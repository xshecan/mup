package measure

import "time"

const (
	maxMarkers   = 512
	backwardEdge = 1 << 31
	minLossSent  = 50
	// backwardRestart is the number of markers in a row that go back and
	// that mean a restart of a counter. A counter that starts again from
	// zero goes back for good, while a late frame goes back only once.
	backwardRestart = 3
)

type marker struct {
	tx, rx uint32
	at     time.Time
}

// Loss pairs the sender count and the receiver count of the same frame.
// The zero value is ready to use.
type Loss struct {
	markers []marker
	// backward counts the markers in a row that went back.
	backward int
}

// Mark adds one marker with the decoded sender and receiver counts.
func (l *Loss) Mark(tx, rx uint32, at time.Time) {
	if n := len(l.markers); n > 0 {
		newest := l.markers[n-1]
		dtx := CountDelta(tx, newest.tx)
		drx := CountDelta(rx, newest.rx)
		if dtx >= backwardEdge || drx >= backwardEdge {
			l.backward++
			if l.backward < backwardRestart {
				return
			}
			l.markers = l.markers[:0]
		}
		slack := dtx / 4
		if slack < 64 {
			slack = 64
		}
		if uint64(drx) > uint64(dtx)+uint64(slack) {
			l.markers = l.markers[:0]
		}
	}
	l.backward = 0
	l.markers = append(l.markers, marker{tx: tx, rx: rx, at: at})
	l.prune(at)
}

func (l *Loss) prune(newest time.Time) {
	cut := newest.Add(-LongWindow)
	drop := 0
	for drop < len(l.markers)-1 && l.markers[drop].at.Before(cut) {
		drop++
	}
	if over := len(l.markers) - drop - maxMarkers; over > 0 {
		drop += over
	}
	if drop > 0 {
		n := copy(l.markers, l.markers[drop:])
		l.markers = l.markers[:n]
	}
}

// Percent returns the loss over the window ending at now. It returns false
// when there is not enough data.
func (l *Loss) Percent(window time.Duration, now time.Time) (float64, bool) {
	n := len(l.markers)
	if n < 2 {
		return 0, false
	}
	newest := l.markers[n-1]
	cut := now.Add(-window)
	if newest.at.Before(cut) {
		return 0, false
	}
	var oldest *marker
	for i := range l.markers {
		if !l.markers[i].at.Before(cut) {
			oldest = &l.markers[i]
			break
		}
	}
	if oldest == nil || oldest == &l.markers[n-1] {
		return 0, false
	}
	if newest.at.Sub(oldest.at) < window/2 {
		return 0, false
	}
	dtx := CountDelta(newest.tx, oldest.tx)
	drx := CountDelta(newest.rx, oldest.rx)
	if dtx < minLossSent {
		return 0, false
	}
	loss := (1 - float64(drx)/float64(dtx)) * 100
	if loss < 0 {
		loss = 0
	}
	if loss > 100 {
		loss = 100
	}
	return loss, true
}

// Reset forgets all markers.
func (l *Loss) Reset() {
	l.markers = nil
	l.backward = 0
}
