package measure

import "time"

const maxRTTs = 512

type rttSample struct {
	rtt time.Duration
	at  time.Time
}

// RTTs is a window of round trip samples that come without a sequence.
// The zero value is ready to use.
type RTTs struct {
	samples []rttSample
	last    time.Duration
	hasLast bool
}

// Add records one sample.
func (r *RTTs) Add(rtt time.Duration, at time.Time) {
	r.samples = append(r.samples, rttSample{rtt: rtt, at: at})
	r.last = rtt
	r.hasLast = true
	cut := at.Add(-ProbeWindow)
	drop := 0
	for drop < len(r.samples)-1 && r.samples[drop].at.Before(cut) {
		drop++
	}
	if over := len(r.samples) - drop - maxRTTs; over > 0 {
		drop += over
	}
	if drop > 0 {
		n := copy(r.samples, r.samples[drop:])
		r.samples = r.samples[:n]
	}
}

// Avg returns the mean of the samples in the last ProbeWindow.
func (r *RTTs) Avg(now time.Time) (time.Duration, bool) {
	cut := now.Add(-ProbeWindow)
	var sum time.Duration
	n := 0
	for _, s := range r.samples {
		if !s.at.Before(cut) {
			sum += s.rtt
			n++
		}
	}
	if n == 0 {
		return 0, false
	}
	return sum / time.Duration(n), true
}

// Jitter returns the mean absolute difference of adjacent samples in the
// last ProbeWindow. It needs two samples.
func (r *RTTs) Jitter(now time.Time) (time.Duration, bool) {
	cut := now.Add(-ProbeWindow)
	var sum time.Duration
	n := 0
	have := false
	var prev time.Duration
	for _, s := range r.samples {
		if s.at.Before(cut) {
			continue
		}
		if have {
			d := s.rtt - prev
			if d < 0 {
				d = -d
			}
			sum += d
			n++
		}
		prev = s.rtt
		have = true
	}
	if n == 0 {
		return 0, false
	}
	return sum / time.Duration(n), true
}

// Last returns the newest sample.
func (r *RTTs) Last() (time.Duration, bool) {
	return r.last, r.hasLast
}
