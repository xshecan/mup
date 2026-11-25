package measure

import "time"

const (
	maxRateSamples = 256
	minRateSpan    = time.Second
)

type rateSample struct {
	packets, bytes uint64
	at             time.Time
}

// Rate turns samples of a growing counter into a rate. It keeps the samples
// inside RateWindow and the one sample just before the window, so a span of
// the full window is possible. The zero value is ready to use.
type Rate struct {
	samples []rateSample
}

// Sample records the counter totals at a time. A total that goes down means
// the counter started again, and the older samples are dropped.
func (r *Rate) Sample(packets, bytes uint64, at time.Time) {
	if n := len(r.samples); n > 0 {
		newest := r.samples[n-1]
		if packets < newest.packets || bytes < newest.bytes {
			r.samples = r.samples[:0]
		}
	}
	r.samples = append(r.samples, rateSample{packets: packets, bytes: bytes, at: at})
	cut := at.Add(-RateWindow)
	drop := 0
	for drop+1 < len(r.samples) && !r.samples[drop+1].at.After(cut) {
		drop++
	}
	if over := len(r.samples) - drop - maxRateSamples; over > 0 {
		drop += over
	}
	if drop > 0 {
		n := copy(r.samples, r.samples[drop:])
		r.samples = r.samples[:n]
	}
}

// Rate returns packets per second and bits per second over the window. It
// returns zeros when the samples are too few, too close or too old.
func (r *Rate) Rate(now time.Time) (packetsPerSecond, bitsPerSecond float64) {
	n := len(r.samples)
	if n < 2 {
		return 0, 0
	}
	newest := r.samples[n-1]
	cut := now.Add(-RateWindow)
	if newest.at.Before(cut) {
		return 0, 0
	}
	start := 0
	for i := range r.samples {
		if r.samples[i].at.After(cut) {
			break
		}
		start = i
	}
	oldest := r.samples[start]
	span := newest.at.Sub(oldest.at)
	if span < minRateSpan {
		return 0, 0
	}
	secs := span.Seconds()
	return float64(newest.packets-oldest.packets) / secs,
		float64(newest.bytes-oldest.bytes) * 8 / secs
}
