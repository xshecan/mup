package measure

import "time"

const (
	maxProbes        = 512
	minCompleteProbe = 5
	// MinChoiceSamples is the fewest RTT samples that a latency choice uses.
	MinChoiceSamples = 5
)

type probe struct {
	sequence   uint32
	sent       time.Time
	answered   bool
	answeredAt time.Time
	rtt        time.Duration
}

// Probes tracks probes by sequence number. The zero value is ready to use.
type Probes struct {
	list       []probe
	newestSent time.Time
	everAnswer bool
	hasLast    bool
	lastAt     time.Time
	lastRTT    time.Duration
}

// Sent records a probe. A sequence that is already tracked is ignored.
func (p *Probes) Sent(sequence uint32, at time.Time) {
	for i := range p.list {
		if p.list[i].sequence == sequence {
			return
		}
	}
	p.list = append(p.list, probe{sequence: sequence, sent: at})
	if len(p.list) == 1 || at.After(p.newestSent) {
		p.newestSent = at
	}
	cut := p.newestSent.Add(-ProbeWindow)
	drop := 0
	for drop < len(p.list)-1 && p.list[drop].sent.Before(cut) {
		drop++
	}
	if over := len(p.list) - drop - maxProbes; over > 0 {
		drop += over
	}
	if drop > 0 {
		n := copy(p.list, p.list[drop:])
		p.list = p.list[:n]
	}
}

// Answered records the answer of a probe and returns its round trip time.
// It returns false for an unknown sequence or a second answer.
func (p *Probes) Answered(sequence uint32, at time.Time) (rtt time.Duration, ok bool) {
	for i := range p.list {
		e := &p.list[i]
		if e.sequence != sequence {
			continue
		}
		if e.answered {
			return 0, false
		}
		rtt = at.Sub(e.sent)
		if rtt < 0 {
			rtt = 0
		}
		e.answered = true
		e.answeredAt = at
		e.rtt = rtt
		p.everAnswer = true
		if !p.hasLast || !at.Before(p.lastAt) {
			p.hasLast = true
			p.lastAt = at
			p.lastRTT = rtt
		}
		return rtt, true
	}
	return 0, false
}

// inWindow reports whether a probe was sent within ProbeWindow before now.
func inWindow(e *probe, now time.Time) bool {
	return !e.sent.Before(now.Add(-ProbeWindow))
}

// LossPercent returns the share of complete probes that got no answer.
func (p *Probes) LossPercent(now time.Time) (float64, bool) {
	if !p.everAnswer {
		return 0, false
	}
	complete, lost := 0, 0
	for i := range p.list {
		e := &p.list[i]
		if !inWindow(e, now) {
			continue
		}
		if e.answered {
			complete++
		} else if now.Sub(e.sent) >= ProbeTimeout {
			complete++
			lost++
		}
	}
	if complete < minCompleteProbe {
		return 0, false
	}
	return float64(lost) / float64(complete) * 100, true
}

// RTTAvg returns the mean round trip time of answered probes in the window.
func (p *Probes) RTTAvg(now time.Time) (time.Duration, bool) {
	var sum time.Duration
	n := 0
	for i := range p.list {
		e := &p.list[i]
		if e.answered && inWindow(e, now) {
			sum += e.rtt
			n++
		}
	}
	if n == 0 {
		return 0, false
	}
	return sum / time.Duration(n), true
}

// RTTSamples returns the number of answered probes in the window, which the
// mean of RTTAvg is over.
func (p *Probes) RTTSamples(now time.Time) int {
	n := 0
	for i := range p.list {
		if p.list[i].answered && inWindow(&p.list[i], now) {
			n++
		}
	}
	return n
}

// RTTLast returns the round trip time of the most recently answered probe.
func (p *Probes) RTTLast() (time.Duration, bool) {
	return p.lastRTT, p.hasLast
}

// RTTJitter returns the mean absolute difference of the round trip times of
// adjacent answered probes in sent order. A probe without an answer breaks
// the row.
func (p *Probes) RTTJitter(now time.Time) (time.Duration, bool) {
	var sum time.Duration
	n := 0
	var prev *probe
	for i := range p.list {
		e := &p.list[i]
		if !inWindow(e, now) {
			continue
		}
		if !e.answered {
			prev = nil
			continue
		}
		if prev != nil {
			d := e.rtt - prev.rtt
			if d < 0 {
				d = -d
			}
			sum += d
			n++
		}
		prev = e
	}
	if n == 0 {
		return 0, false
	}
	return sum / time.Duration(n), true
}
