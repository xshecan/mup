package measure

import "time"

const (
	latencyMargin      = 0.10
	latencyMarginFloor = 2 * time.Millisecond
	latencySwitchAfter = 10 * time.Second
)

// LatencyPath is one path of a latency choice. RTT zero means unknown.
type LatencyPath struct {
	ID       int
	Priority int
	Usable   bool
	RTT      time.Duration
}

// LatencyChooser picks the path with the lowest round trip time for a
// failover group. The zero value is ready to use.
type LatencyChooser struct {
	hasCurrent   bool
	current      int
	hasCandidate bool
	candidate    int
	since        time.Time
}

// better reports whether a ranks before b: known RTT first, then lower RTT,
// then lower priority, then lower ID.
func (a LatencyPath) better(b LatencyPath) bool {
	if (a.RTT > 0) != (b.RTT > 0) {
		return a.RTT > 0
	}
	if a.RTT != b.RTT {
		return a.RTT < b.RTT
	}
	if a.Priority != b.Priority {
		return a.Priority < b.Priority
	}
	return a.ID < b.ID
}

// Choose returns the id of the path to use, or false when no path is usable.
func (c *LatencyChooser) Choose(paths []LatencyPath, now time.Time) (int, bool) {
	var best *LatencyPath
	var cur *LatencyPath
	for i := range paths {
		p := &paths[i]
		if !p.Usable {
			continue
		}
		if best == nil || p.better(*best) {
			best = p
		}
		if c.hasCurrent && p.ID == c.current {
			cur = p
		}
	}
	if best == nil {
		c.hasCurrent, c.hasCandidate = false, false
		return 0, false
	}
	if cur == nil {
		c.hasCurrent, c.current = true, best.ID
		c.hasCandidate = false
		return best.ID, true
	}
	var cand *LatencyPath
	for i := range paths {
		p := &paths[i]
		if !p.Usable || p.ID == cur.ID || p.RTT <= 0 {
			continue
		}
		if cur.RTT > 0 {
			margin := time.Duration(latencyMargin * float64(cur.RTT))
			if margin < latencyMarginFloor {
				margin = latencyMarginFloor
			}
			if cur.RTT-p.RTT <= margin {
				continue
			}
		}
		if cand == nil || p.better(*cand) {
			cand = p
		}
	}
	if cand == nil {
		c.hasCandidate = false
		return cur.ID, true
	}
	if !c.hasCandidate || c.candidate != cand.ID {
		c.hasCandidate, c.candidate, c.since = true, cand.ID, now
	}
	if now.Sub(c.since) >= latencySwitchAfter {
		c.current = cand.ID
		c.hasCandidate = false
		return cand.ID, true
	}
	return cur.ID, true
}
