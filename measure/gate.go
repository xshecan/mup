package measure

import (
	"math"
	"strconv"
	"time"
)

const (
	// LossHoldFirst is the hold of the first strike.
	LossHoldFirst = 30 * time.Second
	// LossHoldMax is the cap of the hold.
	LossHoldMax = 10 * time.Minute
	// LossStrikeWindow is the time after the last recovery in which a new
	// degradation counts as another strike.
	LossStrikeWindow = 10 * time.Minute
)

// LossGate decides whether a path, or a pool member, carries no data because
// of its loss. The zero value is ready to use.
type LossGate struct {
	degraded      bool
	since         time.Time
	hold          time.Duration
	strikes       int
	hasRecovered  bool
	lastRecovered time.Time
	reason        string
}

// Evaluate takes the loss tolerance in percent (zero for none), the data loss of
// the short window and the probe loss (nil when unknown), and returns whether
// the path is degraded now. The data loss is the evidence when it is known,
// else the probe loss is.
func (g *LossGate) Evaluate(limit float64, data, probe *float64, now time.Time) bool {
	if limit <= 0 {
		if g.degraded {
			g.recover(now)
		}
		return false
	}
	var value float64
	kind := ""
	switch {
	case data != nil:
		value = *data
		kind = "loss"
	case probe != nil:
		value = *probe
		kind = "probe loss"
	default:
		return g.degraded
	}
	if !g.degraded {
		if value > limit {
			g.degrade(limit, value, kind, now)
		}
		return g.degraded
	}
	if now.Sub(g.since) >= g.hold && value <= limit/2 {
		g.recover(now)
	}
	return g.degraded
}

func (g *LossGate) degrade(limit, value float64, kind string, now time.Time) {
	if g.hasRecovered && now.Sub(g.lastRecovered) < LossStrikeWindow {
		g.strikes++
	} else {
		g.strikes = 1
	}
	hold := LossHoldMax
	if shift := g.strikes - 1; shift < 16 {
		if h := LossHoldFirst << uint(shift); h < LossHoldMax {
			hold = h
		}
	}
	g.degraded = true
	g.since = now
	g.hold = hold
	g.reason = kind + " " + lossNumber(value) + "% above " + lossNumber(limit) + "%"
}

func (g *LossGate) recover(now time.Time) {
	g.degraded = false
	g.hasRecovered = true
	g.lastRecovered = now
	g.reason = ""
}

// lossNumber formats a percent with one decimal and no trailing zeros.
func lossNumber(v float64) string {
	return strconv.FormatFloat(math.Round(v*10)/10, 'f', -1, 64)
}

// Degraded reports whether the path is degraded.
func (g *LossGate) Degraded() bool { return g.degraded }

// Reason names the loss that degraded the path, or is empty when the path is
// not degraded.
func (g *LossGate) Reason() string { return g.reason }
