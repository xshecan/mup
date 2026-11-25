package measure

import (
	"testing"
	"time"
)

func fp(v float64) *float64 { return &v }

type gateStep struct {
	sec   float64
	data  *float64
	probe *float64
	want  bool
}

func runGate(t *testing.T, limit float64, steps []gateStep) *LossGate {
	t.Helper()
	var g LossGate
	for i, s := range steps {
		if got := g.Evaluate(limit, s.data, s.probe, at(s.sec)); got != s.want {
			t.Fatalf("step %d (t=%v): got %v, want %v", i, s.sec, got, s.want)
		}
		if g.Degraded() != s.want {
			t.Fatalf("step %d: Degraded() disagrees", i)
		}
	}
	return &g
}

func TestLossGateSteps(t *testing.T) {
	tests := []struct {
		name  string
		limit float64
		steps []gateStep
	}{
		{"not above limit stays healthy", 5, []gateStep{
			{0, fp(5), nil, false}, {1, fp(4.9), nil, false},
		}},
		{"above limit degrades", 5, []gateStep{
			{0, fp(5.1), nil, true},
		}},
		{"hold even at zero loss", 5, []gateStep{
			{0, fp(50), nil, true}, {1, fp(0), nil, true}, {29.9, fp(0), nil, true}, {30, fp(0), nil, false},
		}},
		{"recovery at half the tolerance", 5, []gateStep{
			{0, fp(50), nil, true}, {30, fp(2.5), nil, false},
		}},
		{"no recovery above half", 5, []gateStep{
			{0, fp(50), nil, true}, {30, fp(2.6), nil, true}, {100, fp(3), nil, true}, {101, fp(2), nil, false},
		}},
		{"no evidence keeps degraded", 5, []gateStep{
			{0, fp(50), nil, true}, {600, nil, nil, true},
		}},
		{"no evidence keeps healthy", 5, []gateStep{
			{0, nil, nil, false}, {10, fp(1), nil, false}, {20, nil, nil, false},
		}},
		{"probe used when data is nil", 5, []gateStep{
			{0, nil, fp(10), true}, {30, nil, fp(1), false},
		}},
		{"data preferred over probe, data low", 5, []gateStep{
			{0, fp(1), fp(90), false},
		}},
		{"data preferred over probe, data high", 5, []gateStep{
			{0, fp(10), fp(0), true}, {30, fp(10), fp(0), true}, {31, fp(1), fp(90), false},
		}},
		{"limit zero never degrades", 0, []gateStep{
			{0, fp(100), nil, false}, {1, nil, fp(100), false},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { runGate(t, tt.limit, tt.steps) })
	}
}

func TestLossGateLimitZeroRecovers(t *testing.T) {
	var g LossGate
	g.Evaluate(5, fp(50), nil, at(0))
	if !g.Degraded() {
		t.Fatal("not degraded")
	}
	if g.Evaluate(0, fp(50), nil, at(1)) || g.Reason() != "" {
		t.Fatal("limit zero must recover at once")
	}
	// The recovery counts for the strike logic: next hold is 60 s.
	g.Evaluate(5, fp(50), nil, at(2))
	if !g.Evaluate(5, fp(0), nil, at(2+59)) || g.Evaluate(5, fp(0), nil, at(2+60)) {
		t.Fatal("expected a 60 s hold after a recovery by limit zero")
	}
}

func TestLossGateStrikes(t *testing.T) {
	holds := []time.Duration{30 * time.Second, 60 * time.Second, 120 * time.Second,
		240 * time.Second, 480 * time.Second, LossHoldMax, LossHoldMax, LossHoldMax}
	var g LossGate
	now := at(0)
	for i, hold := range holds {
		if !g.Evaluate(5, fp(50), nil, now) {
			t.Fatalf("strike %d: not degraded", i+1)
		}
		if !g.Evaluate(5, fp(0), nil, now.Add(hold-time.Millisecond)) {
			t.Fatalf("strike %d: recovered before %v", i+1, hold)
		}
		if g.Evaluate(5, fp(0), nil, now.Add(hold)) {
			t.Fatalf("strike %d: not recovered at %v", i+1, hold)
		}
		now = now.Add(hold).Add(time.Second)
	}
}

func TestLossGateManyStrikesNoOverflow(t *testing.T) {
	var g LossGate
	now := at(0)
	for i := 0; i < 100; i++ {
		g.Evaluate(5, fp(50), nil, now)
		now = now.Add(LossHoldMax)
		if g.Evaluate(5, fp(0), nil, now) {
			t.Fatalf("round %d: still degraded", i)
		}
		now = now.Add(time.Second)
	}
}

func TestLossGateStrikeReset(t *testing.T) {
	var g LossGate
	g.Evaluate(5, fp(50), nil, at(0))
	g.Evaluate(5, fp(0), nil, at(30)) // recovered at 30
	g.Evaluate(5, fp(50), nil, at(31))
	// Second strike: 60 s hold.
	if !g.Evaluate(5, fp(0), nil, at(31+59)) {
		t.Fatal("second strike must hold 60 s")
	}
	g.Evaluate(5, fp(0), nil, at(31+60)) // recovered
	rec := 31.0 + 60
	// Degrade again after the strike window: first strike again.
	g.Evaluate(5, fp(50), nil, at(rec+LossStrikeWindow.Seconds()))
	if g.Evaluate(5, fp(0), nil, at(rec+LossStrikeWindow.Seconds()+30)) {
		t.Fatal("strikes must reset to a 30 s hold")
	}
}

func TestLossGateReason(t *testing.T) {
	tests := []struct {
		name        string
		limit       float64
		data, probe *float64
		want        string
	}{
		{"data", 5, fp(12.5), nil, "loss 12.5% above 5%"},
		{"probe", 5, nil, fp(12.5), "probe loss 12.5% above 5%"},
		{"whole numbers", 7.5, fp(100), nil, "loss 100% above 7.5%"},
		{"rounded", 0.5, fp(7.04), nil, "loss 7% above 0.5%"},
		{"data over probe", 5, fp(20), fp(30), "loss 20% above 5%"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var g LossGate
			if g.Reason() != "" {
				t.Fatal("reason before degrade")
			}
			g.Evaluate(tt.limit, tt.data, tt.probe, at(0))
			if g.Reason() != tt.want {
				t.Fatalf("got %q, want %q", g.Reason(), tt.want)
			}
		})
	}
	var g LossGate
	g.Evaluate(5, fp(12.5), nil, at(0))
	g.Evaluate(5, fp(40), nil, at(10))
	if g.Reason() != "loss 12.5% above 5%" {
		t.Fatalf("reason changed: %q", g.Reason())
	}
	g.Evaluate(5, fp(0), nil, at(30))
	if g.Reason() != "" {
		t.Fatalf("reason after recovery: %q", g.Reason())
	}
}
