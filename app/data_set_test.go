package app

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/measure"
	"github.com/xshecan/mup/protocol"
)

func TestDataSetUsesTheUsablePaths(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		candidates []dataCandidate
		want       uint8
	}{
		"all healthy":  {[]dataCandidate{{id: 0, healthy: true}, {id: 1, healthy: true}}, 0b11},
		"one degraded": {[]dataCandidate{{id: 0, healthy: true, degraded: true}, {id: 1, healthy: true}}, 0b10},
		"all degraded keeps the healthy ones": {
			[]dataCandidate{{id: 0, healthy: true, degraded: true}, {id: 1, healthy: true, degraded: true}, {id: 2}}, 0b011,
		},
		"an unhealthy path stays out": {[]dataCandidate{{id: 0}, {id: 3, healthy: true}}, 0b1000},
		"no healthy path":             {[]dataCandidate{{id: 0, degraded: true}, {id: 1}}, 0},
	} {
		t.Run(name, func(t *testing.T) {
			if got := dataSet(tt.candidates, nil, time.Unix(1000, 0)); got != tt.want {
				t.Fatalf("dataSet = %#b, want %#b", got, tt.want)
			}
		})
	}
}

func TestDataSetTakesThePathOfTheChooser(t *testing.T) {
	t.Parallel()

	now := time.Unix(1000, 0)
	chooser := &measure.LatencyChooser{}
	candidates := []dataCandidate{
		{id: 0, priority: 0, healthy: true, rtt: 50 * time.Millisecond},
		{id: 1, priority: 1, healthy: true, rtt: 20 * time.Millisecond},
		{id: 2, priority: 2, healthy: true, degraded: true, rtt: 5 * time.Millisecond},
	}
	if got := dataSet(candidates, chooser, now); got != 0b010 {
		t.Fatalf("dataSet = %#b, want the fastest usable path 1", got)
	}
	// A degraded path is usable again when every path is degraded.
	for index := range candidates {
		candidates[index].degraded = true
	}
	candidates[1].healthy = false
	if got := dataSet(candidates, chooser, now.Add(2*time.Second)); got != 0b100 {
		t.Fatalf("dataSet = %#b, want path 2 when all paths are degraded", got)
	}
	for index := range candidates {
		candidates[index].healthy = false
	}
	if got := dataSet(candidates, chooser, now.Add(4*time.Second)); got != 0 {
		t.Fatalf("dataSet = %#b, want none without a healthy path", got)
	}
}

func TestTheClientMaskIsTheUnionOfTheGroups(t *testing.T) {
	t.Parallel()

	now := time.Unix(1000, 0)
	first := dataSet([]dataCandidate{{id: 0, healthy: true, degraded: true}, {id: 1, healthy: true}}, nil, now)
	second := dataSet([]dataCandidate{
		{id: 2, priority: 2, healthy: true, rtt: 30 * time.Millisecond},
		{id: 3, priority: 3, healthy: true, rtt: 10 * time.Millisecond},
	}, &measure.LatencyChooser{}, now)
	if got := first | second; got != 0b1010 {
		t.Fatalf("union = %#b, want paths 1 and 3", got)
	}
}

func TestChoiceRTTNeedsFiveSamples(t *testing.T) {
	t.Parallel()

	start := time.Unix(1000, 0)
	var probes measure.Probes
	for sequence := uint32(1); sequence <= 5; sequence++ {
		sent := start.Add(time.Duration(sequence) * time.Second)
		probes.Sent(sequence, sent)
		probes.Answered(sequence, sent.Add(20*time.Millisecond))
		now := sent.Add(time.Second)
		want := time.Duration(0)
		if sequence == 5 {
			want = 20 * time.Millisecond
		}
		if got := choiceRTT(&probes, now); got != want {
			t.Fatalf("choiceRTT after %d samples = %v, want %v", sequence, got, want)
		}
	}
	if got := choiceRTT(nil, start); got != 0 {
		t.Fatalf("choiceRTT without a tracker = %v", got)
	}
}

func TestPublishedMembersKeepTheLastMembers(t *testing.T) {
	t.Parallel()

	a, b, c := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2"), netip.MustParseAddr("203.0.113.3")
	for name, tt := range map[string]struct {
		healthy, degraded, want []netip.Addr
	}{
		"none degraded":       {[]netip.Addr{a, b}, nil, []netip.Addr{a, b}},
		"one degraded":        {[]netip.Addr{a, b, c}, []netip.Addr{b}, []netip.Addr{a, c}},
		"all degraded":        {[]netip.Addr{a, b}, []netip.Addr{a, b}, []netip.Addr{a, b}},
		"an unhealthy member": {[]netip.Addr{a}, []netip.Addr{c}, []netip.Addr{a}},
		"no healthy member":   {nil, []netip.Addr{a}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			if got := publishedMembers(tt.healthy, tt.degraded); !slices.Equal(got, tt.want) {
				t.Fatalf("publishedMembers = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPoliciesFollowTheConfiguration(t *testing.T) {
	t.Parallel()

	group := config.Group{
		Mode: config.ModeFailover, MaxLoss: 50, Prefer: config.PreferLatency,
		EgressMode: config.ModeBalancer, EgressMaxLoss: 5, EgressPrefer: config.PreferLatency,
	}
	if got := ingressPolicy(group); got != (dataPolicy{maxLoss: 50, latency: true}) || !got.active() || got.prefer() != "latency" {
		t.Fatalf("ingressPolicy = %#v", got)
	}
	// The latency choice counts only in the failover mode.
	if got := egressSettings(group); got != (protocol.EgressSettings{MaxLossTenths: 5}) {
		t.Fatalf("egressSettings = %#v", got)
	}
	if got := egressPolicy(protocol.EgressSettings{PreferLatency: true}, config.ModeRepeater); got.latency || got.active() {
		t.Fatalf("egressPolicy in the repeater mode = %#v, want none", got)
	}
	if got := ingressPolicy(config.Group{}); got.active() || got.prefer() != "" {
		t.Fatalf("ingressPolicy without settings = %#v", got)
	}
}
