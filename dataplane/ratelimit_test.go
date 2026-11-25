package dataplane

import (
	"testing"

	"github.com/xshecan/mup/config"
)

func TestEncodeRateGivesTheCostOfAByteAndTheBurst(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rate    uint64
		costQ16 uint64
		burstNs uint64
	}{
		{name: "no limit", rate: 0, costQ16: 0, burstNs: 0},
		// 8 kbit is 1 ms a byte, so the cost of 3000 bytes is above 50 ms.
		{name: "8 kbit", rate: 8_000, costQ16: 1_000_000 << 16, burstNs: 3_000_000_000},
		{name: "10 mbit", rate: 10_000_000, costQ16: 800 << 16, burstNs: 50_000_000},
		// 0.8 ns a byte is 52428.8 in 48.16 fixed point, rounded up.
		{name: "10 gbit", rate: 10_000_000_000, costQ16: 52_429, burstNs: 50_000_000},
		{name: "100 gbit", rate: 100_000_000_000, costQ16: 5_243, burstNs: 50_000_000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			costQ16, burstNs := encodeRate(tt.rate)
			if costQ16 != tt.costQ16 || burstNs != tt.burstNs {
				t.Fatalf("encodeRate(%d) = (%d, %d), want (%d, %d)", tt.rate, costQ16, burstNs, tt.costQ16, tt.burstNs)
			}
		})
	}
}

func TestLimitFlagsOfALimit(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		limit RateLimit
		want  uint8
	}{
		{RateLimit{}, 0},
		{RateLimit{PerMember: true}, 0},
		{RateLimit{BitsPerSecond: 10_000_000}, limitFlagPath},
		{RateLimit{BitsPerSecond: 10_000_000, PerMember: true}, limitFlagMember},
	} {
		if got := limitFlags(tt.limit); got != tt.want {
			t.Errorf("limitFlags(%+v) = %d, want %d", tt.limit, got, tt.want)
		}
	}
}

func TestClientBucketIndexesFollowTheABI(t *testing.T) {
	t.Parallel()

	path, members := clientBucketIndexes(3)
	if path != 3 || members != 8+3*16 {
		t.Fatalf("clientBucketIndexes(3) = (%d, %d), want (3, %d)", path, members, 8+3*16)
	}
	if _, last := clientBucketIndexes(config.MaxPaths - 1); last+MaxPool != rateMemberBase+config.MaxPaths*MaxPool {
		t.Fatalf("the members of the last slot end at %d, want the end of the map", last+MaxPool)
	}
}

func TestEncodeGroupShares(t *testing.T) {
	t.Parallel()

	// Equal weights, with a zero that counts as one, set no flag.
	weights, flags, _ := encodeGroupShares(EgressGroupEntry{Mode: config.ModeBalancer, PathMask: 0b111, Weights: [MaxEgressPaths]uint8{1, 0, 1}})
	if flags != 0 || weights[1] != 1 || weights[7] != 1 {
		t.Fatalf("equal weights: flags %d, weights %v, want no flag and ones", flags, weights)
	}
	// A weight outside the path mask does not count.
	if _, flags, _ = encodeGroupShares(EgressGroupEntry{Mode: config.ModeBalancer, PathMask: 0b011, Weights: [MaxEgressPaths]uint8{2, 2, 5}}); flags != 0 {
		t.Fatalf("weights outside the mask: flags %d, want none", flags)
	}
	if _, flags, _ = encodeGroupShares(EgressGroupEntry{Mode: config.ModeBalancer, PathMask: 0b011, Weights: [MaxEgressPaths]uint8{1, 3}}); flags != downGroupFlagWeighted {
		t.Fatalf("different weights: flags %d, want the weighted flag", flags)
	}
	// Weights do not apply to a failover group.
	if _, flags, _ = encodeGroupShares(EgressGroupEntry{Mode: config.ModeFailover, PathMask: 0b011, Weights: [MaxEgressPaths]uint8{1, 3}}); flags != 0 {
		t.Fatalf("failover with weights: flags %d, want none", flags)
	}
	_, flags, preferred := encodeGroupShares(EgressGroupEntry{Mode: config.ModeFailover, PathMask: 0b011, HasPreferred: true, Preferred: 1})
	if flags != downGroupFlagPreferred || preferred != 1 {
		t.Fatalf("preferred path: flags %d, preferred %d, want the preferred flag and 1", flags, preferred)
	}
	// A preferred path applies only to the failover mode.
	if _, flags, _ = encodeGroupShares(EgressGroupEntry{Mode: config.ModeRepeater, PathMask: 0b011, HasPreferred: true, Preferred: 1}); flags != 0 {
		t.Fatalf("repeater with a preferred path: flags %d, want none", flags)
	}
}
