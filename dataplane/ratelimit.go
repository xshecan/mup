package dataplane

import (
	"time"

	"github.com/xshecan/mup/config"
)

// The bandwidth limit of a path is a GCRA bucket in the BPF program. Go gives
// each bucket the cost of one byte and the burst, so the program does no
// division.
const (
	// rateMinBurst and rateMinBurstBytes are the smallest burst of a
	// bucket: 50 ms of its rate, and at least the cost of 3000 bytes.
	rateMinBurst      = 50 * time.Millisecond
	rateMinBurstBytes = 3000

	// limitFlagPath and limitFlagMember mirror MUP_LIMIT_PATH and
	// MUP_LIMIT_MEMBER in bpf/include/mup_abi.h.
	limitFlagPath   uint8 = 1 << 0
	limitFlagMember uint8 = 1 << 1

	// rateMemberBase mirrors MUP_RATE_MEMBER_BASE. client_rate_buckets
	// holds the bucket of client path slot S at S, and the bucket of its
	// member M at rateMemberBase + S*MaxPool + M.
	rateMemberBase = config.MaxPaths

	// downGroupFlagPreferred and downGroupFlagWeighted mirror
	// MUP_DOWN_GROUP_PREFERRED and MUP_DOWN_GROUP_WEIGHTED.
	downGroupFlagPreferred uint8 = 1 << 0
	downGroupFlagWeighted  uint8 = 1 << 1
)

// encodeRate returns the cost of one byte in nanoseconds, in 48.16 fixed
// point, and the burst in nanoseconds, of a limit of bitsPerSecond. Zero is
// no limit and gives zero for both.
func encodeRate(bitsPerSecond uint64) (costQ16, burstNs uint64) {
	if bitsPerSecond == 0 {
		return 0, 0
	}
	const nanosecondBitsQ16 = uint64(8*time.Second) << 16
	costQ16 = (nanosecondBitsQ16 + bitsPerSecond/2) / bitsPerSecond
	if costQ16 == 0 {
		costQ16 = 1
	}
	burstNs = uint64(rateMinBurst)
	if bytesBurst := rateMinBurstBytes * costQ16 >> 16; bytesBurst > burstNs {
		burstNs = bytesBurst
	}
	return costQ16, burstNs
}

// limitFlags returns the MUP_LIMIT_* bits of a limit.
func limitFlags(limit RateLimit) uint8 {
	switch {
	case limit.BitsPerSecond == 0:
		return 0
	case limit.PerMember:
		return limitFlagMember
	default:
		return limitFlagPath
	}
}

// clientBucketIndexes returns the indexes in client_rate_buckets of the
// buckets of a client path slot: the bucket of the whole path, and the first
// bucket of its members.
func clientBucketIndexes(slot int) (path, members uint32) {
	return uint32(slot), uint32(rateMemberBase + slot*MaxPool)
}

// normalizeWeight gives a weight of 0 the share of a weight of 1.
func normalizeWeight(weight uint8) uint8 {
	if weight == 0 {
		return 1
	}
	return weight
}

// encodeGroupShares returns the weights, the MUP_DOWN_GROUP_* flags and the
// preferred path of an egress group. A failover group with a preferred path
// gets the preferred flag. A balancer group whose paths have different
// weights gets the weighted flag. Each flag is only set for the mode that uses
// it, so another group tests no more than before.
func encodeGroupShares(entry EgressGroupEntry) (weights [MaxEgressPaths]uint8, flags, preferred uint8) {
	var first uint8
	equal := true
	seen := false
	for id := range MaxEgressPaths {
		weights[id] = normalizeWeight(entry.Weights[id])
		if entry.PathMask&(1<<id) == 0 {
			continue
		}
		if !seen {
			first, seen = weights[id], true
		} else if weights[id] != first {
			equal = false
		}
	}
	if entry.Mode == config.ModeBalancer && !equal {
		flags |= downGroupFlagWeighted
	}
	if entry.Mode == config.ModeFailover && entry.HasPreferred && entry.Preferred < MaxEgressPaths {
		flags |= downGroupFlagPreferred
		preferred = entry.Preferred
	}
	return weights, flags, preferred
}
