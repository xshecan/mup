package app

import (
	"net/netip"
	"time"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/measure"
	"github.com/xshecan/mup/protocol"
)

// dataPolicy is the loss tolerance and the path choice of one group direction.
// The zero value keeps the paths as their health and their mode pick them.
type dataPolicy struct {
	// tolerance is the loss tolerance, or zero for none.
	tolerance config.Tolerance
	// latency picks the path with the lowest round trip time. Only the
	// failover mode has it.
	latency bool
}

// active reports whether the policy changes anything.
func (p dataPolicy) active() bool {
	return p.tolerance != 0 || p.latency
}

// prefer is the name of the path choice for the API, or empty for the order.
func (p dataPolicy) prefer() string {
	if p.latency {
		return config.PreferLatency.String()
	}
	return ""
}

// ingressPolicy is the policy of the ingress paths of a group. A group without
// separate directions has its settings next to its mode.
func ingressPolicy(group config.Group) dataPolicy {
	return dataPolicy{tolerance: group.Tolerance, latency: group.Prefer == config.PreferLatency && group.Mode == config.ModeFailover}
}

// egressSettings are the settings of the egress paths of a group, as the
// EGRESS_REGISTER frames carry them to the servers.
func egressSettings(group config.Group) protocol.EgressSettings {
	return protocol.EgressSettings{
		ToleranceTenths: uint16(group.EgressTolerance),
		PreferLatency:   group.EgressPrefer == config.PreferLatency && group.EgressMode == config.ModeFailover,
	}
}

// egressPolicy is the policy that a server takes from a EGRESS_REGISTER. The
// latency choice counts only in the failover mode.
func egressPolicy(settings protocol.EgressSettings, mode config.Mode) dataPolicy {
	return dataPolicy{
		tolerance: config.Tolerance(settings.ToleranceTenths),
		latency:   settings.PreferLatency && mode == config.ModeFailover,
	}
}

// dataCandidate is one path of a group direction for its data set.
type dataCandidate struct {
	id       int
	priority int
	healthy  bool
	degraded bool
	// rtt is the mean round trip time, or zero when it is unknown.
	rtt time.Duration
}

// dataSet returns the mask of the paths that carry data in one group
// direction. A usable path is healthy and not degraded, and when no path is
// usable, every healthy path is. The set is the usable set, and the mode
// picks inside it. With a chooser it also returns the usable path that the
// chooser picks, which the failover mode tries first. The set is empty only
// when no path is healthy.
func dataSet(candidates []dataCandidate, chooser *measure.LatencyChooser, now time.Time) (mask uint8, chosen int, ok bool) {
	var healthy, usable uint8
	for _, candidate := range candidates {
		if !candidate.healthy {
			continue
		}
		healthy |= 1 << candidate.id
		if !candidate.degraded {
			usable |= 1 << candidate.id
		}
	}
	if usable == 0 {
		usable = healthy
	}
	if chooser == nil {
		return usable, 0, false
	}
	paths := make([]measure.LatencyPath, 0, len(candidates))
	for _, candidate := range candidates {
		paths = append(paths, measure.LatencyPath{
			ID:       candidate.id,
			Priority: candidate.priority,
			Usable:   usable&(1<<candidate.id) != 0,
			RTT:      candidate.rtt,
		})
	}
	chosen, ok = chooser.Choose(paths, now)
	return usable, chosen, ok
}

// maxWeight is the weight of the path with the largest rate in a balancer
// group whose paths all have a rate limit.
const maxWeight = 255

// rateShare is the rate limit of one path of a group direction for its
// balancer weight. members is the number of members of its via, which
// multiplies a limit per member.
type rateShare struct {
	id      int
	limit   dataplane.RateLimit
	members int
}

// rate is the rate of the whole path in bits per second.
func (s rateShare) rate() uint64 {
	if s.limit.PerMember {
		return s.limit.BitsPerSecond * uint64(max(s.members, 1))
	}
	return s.limit.BitsPerSecond
}

// balancerWeights returns the weight of each path of a group direction by its
// ID. When the mode is balancer and every path has a rate limit, the weights
// are the rates scaled so the largest is 255, and each other at least 1.
// Otherwise every weight is zero, and the paths share the peers equally.
func balancerWeights(mode config.Mode, shares []rateShare) [config.MaxPaths]uint8 {
	var weights [config.MaxPaths]uint8
	if mode != config.ModeBalancer || len(shares) == 0 {
		return weights
	}
	var largest uint64
	for _, share := range shares {
		if share.limit.BitsPerSecond == 0 {
			return weights
		}
		largest = max(largest, share.rate())
	}
	for _, share := range shares {
		if share.id < 0 || share.id >= len(weights) {
			continue
		}
		weight := (share.rate()*maxWeight + largest/2) / largest
		weights[share.id] = uint8(max(weight, 1))
	}
	return weights
}

// rateLimitOf is the dataplane form of the rate limit of a path.
func rateLimitOf(path config.Path) dataplane.RateLimit {
	return dataplane.RateLimit{BitsPerSecond: path.BandwidthBitsPerSecond, PerMember: path.BandwidthPerMember}
}

// choiceRTT is the mean round trip time of a probe tracker for a latency
// choice, or zero when the window holds too few samples.
func choiceRTT(probes *measure.Probes, now time.Time) time.Duration {
	if probes == nil || probes.RTTSamples(now) < measure.MinChoiceSamples {
		return 0
	}
	rtt, ok := probes.RTTAvg(now)
	if !ok {
		return 0
	}
	return rtt
}

// publishedMembers returns the healthy members without the degraded ones, or
// every healthy member when all of them are degraded.
func publishedMembers(healthy, degraded []netip.Addr) []netip.Addr {
	if len(degraded) == 0 {
		return healthy
	}
	published := make([]netip.Addr, 0, len(healthy))
	for _, member := range healthy {
		if !containsAddr(degraded, member) {
			published = append(published, member)
		}
	}
	if len(published) == 0 {
		return healthy
	}
	return published
}
