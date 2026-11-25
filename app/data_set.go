package app

import (
	"net/netip"
	"time"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/measure"
	"github.com/xshecan/mup/protocol"
)

// dataPolicy is the loss limit and the path choice of one group direction.
// The zero value keeps the paths as their health and their mode pick them.
type dataPolicy struct {
	// maxLoss is the loss limit, or zero for none.
	maxLoss config.LossLimit
	// latency picks the path with the lowest round trip time. Only the
	// failover mode has it.
	latency bool
}

// active reports whether the policy changes anything.
func (p dataPolicy) active() bool {
	return p.maxLoss != 0 || p.latency
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
	return dataPolicy{maxLoss: group.MaxLoss, latency: group.Prefer == config.PreferLatency && group.Mode == config.ModeFailover}
}

// egressSettings are the settings of the egress paths of a group, as the
// EGRESS_REGISTER frames carry them to the servers.
func egressSettings(group config.Group) protocol.EgressSettings {
	return protocol.EgressSettings{
		MaxLossTenths: uint16(group.EgressMaxLoss),
		PreferLatency: group.EgressPrefer == config.PreferLatency && group.EgressMode == config.ModeFailover,
	}
}

// egressPolicy is the policy that a server takes from a EGRESS_REGISTER. The
// latency choice counts only in the failover mode.
func egressPolicy(settings protocol.EgressSettings, mode config.Mode) dataPolicy {
	return dataPolicy{
		maxLoss: config.LossLimit(settings.MaxLossTenths),
		latency: settings.PreferLatency && mode == config.ModeFailover,
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
// usable, every healthy path is. With a chooser the set is the one usable
// path that the chooser picks. Without one it is the usable set, and the mode
// picks inside it. The set is empty only when no path is healthy.
func dataSet(candidates []dataCandidate, chooser *measure.LatencyChooser, now time.Time) uint8 {
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
		return usable
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
	id, ok := chooser.Choose(paths, now)
	if !ok {
		return 0
	}
	return 1 << id
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
