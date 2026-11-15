package app

import (
	"net/netip"
	"slices"

	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/protocol"
)

const (
	// reflectorMissThreshold marks a member unhealthy after this many sweeps in
	// a row without a reply.
	reflectorMissThreshold = 3
	// reflectorRemoveThreshold drops a member from the pool after this many
	// sweeps in a row without a reply, so a host that leaves the range stops
	// taking a slot.
	reflectorRemoveThreshold = 15
)

// poolProbeState tracks the live members of one pool across sweeps. The map
// holds every member that answered recently, keyed by address, with its count
// of sweeps in a row without a reply.
type poolProbeState struct {
	misses map[netip.Addr]int
	// live is the number of known members that answered the latest sweep, and
	// reported is the value of live at the latest log line.
	live     int
	reported int
}

func newPoolProbeState() *poolProbeState {
	return &poolProbeState{misses: make(map[netip.Addr]int), reported: -1}
}

// update folds the responders of one sweep into the member set and returns the
// members and their health.
//
// An ICMP member must answer ping, because it sends the Echo Reply to the
// client. The members are the hosts that answered recently, sorted by address
// and capped at MaxPool, and a member is healthy while it answers.
//
// A UDP member only appears as a spoofed source and never sees a packet, so it
// does not have to answer ping. The members are the hosts that answered first,
// then the other candidates of the range in order, up to MaxPool. The health
// value here is always true, because the real health of a UDP member comes from
// the client receipt of a spoofed-source probe.
func (s *poolProbeState) update(responders map[netip.Addr]bool, transport protocol.TransportID, candidates []netip.Addr) ([]netip.Addr, []bool) {
	s.live = 0
	for address, miss := range s.misses {
		if responders[address] {
			s.misses[address] = 0
			s.live++
			continue
		}
		if miss+1 >= reflectorRemoveThreshold {
			delete(s.misses, address)
			continue
		}
		s.misses[address] = miss + 1
	}
	for address := range responders {
		if _, known := s.misses[address]; known {
			continue
		}
		s.misses[address] = 0
		s.live++
	}
	members := make([]netip.Addr, 0, len(s.misses))
	for address := range s.misses {
		members = append(members, address)
	}
	slices.SortFunc(members, func(a, b netip.Addr) int { return a.Compare(b) })
	if len(members) > dataplane.MaxPool {
		members = members[:dataplane.MaxPool]
	}
	if transport == protocol.TransportUDP {
		for _, candidate := range candidates {
			if len(members) >= dataplane.MaxPool {
				break
			}
			if _, known := s.misses[candidate]; !known {
				members = append(members, candidate)
			}
		}
	}
	healthy := make([]bool, len(members))
	for index, address := range members {
		if transport == protocol.TransportICMP {
			healthy[index] = s.misses[address] < reflectorMissThreshold
		} else {
			healthy[index] = true
		}
	}
	return members, healthy
}

// poolResponders keeps the responders of one sweep that are in the range of
// the pool, because one sweep pings the candidates of every pool.
func poolResponders(responders map[netip.Addr]bool, pool dataplane.PoolInfo) map[netip.Addr]bool {
	prefix := netip.PrefixFrom(pool.Base, int(pool.Prefix))
	kept := make(map[netip.Addr]bool, len(responders))
	for address := range responders {
		if prefix.Contains(address) {
			kept[address] = true
		}
	}
	return kept
}

// liveChanged returns the number of members that answered the latest sweep,
// and whether it differs from the value at the previous call that reported a
// change.
func (s *poolProbeState) liveChanged() (int, bool) {
	if s.live == s.reported {
		return s.live, false
	}
	s.reported = s.live
	return s.live, true
}
