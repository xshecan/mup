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
}

func newPoolProbeState() *poolProbeState {
	return &poolProbeState{misses: make(map[netip.Addr]int)}
}

// update folds the responders of one sweep into the member set and returns the
// members, sorted by address and capped at MaxPool, and their health. An ICMP
// member is healthy while it answers. A UDP member stays healthy here, because
// the reflector never sees a UDP reply, so its real health comes from the
// client receipt of a spoofed-source probe.
func (s *poolProbeState) update(responders map[netip.Addr]bool, transport protocol.TransportID) ([]netip.Addr, []bool) {
	for address, miss := range s.misses {
		if responders[address] {
			s.misses[address] = 0
			continue
		}
		if miss+1 >= reflectorRemoveThreshold {
			delete(s.misses, address)
			continue
		}
		s.misses[address] = miss + 1
	}
	for address := range responders {
		if _, known := s.misses[address]; !known {
			s.misses[address] = 0
		}
	}
	members := make([]netip.Addr, 0, len(s.misses))
	for address := range s.misses {
		members = append(members, address)
	}
	slices.SortFunc(members, func(a, b netip.Addr) int { return a.Compare(b) })
	if len(members) > dataplane.MaxPool {
		members = members[:dataplane.MaxPool]
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
