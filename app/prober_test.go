package app

import (
	"net/netip"
	"testing"

	"github.com/xshecan/mup/protocol"
)

func addrSet(addresses ...string) map[netip.Addr]bool {
	set := make(map[netip.Addr]bool, len(addresses))
	for _, address := range addresses {
		set[netip.MustParseAddr(address)] = true
	}
	return set
}

func TestPoolProbeStateDiscoversAndSorts(t *testing.T) {
	t.Parallel()
	state := newPoolProbeState()
	members, healthy := state.update(addrSet("194.225.72.10", "194.225.72.1", "194.225.72.9"), protocol.TransportICMP)
	if len(members) != 3 {
		t.Fatalf("members = %v, want 3", members)
	}
	want := []string{"194.225.72.1", "194.225.72.9", "194.225.72.10"}
	for index, address := range members {
		if address.String() != want[index] {
			t.Fatalf("member %d = %s, want %s", index, address, want[index])
		}
		if !healthy[index] {
			t.Fatalf("member %s should be healthy on first reply", address)
		}
	}
}

func TestPoolProbeStateUDPStaysHealthy(t *testing.T) {
	t.Parallel()
	state := newPoolProbeState()
	// A member that never answers ICMP still counts as a healthy UDP member,
	// because UDP health comes from the client receipt, not from this ping.
	state.update(addrSet("10.0.0.1"), protocol.TransportUDP)
	members, healthy := state.update(map[netip.Addr]bool{}, protocol.TransportUDP)
	if len(members) != 1 || !healthy[0] {
		t.Fatalf("UDP member = %v healthy %v, want one healthy member", members, healthy)
	}
}

func TestPoolProbeStateMissesGoUnhealthyThenLeave(t *testing.T) {
	t.Parallel()
	state := newPoolProbeState()
	state.update(addrSet("10.0.0.1"), protocol.TransportICMP)
	// Miss until unhealthy.
	var healthy []bool
	for sweep := 0; sweep < reflectorMissThreshold; sweep++ {
		_, healthy = state.update(map[netip.Addr]bool{}, protocol.TransportICMP)
	}
	if len(healthy) != 1 || healthy[0] {
		t.Fatalf("member should be unhealthy after %d misses, got %v", reflectorMissThreshold, healthy)
	}
	// Miss until removed.
	var members []netip.Addr
	for sweep := reflectorMissThreshold; sweep < reflectorRemoveThreshold; sweep++ {
		members, _ = state.update(map[netip.Addr]bool{}, protocol.TransportICMP)
	}
	if len(members) != 0 {
		t.Fatalf("member should be removed after %d misses, got %v", reflectorRemoveThreshold, members)
	}
}

func TestPoolProbeStateRecoversAfterMiss(t *testing.T) {
	t.Parallel()
	state := newPoolProbeState()
	state.update(addrSet("10.0.0.1"), protocol.TransportICMP)
	state.update(map[netip.Addr]bool{}, protocol.TransportICMP)
	_, healthy := state.update(addrSet("10.0.0.1"), protocol.TransportICMP)
	if !healthy[0] {
		t.Fatalf("member should be healthy again after it answers, got %v", healthy)
	}
}

func TestPoolProbeStateCapsAtMaxPool(t *testing.T) {
	t.Parallel()
	state := newPoolProbeState()
	responders := make(map[netip.Addr]bool)
	for last := 1; last <= 20; last++ {
		responders[netip.AddrFrom4([4]byte{10, 0, 0, byte(last)})] = true
	}
	members, healthy := state.update(responders, protocol.TransportICMP)
	if len(members) != 16 || len(healthy) != 16 {
		t.Fatalf("members = %d, want 16", len(members))
	}
	if members[0].String() != "10.0.0.1" || members[15].String() != "10.0.0.16" {
		t.Fatalf("members kept = %s..%s, want the 16 lowest", members[0], members[15])
	}
}
