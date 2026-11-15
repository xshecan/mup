package app

import (
	"net/netip"
	"testing"

	"github.com/xshecan/mup/dataplane"
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
	members, healthy := state.update(addrSet("194.225.72.10", "194.225.72.1", "194.225.72.9"), protocol.TransportICMP, nil)
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
	state.update(addrSet("10.0.0.1"), protocol.TransportUDP, nil)
	members, healthy := state.update(map[netip.Addr]bool{}, protocol.TransportUDP, nil)
	if len(members) != 1 || !healthy[0] {
		t.Fatalf("UDP member = %v healthy %v, want one healthy member", members, healthy)
	}
}

func TestPoolProbeStateMissesGoUnhealthyThenLeave(t *testing.T) {
	t.Parallel()
	state := newPoolProbeState()
	state.update(addrSet("10.0.0.1"), protocol.TransportICMP, nil)
	// Miss until unhealthy.
	var healthy []bool
	for sweep := 0; sweep < reflectorMissThreshold; sweep++ {
		_, healthy = state.update(map[netip.Addr]bool{}, protocol.TransportICMP, nil)
	}
	if len(healthy) != 1 || healthy[0] {
		t.Fatalf("member should be unhealthy after %d misses, got %v", reflectorMissThreshold, healthy)
	}
	// Miss until removed.
	var members []netip.Addr
	for sweep := reflectorMissThreshold; sweep < reflectorRemoveThreshold; sweep++ {
		members, _ = state.update(map[netip.Addr]bool{}, protocol.TransportICMP, nil)
	}
	if len(members) != 0 {
		t.Fatalf("member should be removed after %d misses, got %v", reflectorRemoveThreshold, members)
	}
}

func TestPoolProbeStateRecoversAfterMiss(t *testing.T) {
	t.Parallel()
	state := newPoolProbeState()
	state.update(addrSet("10.0.0.1"), protocol.TransportICMP, nil)
	state.update(map[netip.Addr]bool{}, protocol.TransportICMP, nil)
	_, healthy := state.update(addrSet("10.0.0.1"), protocol.TransportICMP, nil)
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
	members, healthy := state.update(responders, protocol.TransportICMP, nil)
	if len(members) != 16 || len(healthy) != 16 {
		t.Fatalf("members = %d, want 16", len(members))
	}
	if members[0].String() != "10.0.0.1" || members[15].String() != "10.0.0.16" {
		t.Fatalf("members kept = %s..%s, want the 16 lowest", members[0], members[15])
	}
}

func poolCandidatesForTest(t *testing.T, base string, prefix uint8) []netip.Addr {
	t.Helper()
	candidates, err := dataplane.PoolCandidates(netip.MustParseAddr(base), prefix, reflectorMaxSweepForTest)
	if err != nil {
		t.Fatalf("PoolCandidates(%s/%d): %v", base, prefix, err)
	}
	return candidates
}

const reflectorMaxSweepForTest = 1024

func TestPoolProbeStateUDPFillsFromTheRange(t *testing.T) {
	t.Parallel()
	state := newPoolProbeState()
	candidates := poolCandidatesForTest(t, "94.184.45.48", 28)
	// A UDP reflector is only a spoofed source, so a range without one host
	// that answers ping still has members, and the client probes decide.
	members, _ := state.update(map[netip.Addr]bool{}, protocol.TransportUDP, candidates)
	if len(members) != 14 {
		t.Fatalf("UDP members without responders = %v, want the 14 hosts", members)
	}
	// The hosts that answer ping come first.
	members, healthy := state.update(addrSet("94.184.45.60", "94.184.45.50"), protocol.TransportUDP, candidates)
	if len(members) != 14 || len(healthy) != 14 {
		t.Fatalf("UDP members = %v, want 14", members)
	}
	want := []string{"94.184.45.50", "94.184.45.60", "94.184.45.49", "94.184.45.51"}
	for index, address := range want {
		if members[index].String() != address {
			t.Fatalf("member %d = %s, want %s (members %v)", index, members[index], address, members)
		}
	}
	seen := make(map[netip.Addr]bool)
	for _, member := range members {
		if seen[member] {
			t.Fatalf("member %s appears twice in %v", member, members)
		}
		seen[member] = true
	}
}

func TestPoolProbeStateICMPDoesNotFill(t *testing.T) {
	t.Parallel()
	state := newPoolProbeState()
	candidates := poolCandidatesForTest(t, "94.184.45.48", 28)
	// An ICMP reflector must answer the Echo Request, so only live hosts count.
	members, _ := state.update(addrSet("94.184.45.55"), protocol.TransportICMP, candidates)
	if len(members) != 1 || members[0].String() != "94.184.45.55" {
		t.Fatalf("ICMP members = %v, want only the responder", members)
	}
}

func TestPoolRespondersKeepsTheRangeOfThePool(t *testing.T) {
	t.Parallel()
	pool := dataplane.PoolInfo{Base: netip.MustParseAddr("94.184.45.48"), Prefix: 28}
	kept := poolResponders(addrSet("94.184.45.50", "194.225.72.81", "94.184.45.64"), pool)
	if len(kept) != 1 || !kept[netip.MustParseAddr("94.184.45.50")] {
		t.Fatalf("kept = %v, want only 94.184.45.50", kept)
	}
}

func TestPoolProbeStateReportsLiveChanges(t *testing.T) {
	t.Parallel()
	state := newPoolProbeState()
	state.update(map[netip.Addr]bool{}, protocol.TransportICMP, nil)
	if live, changed := state.liveChanged(); !changed || live != 0 {
		t.Fatalf("first report = %d %v, want 0 true", live, changed)
	}
	state.update(map[netip.Addr]bool{}, protocol.TransportICMP, nil)
	if _, changed := state.liveChanged(); changed {
		t.Fatal("an unchanged count should not report again")
	}
	state.update(addrSet("10.0.0.1", "10.0.0.2"), protocol.TransportICMP, nil)
	if live, changed := state.liveChanged(); !changed || live != 2 {
		t.Fatalf("report after two answers = %d %v, want 2 true", live, changed)
	}
}
