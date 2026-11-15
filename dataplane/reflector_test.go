package dataplane

import (
	"net/netip"

	"github.com/xshecan/mup/protocol"
	"testing"
)

func TestPoolAddresses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		base      string
		prefix    uint8
		wantCount int
		wantFirst string
		wantLast  string
	}{
		{"194.225.72.0", 24, 16, "194.225.72.1", "194.225.72.16"},
		{"10.0.0.0", 30, 3, "10.0.0.1", "10.0.0.3"},
		{"10.0.0.0", 29, 7, "10.0.0.1", "10.0.0.7"},
	}
	for _, tt := range tests {
		addresses, err := poolAddresses(netip.MustParseAddr(tt.base), tt.prefix)
		if err != nil {
			t.Fatalf("poolAddresses(%s/%d): %v", tt.base, tt.prefix, err)
		}
		if len(addresses) != tt.wantCount {
			t.Fatalf("%s/%d count = %d, want %d", tt.base, tt.prefix, len(addresses), tt.wantCount)
		}
		if addresses[0] != netip.MustParseAddr(tt.wantFirst) {
			t.Fatalf("%s/%d first = %s, want %s", tt.base, tt.prefix, addresses[0], tt.wantFirst)
		}
		if addresses[len(addresses)-1] != netip.MustParseAddr(tt.wantLast) {
			t.Fatalf("%s/%d last = %s, want %s", tt.base, tt.prefix, addresses[len(addresses)-1], tt.wantLast)
		}
	}
}

func TestPoolCandidatesSweepsTheWholeRange(t *testing.T) {
	t.Parallel()
	addresses, err := PoolCandidates(netip.MustParseAddr("194.225.72.0"), 24, reflectorSweepCapForTest)
	if err != nil {
		t.Fatalf("PoolCandidates /24: %v", err)
	}
	if len(addresses) != 255 {
		t.Fatalf("/24 candidates = %d, want 255", len(addresses))
	}
	if addresses[0].String() != "194.225.72.1" || addresses[254].String() != "194.225.72.255" {
		t.Fatalf("/24 range = %s..%s", addresses[0], addresses[254])
	}
}

func TestPoolCandidatesRespectsTheCap(t *testing.T) {
	t.Parallel()
	addresses, err := PoolCandidates(netip.MustParseAddr("10.0.0.0"), 8, 1024)
	if err != nil {
		t.Fatalf("PoolCandidates /8: %v", err)
	}
	if len(addresses) != 1024 {
		t.Fatalf("/8 candidates = %d, want the cap 1024", len(addresses))
	}
}

const reflectorSweepCapForTest = 1024

func TestPoolAddressesRejectsBadPrefix(t *testing.T) {
	t.Parallel()
	for _, prefix := range []uint8{0, 32, 33} {
		if _, err := poolAddresses(netip.MustParseAddr("10.0.0.0"), prefix); err == nil {
			t.Fatalf("prefix %d should be rejected", prefix)
		}
	}
}

func TestEncodeReflectorPoolHealthyMask(t *testing.T) {
	t.Parallel()
	addresses := []netip.Addr{
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("10.0.0.3"),
	}
	all, err := encodeReflectorPool(addresses, nil)
	if err != nil {
		t.Fatal(err)
	}
	if all.Count != 3 || all.HealthyMask != 0b111 {
		t.Fatalf("all healthy = count %d mask %b, want 3 111", all.Count, all.HealthyMask)
	}
	partial, err := encodeReflectorPool(addresses, []bool{true, false, true})
	if err != nil {
		t.Fatal(err)
	}
	if partial.HealthyMask != 0b101 {
		t.Fatalf("partial mask = %b, want 101", partial.HealthyMask)
	}
	// The address words are stored in network byte order.
	first, _ := requiredIPv4Word(addresses[0], "test")
	if partial.Addresses[0] != first {
		t.Fatalf("address[0] = %d, want %d", partial.Addresses[0], first)
	}
}

func TestEncodeReflectorPoolRejectsOversize(t *testing.T) {
	t.Parallel()
	addresses := make([]netip.Addr, MaxPool+1)
	for index := range addresses {
		addresses[index] = netip.MustParseAddr("10.0.0.1")
	}
	if _, err := encodeReflectorPool(addresses, nil); err == nil {
		t.Fatal("oversize pool should be rejected")
	}
}

func TestReflectorKeySeparatesTransports(t *testing.T) {
	t.Parallel()
	base := netip.MustParseAddr("94.184.45.48")
	udp, err := reflectorKey(PoolKey{Base: base, Transport: protocol.TransportUDP})
	if err != nil {
		t.Fatalf("reflectorKey UDP: %v", err)
	}
	icmp, err := reflectorKey(PoolKey{Base: base, Transport: protocol.TransportICMP})
	if err != nil {
		t.Fatalf("reflectorKey ICMP: %v", err)
	}
	if udp == icmp {
		t.Fatalf("UDP and ICMP pools of %s share the key %+v", base, udp)
	}
	if udp.Base != icmp.Base {
		t.Fatalf("bases differ: %d and %d", udp.Base, icmp.Base)
	}
}
