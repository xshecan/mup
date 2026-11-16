package config

import (
	"net/netip"
	"testing"
)

func TestParsePathPool(t *testing.T) {
	t.Parallel()
	tests := []struct {
		raw     string
		base    string
		prefix  uint8
		balance Balance
	}{
		{"203.0.113.5:5300/icmp via 194.225.72.0/24 balance per-peer", "194.225.72.0", 24, BalancePerPeer},
		{"203.0.113.5:5300/udp via 198.51.100.0/24 balance per-packet", "198.51.100.0", 24, BalancePerPacket},
	}
	for _, tt := range tests {
		path, err := ParsePath(tt.raw)
		if err != nil {
			t.Fatalf("ParsePath(%q): %v", tt.raw, err)
		}
		if !path.IsPool() {
			t.Fatalf("ParsePath(%q): not a pool", tt.raw)
		}
		if path.ReturnIP != netip.MustParseAddr(tt.base) || path.ReturnPrefix != tt.prefix || path.Balance != tt.balance {
			t.Fatalf("ParsePath(%q) = %s/%d %s, want %s/%d %s", tt.raw, path.ReturnIP, path.ReturnPrefix, path.Balance, tt.base, tt.prefix, tt.balance)
		}
		if path.String() != tt.raw {
			t.Fatalf("round-trip %q -> %q", tt.raw, path.String())
		}
	}
	// A pool with no explicit balance keeps the per-peer default and shows it.
	path, err := ParsePath("203.0.113.5:5300/icmp via 10.0.0.0/30")
	if err != nil {
		t.Fatal(err)
	}
	if path.Balance != BalancePerPeer || path.String() != "203.0.113.5:5300/icmp via 10.0.0.0/30 balance per-peer" {
		t.Fatalf("default balance string = %q", path.String())
	}
}

func TestParsePathPoolNormalizesBase(t *testing.T) {
	t.Parallel()
	path, err := ParsePath("203.0.113.5:5300/icmp via 194.225.72.33/24 balance per-peer")
	if err != nil {
		t.Fatal(err)
	}
	if path.ReturnIP != netip.MustParseAddr("194.225.72.0") {
		t.Fatalf("base = %s, want 194.225.72.0", path.ReturnIP)
	}
}

func TestParsePathErrors(t *testing.T) {
	t.Parallel()
	bad := []string{
		"203.0.113.5:5300/udp via 194.225.72.0/24 balance bogus",
		"203.0.113.5:5300/udp via 194.225.72.10 balance per-peer",
		"203.0.113.5:5300/udp via 194.225.72.0/33",
		"203.0.113.5:5300/udp via 194.225.72.0/32",
		"203.0.113.5:5300/udp via 0.0.0.0/24",
		"203.0.113.5:5300/udp via 194.225.72.0/24 drop per-peer",
		"203.0.113.5:5300/udp via 194.225.72.0/24 balance",
	}
	for _, raw := range bad {
		if _, err := ParsePath(raw); err == nil {
			t.Fatalf("ParsePath(%q) should have failed", raw)
		}
	}
}

func TestSameRouteIgnoresThePool(t *testing.T) {
	t.Parallel()
	path, err := ParsePath("203.0.113.5:5300/icmp via 194.225.72.0/24 balance per-packet")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := ParsePath("203.0.113.5:5300/icmp")
	if err != nil {
		t.Fatal(err)
	}
	if !path.SameRoute(plain) {
		t.Fatalf("%s and %s are not the same route", path, plain)
	}
}
