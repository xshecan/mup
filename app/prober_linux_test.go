//go:build linux

package app

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestSweepEchoFindsALiveHost pings the loopback address through the same raw
// socket and read path as the prober. ReadFromIP already strips the IPv4
// header, so a second strip lost every reply, and every pool stayed empty.
func TestSweepEchoFindsALiveHost(t *testing.T) {
	connection, err := net.ListenIP("ip4:icmp", &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Skipf("raw ICMP socket needs CAP_NET_RAW: %v", err)
	}
	defer connection.Close()
	loopback := netip.MustParseAddr("127.0.0.1")
	// 192.0.2.1 is a documentation address that never answers.
	silent := netip.MustParseAddr("192.0.2.1")
	responders := sweepEcho(context.Background(), connection,
		[]netip.Addr{loopback, silent}, reflectorProbeID, 7, 500*time.Millisecond)
	if !responders[loopback] {
		t.Fatalf("responders = %v, want %s", responders, loopback)
	}
	if responders[silent] {
		t.Fatalf("responders = %v, %s should not answer", responders, silent)
	}
}
