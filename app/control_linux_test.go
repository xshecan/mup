//go:build linux

package app

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/protocol"
)

func TestUDPPathReopensItsSocketAfterMissedACKs(t *testing.T) {
	t.Parallel()

	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer server.Close()
	loopback := netip.MustParseAddr("127.0.0.1")
	registration := pathRegistration{
		advertisedIP: loopback,
		listenPort:   51820,
		path: config.Path{
			Server:     loopback,
			ServerPort: uint16(server.LocalAddr().(*net.UDPAddr).Port),
			Transport:  protocol.TransportUDP,
		},
		nonce: 1,
	}
	path, err := openUDPPathConn(registration)
	if err != nil {
		t.Fatalf("openUDPPathConn: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = path.Run(ctx, func(context.Context, uint32, time.Time, bool) error { return nil })
	}()

	// The server never answers, so the path misses each ACK.
	sources := make(map[int]int)
	deadline := time.Now().Add(15 * time.Second)
	buffer := make([]byte, 128)
	for len(sources) < 2 {
		_ = server.SetReadDeadline(deadline)
		_, source, err := server.ReadFromUDP(buffer)
		if err != nil {
			t.Fatalf("REGISTER frames came from %d source ports, want a new port after %d misses: %v", len(sources), udpReopenAfterMisses, err)
		}
		sources[source.Port]++
	}
	for port, count := range sources {
		if count > udpReopenAfterMisses {
			t.Fatalf("source port %d sent %d frames, want at most %d", port, count, udpReopenAfterMisses)
		}
	}
	if err := path.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
