package app

import (
	"net/netip"
	"testing"
	"time"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/protocol"
)

func TestProbeReplyFrameNamesTheReflector(t *testing.T) {
	t.Parallel()
	registration := pathRegistration{
		advertisedIP: netip.MustParseAddr("10.0.0.1"),
		listenPort:   51820,
		nonce:        7,
		pathID:       2,
		path: config.Path{
			Server:       netip.MustParseAddr("203.0.113.5"),
			ServerPort:   5000,
			Transport:    protocol.TransportUDP,
			ReturnIP:     netip.MustParseAddr("194.225.72.0"),
			ReturnPrefix: 24,
		},
	}
	reflector := netip.MustParseAddr("194.225.72.10")
	packet, err := probeReplyFrame(registration, reflector, 9)
	if err != nil {
		t.Fatalf("probeReplyFrame: %v", err)
	}
	frame, err := protocol.DecodeControlFrame(packet)
	if err != nil {
		t.Fatalf("decode probe reply: %v", err)
	}
	if frame.Type != protocol.ControlProbeReply {
		t.Fatalf("type = %d, want probe reply", frame.Type)
	}
	if frame.Transport != protocol.TransportUDP || frame.ReturnIP != reflector {
		t.Fatalf("frame = %+v, want UDP reflector %s", frame, reflector)
	}
	if frame.AdvertisedIP != registration.advertisedIP || frame.InstanceNonce != 7 ||
		frame.PathID != 2 || frame.Sequence != 9 {
		t.Fatalf("frame identity = %+v", frame)
	}
}

func TestReflectorTargetsActiveRefreshAndExpiry(t *testing.T) {
	t.Parallel()
	targets := newReflectorTargets()
	now := time.Now()
	target := reflectorTarget{
		advertisedIP: netip.MustParseAddr("10.0.0.1"),
		listenPort:   51820,
		nonce:        1,
		pathID:       0,
		serverPort:   5000,
		base:         netip.MustParseAddr("194.225.72.0"),
		prefix:       24,
	}
	targets.add(target, now.Add(time.Second))
	if got := targets.active(now); len(got) != 1 || got[0].base != target.base {
		t.Fatalf("active = %+v, want the one target", got)
	}
	// The same client re-registering refreshes one entry, not two.
	targets.add(target, now.Add(2*time.Second))
	if got := targets.active(now.Add(500 * time.Millisecond)); len(got) != 1 {
		t.Fatalf("active after refresh = %d, want 1", len(got))
	}
	if got := targets.active(now.Add(3 * time.Second)); len(got) != 0 {
		t.Fatalf("active after expiry = %d, want 0", len(got))
	}
}
