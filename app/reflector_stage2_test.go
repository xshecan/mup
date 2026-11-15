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

func TestReflectorTargetsConfirmOnlyAProbedPool(t *testing.T) {
	t.Parallel()
	targets := newReflectorTargets()
	now := time.Now()
	targets.add(reflectorTarget{
		advertisedIP: netip.MustParseAddr("91.216.217.188"),
		listenPort:   51821,
		nonce:        0xa2d3e1aecf732bd7,
		pathID:       0,
		serverPort:   9000,
		base:         netip.MustParseAddr("94.184.45.48"),
		prefix:       28,
	}, now.Add(30*time.Second))
	reply := protocol.ControlFrame{
		Type:          protocol.ControlProbeReply,
		Transport:     protocol.TransportUDP,
		Flags:         protocol.ControlFlagReturnIP,
		PathID:        0,
		InstanceNonce: 0xa2d3e1aecf732bd7,
		AdvertisedIP:  netip.MustParseAddr("91.216.217.188"),
		ReturnIP:      netip.MustParseAddr("94.184.45.50"),
	}
	if !targets.confirms(reply, now) {
		t.Fatal("a reply for the probed pool should confirm")
	}
	tests := map[string]func(*protocol.ControlFrame){
		"other nonce":       func(f *protocol.ControlFrame) { f.InstanceNonce++ },
		"other path":        func(f *protocol.ControlFrame) { f.PathID = 1 },
		"other client":      func(f *protocol.ControlFrame) { f.AdvertisedIP = netip.MustParseAddr("91.216.217.189") },
		"outside the pool":  func(f *protocol.ControlFrame) { f.ReturnIP = netip.MustParseAddr("94.184.45.64") },
		"not a probe reply": func(f *protocol.ControlFrame) { f.Type = protocol.ControlRegister },
	}
	for name, change := range tests {
		frame := reply
		change(&frame)
		if targets.confirms(frame, now) {
			t.Fatalf("%s: the reply should not confirm", name)
		}
	}
	if targets.confirms(reply, now.Add(time.Minute)) {
		t.Fatal("a reply after the lease should not confirm")
	}
}
