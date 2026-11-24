package app

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/protocol"
)

var (
	viaBridge = netip.MustParseAddr("5.6.7.8")
	viaMember = netip.MustParseAddr("203.0.113.9")
	viaLocal  = netip.MustParseAddr("203.0.113.5")
)

// egressPathsOfTheFile loads the egress paths of one group from a configuration
// file.
func egressPathsOfTheFile(t *testing.T, egress string) []config.Path {
	t.Helper()
	file := filepath.Join(t.TempDir(), "mup.yaml")
	content := "client:\n  advertise: 192.0.2.10\n  servers:\n    - port: 51820\n      ingress:\n        routes: [198.51.100.1:9000/udp]\n      egress:\n" + egress
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	app, err := config.Load(file)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return app.Client.Groups[0].EgressPaths
}

func TestTheEgressRegisterTellsTheTwoKindsOfEgressBridgeWithAVia(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	controller := fixture.controller
	bridgeVia, err := controller.AddEgressBridge("5.6.7.8:9700/udp via 203.0.113.9", 51820)
	if err != nil {
		t.Fatalf("AddEgressBridge: %v", err)
	}
	reflects, err := controller.AddEgressPath("198.51.100.1:9701/icmp via 203.0.113.0/28 bridge 5.6.7.9", 51820)
	if err != nil {
		t.Fatalf("AddEgressPath: %v", err)
	}
	if !bridgeVia.Bridge || !bridgeVia.BridgeVia || bridgeVia.Server != "5.6.7.8" || bridgeVia.ReturnIP != "203.0.113.9" {
		t.Fatalf("bridge via path = %#v", bridgeVia)
	}
	if !reflects.Bridge || reflects.BridgeVia || reflects.Server != "5.6.7.9" || reflects.ReturnIP != "203.0.113.0/28" {
		t.Fatalf("bridge path that reflects = %#v", reflects)
	}
	frames := decodeFrames(t, fixture.registrations[0].egressFrames(1))
	if len(frames) != 4 {
		t.Fatalf("EGRESS_REGISTER frames = %d, want 4", len(frames))
	}
	viaFrame, reflectFrame := frames[2], frames[3]
	if viaFrame.Flags != protocol.ControlFlagBridge|protocol.ControlFlagBridgeVia|protocol.ControlFlagReturnIP ||
		viaFrame.ReturnIP != viaMember || viaFrame.EgressServer != viaBridge {
		t.Fatalf("EGRESS_REGISTER of the bridge via path = %#v", viaFrame)
	}
	if reflectFrame.Flags != protocol.ControlFlagBridge|protocol.ControlFlagReturnPool ||
		reflectFrame.EgressServer != netip.MustParseAddr("5.6.7.9") {
		t.Fatalf("EGRESS_REGISTER of the bridge path that reflects = %#v", reflectFrame)
	}
}

func TestEgressSourceMatchesTellsTheKindsOfEgressBridge(t *testing.T) {
	t.Parallel()

	for _, transport := range []protocol.TransportID{protocol.TransportUDP, protocol.TransportICMP} {
		bridgeVia := config.Path{Server: viaBridge, ServerPort: 9700, Transport: transport, ReturnIP: viaMember, Bridge: true, BridgeVia: true}
		reflects := config.Path{Server: viaBridge, ServerPort: 9700, Transport: transport, ReturnIP: viaMember, Bridge: true}
		pool := bridgeVia
		pool.ReturnIP, pool.ReturnPrefix = netip.MustParseAddr("203.0.113.0"), 28
		for name, test := range map[string]struct {
			path   config.Path
			source netip.Addr
			port   uint16
			want   bool
		}{
			"bridge via from the bridge":           {path: bridgeVia, source: viaBridge, port: 9700, want: true},
			"bridge via from the member":           {path: bridgeVia, source: viaMember, port: 9700},
			"bridge via pool from the bridge":      {path: pool, source: viaBridge, port: 9700, want: true},
			"bridge via pool from a member":        {path: pool, source: viaMember, port: 9700},
			"bridge via from another port":         {path: bridgeVia, source: viaBridge, port: 9701},
			"bridge that reflects from the member": {path: reflects, source: viaMember, port: 9700, want: true},
			"bridge that reflects from the bridge": {path: reflects, source: viaBridge, port: 9700},
		} {
			if got := egressSourceMatches(test.path, test.source, transport, test.port); got != test.want {
				t.Fatalf("%s over %s = %v, want %v", name, transport, got, test.want)
			}
		}
	}
}

func TestTheEgressProbeReplyNamesTheReturnIPOfTheProbe(t *testing.T) {
	t.Parallel()

	registration := pathRegistration{advertisedIP: netip.MustParseAddr("192.0.2.10"), listenPort: 51820, nonce: 42}
	path := config.Path{Server: viaBridge, ServerPort: 9700, Transport: protocol.TransportUDP, ReturnIP: viaMember, Bridge: true, BridgeVia: true}
	probe := egressProbe{
		frame: protocol.ControlFrame{
			Type: protocol.ControlProbe, Transport: protocol.TransportUDP,
			Flags:  protocol.ControlFlagEgressPath | protocol.ControlFlagReturnIP,
			PathID: 2, Sequence: 9, ListenPort: 51820, ServerPort: 9700,
			InstanceNonce: 42, AdvertisedIP: registration.advertisedIP, ReturnIP: viaMember,
		},
		source:    viaBridge,
		transport: protocol.TransportUDP,
		port:      9700,
	}
	replyOf := func(probe egressProbe) protocol.ControlFrame {
		packet, err := egressProbeReplyFrame(registration, probe, path)
		if err != nil {
			t.Fatalf("egressProbeReplyFrame: %v", err)
		}
		frame, err := protocol.DecodeControlFrame(packet)
		if err != nil {
			t.Fatalf("DecodeControlFrame: %v", err)
		}
		return frame
	}
	if reply := replyOf(probe); reply.ReturnIP != viaMember {
		t.Fatalf("reply to a probe with a return IP names %s, want the member %s", reply.ReturnIP, viaMember)
	}
	// An old server sends no return IP, and the reply names the packet source.
	probe.frame.Flags = protocol.ControlFlagEgressPath
	probe.frame.ReturnIP = netip.Addr{}
	if reply := replyOf(probe); reply.ReturnIP != viaBridge {
		t.Fatalf("reply to a probe without a return IP names %s, want the source %s", reply.ReturnIP, viaBridge)
	}
}

func TestABridgeViaPathIsHealthyAfterAProbeFromTheBridge(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	if _, err := fixture.controller.AddEgressBridge("5.6.7.8:9700/icmp via 203.0.113.9", 51820); err != nil {
		t.Fatalf("AddEgressBridge: %v", err)
	}
	probe := egressProbe{
		frame: protocol.ControlFrame{
			Type: protocol.ControlProbe, Transport: protocol.TransportICMP,
			Flags:  protocol.ControlFlagEgressPath | protocol.ControlFlagReturnIP,
			PathID: 2, Sequence: 3, ListenPort: 51820, ServerPort: 9700,
			InstanceNonce: 42, AdvertisedIP: netip.MustParseAddr("192.0.2.10"), ReturnIP: viaMember,
		},
		source:    viaMember,
		transport: protocol.TransportICMP,
		port:      9700,
		received:  time.Now(),
	}
	fixture.controls.handle(probe)
	if sent := fixture.controls.takeSent(); len(sent) != 0 {
		t.Fatalf("probe replies to a probe from the member = %d, want none", len(sent))
	}
	probe.source = viaBridge
	fixture.controls.handle(probe)
	sent := fixture.controls.takeSent()
	if len(sent) != 1 || sent[0].frame.ReturnIP != viaMember {
		t.Fatalf("probe replies = %#v, want one that names the member", sent)
	}
	paths, _ := fixture.controller.Paths()
	for _, path := range paths {
		if path.Direction == directionEgress && path.ID == 2 && !path.Healthy {
			t.Fatalf("bridge via path = %#v, want it healthy", path)
		}
	}
}

func TestRuntimeEgressPathsMatchTheFile(t *testing.T) {
	t.Parallel()

	file := egressPathsOfTheFile(t, `        routes:
          - 198.51.100.1:9701/udp via 203.0.113.9 bridge 5.6.7.8
        bridges:
          - 5.6.7.8:9702/icmp via 203.0.113.0/28 per-packet
          - 5.6.7.8:9703/udp
`)
	fixture := newSplitFixture(t)
	controller := fixture.controller
	for index, add := range []func() error{
		func() error {
			_, err := controller.AddEgressPath("198.51.100.1:9701/udp via 203.0.113.9 bridge 5.6.7.8", 51820)
			return err
		},
		func() error {
			_, err := controller.AddEgressBridge("5.6.7.8:9702/icmp via 203.0.113.0/28 per-packet", 51820)
			return err
		},
		func() error {
			_, err := controller.AddEgressBridge("5.6.7.8:9703/udp", 51820)
			return err
		},
	} {
		if err := add(); err != nil {
			t.Fatalf("add %d: %v", index, err)
		}
		controller.mu.Lock()
		got := controller.egressSlots[2+index].path
		controller.mu.Unlock()
		if got != file[index] {
			t.Fatalf("runtime path %d = %#v, the file gives %#v", index, got, file[index])
		}
	}
	_, err := controller.AddEgressPath("198.51.100.1:9704/udp bridge 5.6.7.8", 51820)
	if statusOf(err) != http.StatusBadRequest || !strings.Contains(err.Error(), "needs a via") {
		t.Fatalf("AddEgressPath with a bridge suffix and no via error = %v", err)
	}
}

func bridgeViaRegistry(t *testing.T, plane *fakeEgressPlane) *egressRegistry {
	t.Helper()
	registry := newTestEgressRegistry(plane)
	registry.route = func(address netip.Addr) (netip.Addr, int, error) {
		if address != viaBridge {
			return netip.Addr{}, 0, errors.New("no route")
		}
		return viaLocal, 4, nil
	}
	return registry
}

func bridgeViaPoolFrame(id uint16) protocol.ControlFrame {
	frame := egressFrame(id, 12000, protocol.TransportICMP, config.ModeFailover)
	frame.Flags = protocol.ControlFlagReturnPool | protocol.ControlFlagBridge | protocol.ControlFlagBridgeVia
	frame.ReturnIP = egressPool
	frame.ReturnPrefix = 28
	frame.EgressServer = viaBridge
	return frame
}

func TestEgressRegistryKeepsABridgeViaPathWithTheUDPPool(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	// The members of a bridge via path are forged sources of the UDP wrapper,
	// so the path reads the UDP pool also when it is an ICMP path.
	plane.members[dataplane.PoolKey{Base: egressPool, Transport: protocol.TransportUDP}] = egressMembers
	registry := bridgeViaRegistry(t, plane)
	frame := bridgeViaPoolFrame(0)
	start := time.Unix(1000, 0)
	if err := registry.register(frame, start); err != nil {
		t.Fatalf("register: %v", err)
	}
	if !slices.Equal(plane.pools, []dataplane.PoolKey{{Base: egressPool, Transport: protocol.TransportUDP}}) {
		t.Fatalf("observed pools = %#v, want the UDP pool", plane.pools)
	}
	key := egressKey{client: egressKeyOf, id: 0}
	entry := plane.paths[key]
	if !entry.Bridge || !entry.BridgeVia || entry.LocalIP != viaLocal || entry.Server != viaBridge || len(entry.Members) != 0 {
		t.Fatalf("entry = %#v, want a bridge via path without healthy members", entry)
	}
	targets := registry.probeTargets(start)
	if len(targets) != len(egressMembers) {
		t.Fatalf("probe targets = %#v, want one for each member", targets)
	}
	for _, target := range targets {
		if !target.bridge || !target.bridgeVia || !slices.Contains(egressMembers, target.member) {
			t.Fatalf("probe target = %#v", target)
		}
	}
	if !registry.confirm(probeReply(0, protocol.TransportICMP, egressMembers[1]), start.Add(time.Second)) {
		t.Fatal("confirm of a member failed")
	}
	registry.sync(start.Add(time.Second))
	if entry := plane.paths[key]; !entry.BridgeVia || !slices.Equal(entry.Members, []netip.Addr{egressMembers[1]}) {
		t.Fatalf("entry = %#v, want the confirmed member", entry)
	}
	views := registry.clients(start.Add(time.Second))
	if groups := views[egressKeyOf]; len(groups) != 1 || len(groups[0].Paths) != 1 || !groups[0].Paths[0].BridgeVia ||
		groups[0].Paths[0].HealthyMembers != 1 || groups[0].Paths[0].Members != len(egressMembers) {
		t.Fatalf("API view = %#v", views[egressKeyOf])
	}

	// A frame without the bridge via flag is another path, and it replaces it.
	frame.Flags &^= protocol.ControlFlagBridgeVia
	if err := registry.register(frame, start.Add(2*time.Second)); err != nil {
		t.Fatalf("register without the flag: %v", err)
	}
	if entry := plane.paths[key]; entry.BridgeVia || !entry.Bridge || len(entry.Members) != 0 {
		t.Fatalf("entry = %#v, want a new bridge path that reflects", entry)
	}
	if last := plane.pools[len(plane.pools)-1]; last.Transport != protocol.TransportICMP {
		t.Fatalf("observed pool = %#v, want the ICMP pool of a bridge that reflects", last)
	}
}

// recordingEgressSender keeps what the egress service sends.
type recordingEgressSender struct {
	mu     sync.Mutex
	sent   []egressTarget
	frames []protocol.ControlFrame
}

func (r *recordingEgressSender) send(target egressTarget, packet []byte, _ uint16) error {
	frame, err := protocol.DecodeControlFrame(packet)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, target)
	r.frames = append(r.frames, frame)
	return nil
}

func TestTheProbeOfABridgeViaTargetNamesItsMember(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	registry := bridgeViaRegistry(t, plane)
	start := time.Now()
	viaFrame := egressFrame(0, 12000, protocol.TransportUDP, config.ModeFailover)
	viaFrame.Flags = protocol.ControlFlagReturnIP | protocol.ControlFlagBridge | protocol.ControlFlagBridgeVia
	viaFrame.ReturnIP = viaMember
	viaFrame.EgressServer = viaBridge
	reflectFrame := viaFrame
	reflectFrame.PathID = 1
	reflectFrame.ServerPort = 12001
	reflectFrame.Flags &^= protocol.ControlFlagBridgeVia
	for _, frame := range []protocol.ControlFrame{viaFrame, reflectFrame} {
		if err := registry.register(frame, start); err != nil {
			t.Fatalf("register %d: %v", frame.PathID, err)
		}
	}
	sender := &recordingEgressSender{}
	service := &egressService{registry: registry, sender: sender, logger: discardLogger}
	service.probe(start)
	if len(sender.frames) != 2 {
		t.Fatalf("probes = %#v, want two", sender.frames)
	}
	var viaProbe protocol.ControlFrame
	for _, frame := range sender.frames {
		switch frame.PathID {
		case 0:
			if frame.Flags != protocol.ControlFlagEgressPath|protocol.ControlFlagReturnIP || frame.ReturnIP != viaMember {
				t.Fatalf("probe of the bridge via path = %#v, want the member", frame)
			}
			viaProbe = frame
		case 1:
			if frame.Flags != protocol.ControlFlagEgressPath || frame.ReturnIP.IsValid() {
				t.Fatalf("probe of the bridge that reflects = %#v, want no return IP", frame)
			}
		}
	}

	// The client sees the probe from the bridge and names the member in its
	// reply, so confirm marks the member.
	registration := pathRegistration{advertisedIP: egressClient, listenPort: 51820, nonce: 7}
	path := config.Path{Server: viaBridge, ServerPort: 12000, Transport: protocol.TransportUDP, ReturnIP: viaMember, Bridge: true, BridgeVia: true}
	packet, err := egressProbeReplyFrame(registration, egressProbe{frame: viaProbe, source: viaBridge, transport: protocol.TransportUDP, port: 12000}, path)
	if err != nil {
		t.Fatalf("egressProbeReplyFrame: %v", err)
	}
	reply, err := protocol.DecodeControlFrame(packet)
	if err != nil {
		t.Fatalf("DecodeControlFrame: %v", err)
	}
	if !registry.confirm(reply, start.Add(time.Second)) {
		t.Fatal("confirm of the reply failed")
	}
	registry.sync(start.Add(time.Second))
	if group := plane.groups[egressGroupOf]; group.HealthyMask != 0b1 {
		t.Fatalf("group = %#v, want only the bridge via path healthy", group)
	}
}

func bridgeTarget(transport protocol.TransportID, bridgeVia bool) egressTarget {
	return egressTarget{
		client:     egressKeyOf,
		pathID:     0,
		listenPort: 51820,
		server:     viaBridge,
		port:       12000,
		transport:  transport,
		member:     viaMember,
		bridge:     true,
		bridgeVia:  bridgeVia,
		localIP:    viaLocal,
	}
}

// unwrapTestBridge checks the wrapper of a packet for a bridge, and returns its
// outer source and its inner packet.
func unwrapTestBridge(t *testing.T, packet []byte, port uint16) (netip.Addr, []byte) {
	t.Helper()
	source, destination, protocolNumber, payload := parseTestIPv4(t, packet)
	if destination != viaBridge || protocolNumber != ipProtocolUDP {
		t.Fatalf("wrapper goes to %s with protocol %d, want UDP to the bridge %s", destination, protocolNumber, viaBridge)
	}
	if binary.BigEndian.Uint16(payload[0:2]) != port || binary.BigEndian.Uint16(payload[2:4]) != port {
		t.Fatalf("wrapper ports = % x, want %d at both ends", payload[0:4], port)
	}
	inner, err := protocol.UnwrapBridge(packet)
	if err != nil {
		t.Fatalf("UnwrapBridge: %v", err)
	}
	return source, inner
}

func TestTheBridgeViaPacketIsTheDirectReplyWrappedFromTheMember(t *testing.T) {
	t.Parallel()

	frame := bytes.Repeat([]byte{0xab}, protocol.ControlFrameLength)
	for _, transport := range []protocol.TransportID{protocol.TransportUDP, protocol.TransportICMP} {
		packet, destination := egressWirePacket(bridgeTarget(transport, true), frame, 7)
		if destination != viaBridge {
			t.Fatalf("%s: destination = %s, want the bridge", transport, destination)
		}
		outerSource, inner := unwrapTestBridge(t, packet, 12000)
		if outerSource != viaMember {
			t.Fatalf("%s: wrapper source = %s, want the member %s", transport, outerSource, viaMember)
		}
		source, target, protocolNumber, payload := parseTestIPv4(t, inner)
		if source != viaBridge || target != egressClient {
			t.Fatalf("%s: inner packet = %s to %s, want the bridge to the client", transport, source, target)
		}
		switch transport {
		case protocol.TransportUDP:
			if protocolNumber != ipProtocolUDP || binary.BigEndian.Uint16(payload[0:2]) != 12000 ||
				binary.BigEndian.Uint16(payload[2:4]) != 51820 || !bytes.Equal(payload[8:], frame) {
				t.Fatalf("inner UDP = protocol %d, % x", protocolNumber, payload[:8])
			}
		case protocol.TransportICMP:
			echo, err := parseICMPEcho(payload)
			if err != nil {
				t.Fatalf("parseICMPEcho: %v", err)
			}
			if protocolNumber != ipProtocolICMP || echo.echoType != icmpEchoReply || echo.identifier != 12000 ||
				echo.sequence != 7 || !bytes.Equal(echo.payload, frame) {
				t.Fatalf("inner echo = %#v", echo)
			}
		}
	}
}

func TestTheBridgePacketThatReflectsIsUnchanged(t *testing.T) {
	t.Parallel()

	frame := bytes.Repeat([]byte{0xcd}, protocol.ControlFrameLength)
	for _, transport := range []protocol.TransportID{protocol.TransportUDP, protocol.TransportICMP} {
		target := bridgeTarget(transport, false)
		packet, destination := egressWirePacket(target, frame, 7)
		inner, _ := egressPacket(target, frame, 7)
		if want := protocol.WrapForBridge(inner, viaLocal, viaBridge, 12000); destination != viaBridge || !bytes.Equal(packet, want) {
			t.Fatalf("%s: packet differs from the wrapped packet of the via", transport)
		}
		outerSource, unwrapped := unwrapTestBridge(t, packet, 12000)
		if outerSource != viaLocal {
			t.Fatalf("%s: wrapper source = %s, want the local address", transport, outerSource)
		}
		source, destinationOfInner, _, _ := parseTestIPv4(t, unwrapped)
		switch transport {
		case protocol.TransportUDP:
			if source != viaMember || destinationOfInner != egressClient {
				t.Fatalf("inner UDP = %s to %s, want the member to the client", source, destinationOfInner)
			}
		case protocol.TransportICMP:
			if source != egressClient || destinationOfInner != viaMember {
				t.Fatalf("inner echo = %s to %s, want the client to the member", source, destinationOfInner)
			}
		}
	}
	// A direct path is not wrapped.
	direct := bridgeTarget(protocol.TransportUDP, false)
	direct.bridge, direct.member = false, netip.Addr{}
	packet, destination := egressWirePacket(direct, frame, 7)
	if source, target, _, _ := parseTestIPv4(t, packet); destination != egressClient || source != viaBridge || target != egressClient {
		t.Fatalf("direct packet = %s to %s via %s", source, target, destination)
	}
}
