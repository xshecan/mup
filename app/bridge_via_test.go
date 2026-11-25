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

// bridgeViaRegistry routes the bridge from viaLocal on interface 4, and every
// address of the pool 198.51.100.0/28 on interface 6.
func bridgeViaRegistry(t *testing.T, plane *fakeEgressPlane) *egressRegistry {
	t.Helper()
	registry := newTestEgressRegistry(plane)
	registry.route = func(address netip.Addr) (netip.Addr, int, error) {
		switch {
		case address == viaBridge:
			return viaLocal, 4, nil
		case netip.PrefixFrom(egressPool, 28).Contains(address):
			return viaLocal, 6, nil
		}
		return netip.Addr{}, 0, errors.New("no route")
	}
	return registry
}

func bridgeViaPoolFrame(id uint16, transport protocol.TransportID) protocol.ControlFrame {
	frame := egressFrame(id, 12000, transport, config.ModeFailover)
	frame.Flags = protocol.ControlFlagReturnPool | protocol.ControlFlagBridge | protocol.ControlFlagBridgeVia
	frame.ReturnIP = egressPool
	frame.ReturnPrefix = 28
	frame.EgressServer = viaBridge
	return frame
}

// A UDP bridge via path forges its wrappers from the members, so it reads the
// UDP pool and leaves on the route to the bridge.
func TestEgressRegistryKeepsABridgeViaPathWithTheUDPPool(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	plane.members[dataplane.PoolKey{Base: egressPool, Transport: protocol.TransportUDP}] = egressMembers
	registry := bridgeViaRegistry(t, plane)
	frame := bridgeViaPoolFrame(0, protocol.TransportUDP)
	start := time.Unix(1000, 0)
	if err := registry.register(frame, start); err != nil {
		t.Fatalf("register: %v", err)
	}
	if !slices.Equal(plane.pools, []dataplane.PoolKey{{Base: egressPool, Transport: protocol.TransportUDP}}) {
		t.Fatalf("observed pools = %#v, want the UDP pool", plane.pools)
	}
	key := egressKey{client: egressKeyOf, id: 0}
	entry := plane.paths[key]
	if !entry.Bridge || !entry.BridgeVia || entry.LocalIP != viaLocal || entry.Server != viaBridge || entry.Ifindex != 4 || len(entry.Members) != 0 {
		t.Fatalf("entry = %#v, want a bridge via path on the route to the bridge without healthy members", entry)
	}
	targets := registry.probeTargets(start)
	if len(targets) != len(egressMembers) {
		t.Fatalf("probe targets = %#v, want one for each member", targets)
	}
	for _, target := range targets {
		if !target.bridge || !target.bridgeVia || target.reflectsWrapper() || !slices.Contains(egressMembers, target.member) {
			t.Fatalf("probe target = %#v", target)
		}
	}
	if !registry.confirm(probeReply(0, protocol.TransportUDP, egressMembers[1]), start.Add(time.Second)) {
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
	if last := plane.pools[len(plane.pools)-1]; last.Transport != protocol.TransportUDP {
		t.Fatalf("observed pool = %#v, want the UDP pool of the path", last)
	}
}

// An ICMP bridge via path reflects its wrappers off the members, so it reads
// the ICMP pool, whose members answer pings, and leaves on the route to the
// members. It keeps the source of the route to the bridge.
func TestEgressRegistryKeepsAnICMPBridgeViaPathWithTheICMPPool(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	plane.members[dataplane.PoolKey{Base: egressPool, Transport: protocol.TransportICMP}] = egressMembers
	registry := bridgeViaRegistry(t, plane)
	frame := bridgeViaPoolFrame(0, protocol.TransportICMP)
	start := time.Unix(1000, 0)
	if err := registry.register(frame, start); err != nil {
		t.Fatalf("register: %v", err)
	}
	if !slices.Equal(plane.pools, []dataplane.PoolKey{{Base: egressPool, Transport: protocol.TransportICMP}}) {
		t.Fatalf("observed pools = %#v, want the ICMP pool", plane.pools)
	}
	key := egressKey{client: egressKeyOf, id: 0}
	entry := plane.paths[key]
	if !entry.Bridge || !entry.BridgeVia || entry.LocalIP != viaLocal || entry.Server != viaBridge || entry.Ifindex != 6 {
		t.Fatalf("entry = %#v, want a bridge via path on the route to the members with the source of the bridge route", entry)
	}
	targets := registry.probeTargets(start)
	if len(targets) != len(egressMembers) {
		t.Fatalf("probe targets = %#v, want one for each member", targets)
	}
	for _, target := range targets {
		if !target.reflectsWrapper() || !slices.Contains(egressMembers, target.member) {
			t.Fatalf("probe target = %#v, want a target that reflects off a member", target)
		}
		if _, destination := egressWirePacket(target, make([]byte, protocol.ControlFrameLength), 1); destination != target.member {
			t.Fatalf("probe goes to %s, want the member %s", destination, target.member)
		}
	}
	if !registry.confirm(probeReply(0, protocol.TransportICMP, egressMembers[1]), start.Add(time.Second)) {
		t.Fatal("confirm of a member failed")
	}
	registry.sync(start.Add(time.Second))
	if entry := plane.paths[key]; !slices.Equal(entry.Members, []netip.Addr{egressMembers[1]}) {
		t.Fatalf("entry = %#v, want the confirmed member", entry)
	}

	// A return IP without a route has no interface for the reflected
	// wrapper, so the registration fails.
	single := egressFrame(1, 12001, protocol.TransportICMP, config.ModeFailover)
	single.Flags = protocol.ControlFlagReturnIP | protocol.ControlFlagBridge | protocol.ControlFlagBridgeVia
	single.ReturnIP = viaMember
	single.EgressServer = viaBridge
	if err := registry.register(single, start); err == nil {
		t.Fatal("register of a member without a route succeeded")
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
	packet, destination := egressWirePacket(bridgeTarget(protocol.TransportUDP, true), frame, 7)
	if destination != viaBridge {
		t.Fatalf("destination = %s, want the bridge", destination)
	}
	outerSource, inner := unwrapTestBridge(t, packet, 12000)
	if outerSource != viaMember {
		t.Fatalf("wrapper source = %s, want the member %s", outerSource, viaMember)
	}
	source, target, protocolNumber, payload := parseTestIPv4(t, inner)
	if source != viaBridge || target != egressClient {
		t.Fatalf("inner packet = %s to %s, want the bridge to the client", source, target)
	}
	if protocolNumber != ipProtocolUDP || binary.BigEndian.Uint16(payload[0:2]) != 12000 ||
		binary.BigEndian.Uint16(payload[2:4]) != 51820 || !bytes.Equal(payload[8:], frame) {
		t.Fatalf("inner UDP = protocol %d, % x", protocolNumber, payload[:8])
	}
}

// An ICMP bridge via path reflects the wrapper off the member: an Echo
// Request from the bridge address to the member, with a valid checksum, that
// holds the direct Echo Reply from the bridge address to the client.
func TestTheICMPBridgeViaPacketIsAnEchoRequestToTheMember(t *testing.T) {
	t.Parallel()

	frame := bytes.Repeat([]byte{0xab}, protocol.ControlFrameLength)
	target := bridgeTarget(protocol.TransportICMP, true)
	packet, destination := egressWirePacket(target, frame, 7)
	if destination != viaMember {
		t.Fatalf("destination = %s, want the member %s", destination, viaMember)
	}
	source, outerDestination, protocolNumber, payload := parseTestIPv4(t, packet)
	if source != viaBridge || outerDestination != viaMember || protocolNumber != ipProtocolICMP {
		t.Fatalf("wrapper = protocol %d from %s to %s, want ICMP from the bridge to the member", protocolNumber, source, outerDestination)
	}
	if payload[0] != icmpEchoRequest || payload[1] != 0 || binary.BigEndian.Uint16(payload[4:6]) != 12000 ||
		binary.BigEndian.Uint16(payload[6:8]) != 12000 {
		t.Fatalf("Echo header = % x, want an Echo Request with identifier and sequence 12000", payload[:8])
	}
	if internetChecksum(payload) != 0 {
		t.Fatal("the ICMP checksum of the wrapper is invalid")
	}
	direct := target
	direct.member = netip.Addr{}
	want, _ := egressPacket(direct, frame, 7)
	if wrapped := protocol.WrapForBridgeEcho(want, viaBridge, viaMember, 12000, 12000); !bytes.Equal(packet, wrapped) {
		t.Fatal("packet differs from the Echo wrapper of the direct reply")
	}
	inner, err := protocol.UnwrapBridge(packet)
	if err != nil {
		t.Fatalf("UnwrapBridge: %v", err)
	}
	if !bytes.Equal(inner, want) {
		t.Fatal("the inner packet is not the direct reply")
	}
	innerSource, innerDestination, innerProtocol, innerPayload := parseTestIPv4(t, inner)
	if innerSource != viaBridge || innerDestination != egressClient || innerProtocol != ipProtocolICMP {
		t.Fatalf("inner packet = protocol %d from %s to %s, want ICMP from the bridge to the client", innerProtocol, innerSource, innerDestination)
	}
	echo, err := parseICMPEcho(innerPayload)
	if err != nil {
		t.Fatalf("parseICMPEcho: %v", err)
	}
	if echo.echoType != icmpEchoReply || echo.identifier != 12000 || echo.sequence != 7 || !bytes.Equal(echo.payload, frame) {
		t.Fatalf("inner echo = %#v", echo)
	}

	// Without a member the path has nothing to reflect off, and the wrapper
	// leaves from the local address to the bridge, as the dataplane does.
	target.member = netip.Addr{}
	packet, destination = egressWirePacket(target, frame, 7)
	if outerSource, _ := unwrapTestBridge(t, packet, 12000); destination != viaBridge || outerSource != viaLocal {
		t.Fatalf("wrapper without a member = from %s via %s, want from %s to the bridge", outerSource, destination, viaLocal)
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
