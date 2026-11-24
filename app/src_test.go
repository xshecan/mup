package app

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/protocol"
)

func srcRegistrationOf(t *testing.T, raw string) pathRegistration {
	t.Helper()
	return pathRegistration{
		advertisedIP: netip.MustParseAddr("192.0.2.10"),
		listenPort:   51820,
		path:         mustParsePath(t, raw),
		nonce:        42,
		pathID:       3,
	}
}

func encodeFrame(t *testing.T, frame protocol.ControlFrame) []byte {
	t.Helper()
	packet := make([]byte, protocol.ControlFrameLength)
	if err := protocol.EncodeControlFrame(packet, frame); err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
	}
	return packet
}

func TestRegistrationFrameCarriesTheSourceRangeOfThePath(t *testing.T) {
	t.Parallel()

	packet, err := registrationFrame(srcRegistrationOf(t, "198.51.100.1:5000/icmp src 20000-20999"), 9)
	if err != nil {
		t.Fatalf("registrationFrame: %v", err)
	}
	frame, err := protocol.DecodeControlFrame(packet)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if frame.Flags&protocol.ControlFlagSourceRange == 0 || frame.SrcFirst != 20000 || frame.SrcLast != 20999 ||
		frame.Sequence != 9 || frame.ServerPort != 5000 {
		t.Fatalf("frame = %#v, want the range 20000-20999 on port 5000", frame)
	}
	if first, last := binary.BigEndian.Uint16(packet[44:46]), binary.BigEndian.Uint16(packet[46:48]); first != 20000 || last != 20999 {
		t.Fatalf("range bytes = %d-%d", first, last)
	}
}

func TestRegistrationFrameWithoutARangeIsUnchanged(t *testing.T) {
	t.Parallel()

	registration := srcRegistrationOf(t, "198.51.100.1:5000/udp via 203.0.113.9")
	registration.returnIP = registration.path.ReturnIP
	packet, err := registrationFrame(registration, 9)
	if err != nil {
		t.Fatalf("registrationFrame: %v", err)
	}
	want := encodeFrame(t, protocol.ControlFrame{
		Type: protocol.ControlRegister, Transport: protocol.TransportUDP, Flags: protocol.ControlFlagReturnIP,
		PathID: 3, Sequence: 9, ListenPort: 51820, ServerPort: 5000, LeaseSeconds: registrationLeaseSeconds,
		InstanceNonce: 42, AdvertisedIP: registration.advertisedIP, ReturnIP: registration.returnIP,
	})
	if !bytes.Equal(packet, want) {
		t.Fatalf("frame = %x, want %x", packet, want)
	}
}

func TestIngressReflectFrameCarriesTheSourceRangeOfThePath(t *testing.T) {
	t.Parallel()

	member := netip.MustParseAddr("203.0.113.5")
	packet, err := ingressReflectFrame(srcRegistrationOf(t, "198.51.100.1:5000/udp via 203.0.113.0/28 src 1000-1009"), member, 4)
	if err != nil {
		t.Fatalf("ingressReflectFrame: %v", err)
	}
	frame, err := protocol.DecodeControlFrame(packet)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if frame.Flags != protocol.ControlFlagIngressReflect|protocol.ControlFlagReturnIP|protocol.ControlFlagSourceRange ||
		frame.SrcFirst != 1000 || frame.SrcLast != 1009 || frame.ReturnIP != member {
		t.Fatalf("frame = %#v, want the reflect flags and the range 1000-1009", frame)
	}

	plain := srcRegistrationOf(t, "198.51.100.1:5000/udp via 203.0.113.0/28")
	packet, err = ingressReflectFrame(plain, member, 4)
	if err != nil {
		t.Fatalf("ingressReflectFrame: %v", err)
	}
	want := encodeFrame(t, protocol.ControlFrame{
		Type: protocol.ControlRegister, Transport: protocol.TransportUDP,
		Flags:  protocol.ControlFlagIngressReflect | protocol.ControlFlagReturnIP,
		PathID: 3, Sequence: 4, ListenPort: 51820, ServerPort: 5000, LeaseSeconds: registrationLeaseSeconds,
		InstanceNonce: 42, AdvertisedIP: plain.advertisedIP, ReturnIP: member,
	})
	if !bytes.Equal(packet, want) {
		t.Fatalf("frame without a range = %x, want %x", packet, want)
	}
}

func TestEgressRegisterFrameCarriesTheSourceRangeWithSequenceZero(t *testing.T) {
	t.Parallel()

	registration := srcRegistrationOf(t, "198.51.100.1:9000/udp")
	path := mustParsePath(t, "198.51.100.2:9200/icmp src 30000-30099")
	for _, lease := range []uint32{registrationLeaseSeconds, 0} {
		packet, err := egressRegisterFrame(registration, 1, path, config.ModeBalancer, 9, lease)
		if err != nil {
			t.Fatalf("lease %d: egressRegisterFrame: %v", lease, err)
		}
		frame, err := protocol.DecodeControlFrame(packet)
		if err != nil {
			t.Fatalf("lease %d: decode: %v", lease, err)
		}
		if frame.Flags&protocol.ControlFlagSourceRange == 0 || frame.SrcFirst != 30000 || frame.SrcLast != 30099 ||
			frame.Sequence != 0 || frame.LeaseSeconds != lease || frame.ServerPort != 9200 {
			t.Fatalf("lease %d: frame = %#v, want the range 30000-30099 with sequence 0", lease, frame)
		}
		if first, last := binary.BigEndian.Uint16(packet[36:38]), binary.BigEndian.Uint16(packet[38:40]); first != 30000 || last != 30099 {
			t.Fatalf("lease %d: range bytes = %d-%d", lease, first, last)
		}
	}

	plain := mustParsePath(t, "198.51.100.2:9200/icmp")
	packet, err := egressRegisterFrame(registration, 1, plain, config.ModeBalancer, 9, registrationLeaseSeconds)
	if err != nil {
		t.Fatalf("egressRegisterFrame: %v", err)
	}
	want := encodeFrame(t, protocol.ControlFrame{
		Type: protocol.ControlEgressRegister, Transport: protocol.TransportICMP, PathID: 1, Sequence: 9,
		ListenPort: 51820, ServerPort: 9200, LeaseSeconds: registrationLeaseSeconds, InstanceNonce: 42,
		AdvertisedIP: registration.advertisedIP, EgressMode: uint8(config.ModeBalancer), EgressServer: plain.Server,
	})
	if !bytes.Equal(packet, want) {
		t.Fatalf("frame without a range = %x, want %x", packet, want)
	}
}

func TestEgressRegistryKeepsTheSourceRangeAndReplacesThePathWhenItChanges(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	registry := newTestEgressRegistry(plane)
	now := time.Unix(1000, 0)
	frame := egressFrame(1, 9300, protocol.TransportUDP, config.ModeFailover)
	frame.Flags, frame.SrcFirst, frame.SrcLast = protocol.ControlFlagSourceRange, 20000, 20999
	if err := registry.register(frame, now); err != nil {
		t.Fatalf("register: %v", err)
	}
	key := egressKey{client: egressKeyOf, id: 1}
	if entry := plane.paths[key]; entry.SrcFirst != 20000 || entry.SrcLast != 20999 || entry.ServerPort != 9300 {
		t.Fatalf("entry = %#v, want the range 20000-20999 on port 9300", entry)
	}
	views := registry.clients(now)[egressKeyOf]
	if len(views) != 1 || len(views[0].Paths) != 1 || views[0].Paths[0].SrcFirst != 20000 || views[0].Paths[0].SrcLast != 20999 {
		t.Fatalf("views = %#v, want the range", views)
	}
	first := registry.paths[key]

	// The same frame keeps the path, and a new range replaces it.
	if err := registry.register(frame, now.Add(time.Second)); err != nil {
		t.Fatalf("register again: %v", err)
	}
	if registry.paths[key] != first {
		t.Fatal("the same EGRESS_REGISTER replaced the path")
	}
	changed := frame
	changed.SrcFirst, changed.SrcLast = 21000, 21000
	if err := registry.register(changed, now.Add(2*time.Second)); err != nil {
		t.Fatalf("register with a new range: %v", err)
	}
	if registry.paths[key] == first {
		t.Fatal("a new range kept the old path")
	}
	if entry := plane.paths[key]; entry.SrcFirst != 21000 || entry.SrcLast != 21000 {
		t.Fatalf("entry after the new range = %#v", entry)
	}
	plain := frame
	plain.Flags, plain.SrcFirst, plain.SrcLast = 0, 0, 0
	if err := registry.register(plain, now.Add(3*time.Second)); err != nil {
		t.Fatalf("register without a range: %v", err)
	}
	if entry := plane.paths[key]; entry.SrcFirst != 0 || entry.SrcLast != 0 {
		t.Fatalf("entry without a range = %#v", entry)
	}

	// A withdrawal names the path with its range, so it matches the path.
	if err := registry.register(changed, now.Add(4*time.Second)); err != nil {
		t.Fatalf("register: %v", err)
	}
	withdrawal := changed
	withdrawal.LeaseSeconds = 0
	if err := registry.register(withdrawal, now.Add(5*time.Second)); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if _, ok := plane.paths[key]; ok {
		t.Fatalf("the withdrawn path stays in the dataplane: %#v", plane.paths[key])
	}
}

func TestEgressTargetsKeepTheFixedPortOfAPathWithARange(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	registry := newTestEgressRegistry(plane)
	now := time.Unix(1000, 0)
	frame := egressFrame(0, 9300, protocol.TransportICMP, config.ModeFailover)
	frame.Flags, frame.SrcFirst, frame.SrcLast = protocol.ControlFlagSourceRange, 20000, 20999
	if err := registry.register(frame, now); err != nil {
		t.Fatalf("register: %v", err)
	}
	for _, target := range append(registry.probeTargets(now), registry.ackTargets(egressKeyOf, now)...) {
		if target.port != 9300 {
			t.Fatalf("target = %#v, want the fixed port 9300", target)
		}
		packet, _ := egressWirePacket(target, make([]byte, protocol.ControlFrameLength), 1)
		if identifier := binary.BigEndian.Uint16(packet[24:26]); identifier != 9300 {
			t.Fatalf("control Echo identifier = %d, want 9300", identifier)
		}
	}
}

func TestPlanCarriesTheSourceRangeOfEachPath(t *testing.T) {
	t.Parallel()

	group := testGroup(t, 51820, config.ModeFailover, "198.51.100.1:9000/udp src 20000-20999", "198.51.100.2:9100/icmp")
	group.EgressMode = config.ModeFailover
	group.EgressPaths = []config.Path{mustParsePath(t, "198.51.100.1:9300/icmp src 30000")}
	client := config.Client{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), Groups: []config.Group{group}}
	plan, err := buildPlan(config.App{Client: &client}, 42, fakeResolver{catchAll: 2})
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	paths := plan.client.Paths
	if paths[0].SrcFirst != 20000 || paths[0].SrcLast != 20999 || paths[1].SrcFirst != 0 || paths[1].SrcLast != 0 {
		t.Fatalf("paths = %#v", paths)
	}
	if egress := plan.client.EgressPaths[0]; egress.SrcFirst != 30000 || egress.SrcLast != 30000 {
		t.Fatalf("egress path = %#v", egress)
	}
}

func TestTheSourceRangeFollowsTheRuntimePathChanges(t *testing.T) {
	t.Parallel()

	fixture := newControllerFixture(t, "198.51.100.1:5000/udp src 20000-20999", "198.51.100.3:7000-7009/icmp src 30000-30099")
	// The plan writes the paths of the start, and the controller registers them.
	if registration := fixture.registrations[0]; !registration.path.HasSrc() || registration.path.SrcLast != 20999 {
		t.Fatalf("start registration 0 = %#v", registration.path)
	}

	added, err := fixture.controller.AddPath("198.51.100.4%eth4:5000/icmp src 40000-40009", 0)
	if err != nil {
		t.Fatalf("AddPath: %v", err)
	}
	if added.SrcFirst != 40000 || added.SrcLast != 40009 {
		t.Fatalf("added = %#v, want the range", added)
	}
	if path := fixture.dataplane.paths[added.ID]; path.SrcFirst != 40000 || path.SrcLast != 40009 {
		t.Fatalf("added path settings = %#v", path)
	}
	if registration := fixture.registrations[added.ID]; registration.path.SrcFirst != 40000 {
		t.Fatalf("added registration = %#v", registration.path)
	}
	if err := fixture.controller.RemovePath(added.ID); err != nil {
		t.Fatalf("RemovePath: %v", err)
	}
	if _, set := fixture.dataplane.paths[added.ID]; set {
		t.Fatalf("the removed slot keeps %#v", fixture.dataplane.paths[added.ID])
	}
	// The next path in the slot has no range.
	reused, err := fixture.controller.AddPath("198.51.100.4%eth4:5001/udp", 0)
	if err != nil {
		t.Fatalf("AddPath: %v", err)
	}
	if reused.ID != added.ID || fixture.dataplane.paths[reused.ID].SrcFirst != 0 || fixture.dataplane.paths[reused.ID].SrcLast != 0 || reused.SrcFirst != 0 {
		t.Fatalf("reused slot = %#v, %#v, want no range", reused, fixture.dataplane.paths[reused.ID])
	}

	// A port move keeps the range of the path.
	fixture.countPortPicks(7004)
	fixture.miss(t, 1, portMoveMisses)
	if path := fixture.dataplane.paths[1]; path.ServerPort != 7004 || path.SrcFirst != 30000 || path.SrcLast != 30099 {
		t.Fatalf("moved path = %#v, want port 7004 with the range", path)
	}
	if registration := fixture.registrations[1]; registration.path.ServerPort != 7004 || registration.path.SrcFirst != 30000 {
		t.Fatalf("moved registration = %#v", registration.path)
	}
	paths, _ := fixture.controller.Paths()
	if paths[1].SrcFirst != 30000 || paths[1].SrcLast != 30099 {
		t.Fatalf("path 1 view = %#v", paths[1])
	}
}

func TestAddBridgeRefusesAnICMPBridgeWithASourceRange(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	if _, err := fixture.controller.AddBridge("198.51.100.4:9600/icmp src 1000-2000", 51820); statusOf(err) != http.StatusBadRequest {
		t.Fatalf("AddBridge error = %v, want bad request", err)
	}
}

func TestTheSourceRangeFollowsTheRuntimeEgressPathChanges(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	controller := fixture.controller
	added, err := controller.AddEgressPath("198.51.100.1:9400/icmp src 30000-30099", 51820)
	if err != nil {
		t.Fatalf("AddEgressPath: %v", err)
	}
	if added.SrcFirst != 30000 || added.SrcLast != 30099 {
		t.Fatalf("added = %#v, want the range", added)
	}
	if egress := fixture.dataplane.egresses[added.ID]; egress.SrcFirst != 30000 || egress.SrcLast != 30099 {
		t.Fatalf("egress settings = %#v", egress)
	}
	byID := func() map[uint16]protocol.ControlFrame {
		frames := map[uint16]protocol.ControlFrame{}
		for _, frame := range decodeFrames(t, fixture.registrations[0].egressFrames(3)) {
			frames[frame.PathID] = frame
		}
		return frames
	}
	frame := byID()[uint16(added.ID)]
	if frame.Flags&protocol.ControlFlagSourceRange == 0 || frame.SrcFirst != 30000 || frame.Sequence != 0 {
		t.Fatalf("EGRESS_REGISTER = %#v, want the range with sequence 0", frame)
	}
	if other := byID()[0]; other.Flags&protocol.ControlFlagSourceRange != 0 || other.Sequence != 3 {
		t.Fatalf("EGRESS_REGISTER of a path without a range = %#v", other)
	}
	if err := controller.RemoveEgressPath(added.ID); err != nil {
		t.Fatalf("RemoveEgressPath: %v", err)
	}
	if _, set := fixture.dataplane.egresses[added.ID]; set {
		t.Fatalf("the removed egress slot keeps %#v", fixture.dataplane.egresses[added.ID])
	}
	// The withdrawal names the range, so the server finds the same path.
	if withdrawal := byID()[uint16(added.ID)]; withdrawal.LeaseSeconds != 0 || withdrawal.SrcFirst != 30000 || withdrawal.SrcLast != 30099 {
		t.Fatalf("withdrawal = %#v, want lease 0 with the range", withdrawal)
	}
}

func TestServerInspectorShowsTheSourceRangeOfARegisteredPath(t *testing.T) {
	t.Parallel()

	client := dataplane.ClientKey{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), InstanceNonce: 1}
	fake := fakeServerDataplane{
		registrations: []dataplane.Registration{{Client: client, ListenPort: 51820, ExpiresIn: time.Minute}},
		paths: []dataplane.RegisteredPath{
			{Client: client, PathID: 0, Transport: protocol.TransportICMP, Source: client.AdvertisedIP, Local: netip.MustParseAddr("203.0.113.5"), SrcFirst: 20000, SrcLast: 20999},
			{Client: client, PathID: 1, Transport: protocol.TransportUDP, Source: client.AdvertisedIP, Local: netip.MustParseAddr("203.0.113.5")},
		},
	}
	inspector := newServerInspector(config.Server{Port: config.SinglePort(5000), Target: netip.MustParseAddrPort("198.51.100.7:51820")}, fake, time.Unix(0, 0), nil)
	clients, err := inspector.Clients()
	if err != nil || len(clients) != 1 || len(clients[0].Paths) != 2 {
		t.Fatalf("Clients = %#v, %v", clients, err)
	}
	if path := clients[0].Paths[0]; path.SrcFirst != 20000 || path.SrcLast != 20999 {
		t.Fatalf("path 0 = %#v, want the range", path)
	}
	if path := clients[0].Paths[1]; path.SrcFirst != 0 || path.SrcLast != 0 {
		t.Fatalf("path 1 = %#v, want no range", path)
	}
}
