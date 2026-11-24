package app

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/protocol"
)

type sentFrame struct {
	registration pathRegistration
	frame        protocol.ControlFrame
}

// fakeControls records what the controller asks of the control sockets.
type fakeControls struct {
	mu            sync.Mutex
	registrations map[int]pathRegistration
	listened      []egressListen
	handle        func(egressProbe)
	sent          []sentFrame
	stopped       bool
}

func (f *fakeControls) open(registration pathRegistration) (pathConn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.registrations[int(registration.pathID)] = registration
	return newFakePathConn(), nil
}

func (f *fakeControls) listenEgress(listen egressListen, handle func(egressProbe)) (func(), error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listened = append(f.listened, listen)
	f.handle = handle
	return func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.stopped = true
	}, nil
}

func (f *fakeControls) sendIngress(registration pathRegistration, packet []byte) error {
	frame, err := protocol.DecodeControlFrame(packet)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, sentFrame{registration: registration, frame: frame})
	return nil
}

func (f *fakeControls) takeSent() []sentFrame {
	f.mu.Lock()
	defer f.mu.Unlock()
	sent := f.sent
	f.sent = nil
	return sent
}

type splitFixture struct {
	controllerFixture
	controls *fakeControls
}

func newSplitFixture(t *testing.T) splitFixture {
	t.Helper()
	group := testGroup(t, 51820, config.ModeFailover, "198.51.100.1:9000/udp", "198.51.100.2:9100/icmp")
	group.EgressMode = config.ModeBalancer
	for _, raw := range []string{"198.51.100.1:9200/icmp via 203.0.113.0/28", "198.51.100.1:9300/udp"} {
		group.EgressPaths = append(group.EgressPaths, mustParsePath(t, raw))
	}
	paired := testGroup(t, 51821, config.ModeFailover, "198.51.100.3:5000/udp")
	client := config.Client{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), Groups: []config.Group{group, paired}}
	if err := client.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	plan, err := buildPlan(config.App{Client: &client}, 42, fakeResolver{catchAll: 2})
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	if len(plan.client.EgressPaths) != 2 || plan.client.Groups[0].DownMask != 0b11 || plan.client.Groups[1].DownMask != 0 {
		t.Fatalf("plan egress paths = %d, groups = %#v", len(plan.client.EgressPaths), plan.client.Groups)
	}
	fake := &fakeClientDataplane{paths: map[int]dataplane.PathSettings{}, groups: map[uint16]dataplane.GroupSettings{}}
	controls := &fakeControls{registrations: map[int]pathRegistration{}}
	controller := newClientController(client, *plan.client, fake, fakeResolver{catchAll: 2}, controls, time.Unix(100, 0), discardLogger)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := controller.start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	fixture := splitFixture{controls: controls}
	fixture.controller = controller
	fixture.dataplane = fake
	fixture.registrations = controls.registrations
	return fixture
}

func mustParsePath(t *testing.T, raw string) config.Path {
	t.Helper()
	path, err := config.ParsePath(raw)
	if err != nil {
		t.Fatalf("ParsePath(%q): %v", raw, err)
	}
	return path
}

func decodeFrames(t *testing.T, packets [][]byte) []protocol.ControlFrame {
	t.Helper()
	frames := make([]protocol.ControlFrame, 0, len(packets))
	for _, packet := range packets {
		frame, err := protocol.DecodeControlFrame(packet)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		frames = append(frames, frame)
	}
	slices.SortFunc(frames, func(a, b protocol.ControlFrame) int { return int(a.PathID) - int(b.PathID) })
	return frames
}

func TestSplitGroupSendsItsEgressPaths(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	if len(fixture.controls.listened) != 1 || !slices.Equal(fixture.controls.listened[0].listenPorts, []uint16{51820}) ||
		fixture.controls.listened[0].nonce != 42 {
		t.Fatalf("listenEgress = %#v, want the split group only", fixture.controls.listened)
	}
	if fixture.registrations[2].egresses != nil {
		t.Fatal("the ingress path of the paired group sends egress paths")
	}
	frames := decodeFrames(t, fixture.registrations[1].egressFrames(9))
	if len(frames) != 2 {
		t.Fatalf("EGRESS_REGISTER frames = %d, want 2", len(frames))
	}
	pool, direct := frames[0], frames[1]
	if pool.Type != protocol.ControlEgressRegister || pool.Transport != protocol.TransportICMP || pool.ServerPort != 9200 ||
		pool.Flags != protocol.ControlFlagReturnPool || pool.ReturnIP != netip.MustParseAddr("203.0.113.0") || pool.ReturnPrefix != 28 ||
		pool.EgressServer != netip.MustParseAddr("198.51.100.1") || pool.EgressMode != uint8(config.ModeBalancer) ||
		pool.ListenPort != 51820 || pool.Sequence != 9 || pool.LeaseSeconds != registrationLeaseSeconds {
		t.Fatalf("pool frame = %#v", pool)
	}
	if direct.PathID != 1 || direct.Transport != protocol.TransportUDP || direct.Flags != 0 || direct.ReturnIP.IsValid() {
		t.Fatalf("direct frame = %#v", direct)
	}
}

func TestEgressProbeIsAnsweredOnAnIngressPath(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	probe := egressProbe{
		frame: protocol.ControlFrame{
			Type: protocol.ControlProbe, Transport: protocol.TransportICMP, Flags: protocol.ControlFlagEgressPath,
			PathID: 0, Sequence: 77, ListenPort: 51820, ServerPort: 9200,
			InstanceNonce: 42, AdvertisedIP: netip.MustParseAddr("192.0.2.10"),
		},
		source:    netip.MustParseAddr("203.0.113.4"),
		transport: protocol.TransportICMP,
		port:      9200,
		received:  time.Now(),
	}
	fixture.controls.handle(probe)
	sent := fixture.controls.takeSent()
	if len(sent) != 1 || sent[0].registration.pathID != 0 {
		t.Fatalf("probe replies = %#v, want one on ingress path 0", sent)
	}
	reply := sent[0].frame
	if reply.Type != protocol.ControlProbeReply || reply.Flags != protocol.ControlFlagEgressPath|protocol.ControlFlagReturnIP ||
		reply.PathID != 0 || reply.Sequence != 77 || reply.ReturnIP != probe.source || reply.Transport != protocol.TransportICMP {
		t.Fatalf("probe reply = %#v", reply)
	}
	paths, _ := fixture.controller.Paths()
	var downs []bool
	for _, path := range paths {
		if path.Direction == directionEgress {
			downs = append(downs, path.Healthy)
		}
	}
	if !slices.Equal(downs, []bool{true, false}) {
		t.Fatalf("egress path health = %v, want only the probed path healthy", downs)
	}

	for name, bad := range map[string]egressProbe{
		"source outside the pool": {frame: probe.frame, source: netip.MustParseAddr("203.0.114.4"), transport: protocol.TransportICMP, port: 9200},
		"other port":              {frame: probe.frame, source: probe.source, transport: protocol.TransportICMP, port: 9201},
		"other transport":         {frame: probe.frame, source: probe.source, transport: protocol.TransportUDP, port: 9200},
	} {
		fixture.controls.handle(bad)
		if sent := fixture.controls.takeSent(); len(sent) != 0 {
			t.Fatalf("%s: probe replies = %d, want none", name, len(sent))
		}
	}

	// Without a healthy ingress path, the reply goes on every ingress path.
	fixture.miss(t, 0, missLimit)
	fixture.miss(t, 1, missLimit)
	fixture.controls.handle(probe)
	if sent := fixture.controls.takeSent(); len(sent) != 2 {
		t.Fatalf("probe replies without a healthy ingress path = %d, want 2", len(sent))
	}
}

func TestEgressPathRuntimeChanges(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	controller := fixture.controller
	added, err := controller.AddEgressPath("198.51.100.1:9400/udp via 203.0.113.9", 51820)
	if err != nil {
		t.Fatalf("AddEgressPath: %v", err)
	}
	if added.ID != 2 || added.Direction != directionEgress || added.Healthy {
		t.Fatalf("added = %#v", added)
	}
	if group := fixture.dataplane.groups[51820]; group.DownMask != 0b111 {
		t.Fatalf("group = %#v after the add", group)
	}
	for name, test := range map[string]struct {
		raw    string
		port   uint16
		status int
	}{
		"same egress path": {raw: "198.51.100.1:9400/udp", port: 51820, status: http.StatusConflict},
		"interface":        {raw: "198.51.100.1%eth0:9500/udp", port: 51820, status: http.StatusBadRequest},
		"port range":       {raw: "198.51.100.1:9500-9510/udp", port: 51820, status: http.StatusBadRequest},
		"paired group":     {raw: "198.51.100.1:9500/udp", port: 51821, status: http.StatusConflict},
	} {
		if _, err := controller.AddEgressPath(test.raw, test.port); statusOf(err) != test.status {
			t.Fatalf("%s: AddEgressPath error = %v, want status %d", name, err, test.status)
		}
	}
	if _, err := controller.AddBridge("198.51.100.4:9600/udp via 203.0.113.9", 51820); statusOf(err) != http.StatusBadRequest {
		t.Fatalf("AddBridge with via error = %v, want bad request", err)
	}

	if err := controller.RemoveEgressPath(1); err != nil {
		t.Fatalf("RemoveEgressPath: %v", err)
	}
	if group := fixture.dataplane.groups[51820]; group.DownMask != 0b101 {
		t.Fatalf("group = %#v after the removal", group)
	}
	if err := controller.SetEgressMode("repeater", 51820); err != nil {
		t.Fatalf("SetEgressMode: %v", err)
	}
	if group := fixture.dataplane.groups[51820]; group.EgressMode != config.ModeRepeater {
		t.Fatalf("group = %#v after the mode change", group)
	}
	if err := controller.SetEgressMode("repeater", 51821); statusOf(err) != http.StatusConflict {
		t.Fatalf("SetEgressMode on a paired group error = %v", err)
	}
	frames := decodeFrames(t, fixture.registrations[0].egressFrames(3))
	leases := map[uint16]uint32{}
	for _, frame := range frames {
		leases[frame.PathID] = frame.LeaseSeconds
		if frame.EgressMode != uint8(config.ModeRepeater) {
			t.Fatalf("frame %d has egress mode %d, want repeater", frame.PathID, frame.EgressMode)
		}
	}
	if len(leases) != 3 || leases[0] != registrationLeaseSeconds || leases[1] != 0 || leases[2] != registrationLeaseSeconds {
		t.Fatalf("frame leases = %v, want the removed path withdrawn with a lease of zero", leases)
	}
	if err := controller.RemoveEgressPath(0); err != nil {
		t.Fatalf("RemoveEgressPath(0): %v", err)
	}
	if err := controller.RemoveEgressPath(2); statusOf(err) != http.StatusConflict {
		t.Fatalf("RemoveEgressPath of the last egress path error = %v", err)
	}
}

func TestTheProbeReplyOfAReflectPathKnowsTheMembersThatAnswered(t *testing.T) {
	t.Parallel()

	group := testGroup(t, 51820, config.ModeFailover, "198.51.100.1:9000/udp via 203.0.113.0/30")
	group.EgressPaths = append(group.EgressPaths, mustParsePath(t, "198.51.100.1:9300/udp"))
	client := config.Client{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), Groups: []config.Group{group}}
	if err := client.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	plan, err := buildPlan(config.App{Client: &client}, 42, fakeResolver{catchAll: 2})
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	fake := &fakeClientDataplane{paths: map[int]dataplane.PathSettings{}, groups: map[uint16]dataplane.GroupSettings{}}
	controls := &fakeControls{registrations: map[int]pathRegistration{}}
	controller := newClientController(client, *plan.client, fake, fakeResolver{catchAll: 2}, controls, time.Unix(100, 0), discardLogger)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := controller.start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	registration := controls.registrations[0]
	if !registration.ingressReflect || len(registration.members) != 4 || registration.healthyMembers != nil {
		t.Fatalf("registration = %#v, want a reflect path with 4 candidates and no healthy member yet", registration)
	}

	// The control loop publishes the members that answered. A member outside
	// the candidates, from an older path in the slot, does not count.
	answered := netip.MustParseAddr("203.0.113.2")
	if err := registration.writeMembers([]netip.Addr{answered, netip.MustParseAddr("203.0.114.9")}); err != nil {
		t.Fatalf("writeMembers: %v", err)
	}
	probe := egressProbe{
		frame: protocol.ControlFrame{
			Type: protocol.ControlProbe, Transport: protocol.TransportUDP, Flags: protocol.ControlFlagEgressPath,
			PathID: 0, Sequence: 5, ListenPort: 51820, ServerPort: 9300,
			InstanceNonce: 42, AdvertisedIP: client.AdvertisedIP,
		},
		source:    netip.MustParseAddr("198.51.100.1"),
		transport: protocol.TransportUDP,
		port:      9300,
		received:  time.Now(),
	}
	controls.handle(probe)
	sent := controls.takeSent()
	if len(sent) != 1 || !slices.Equal(sent[0].registration.healthyMembers, []netip.Addr{answered}) {
		t.Fatalf("probe replies = %#v, want one that knows the member %s", sent, answered)
	}
}
