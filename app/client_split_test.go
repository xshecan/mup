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
	// member is the member that a frame of an ingress reflect path goes
	// through, or invalid for a frame on the path itself.
	member netip.Addr
}

// fakeControls records what the controller asks of the control sockets.
type fakeControls struct {
	mu            sync.Mutex
	registrations map[int]pathRegistration
	listened      []egressListen
	handle        func(egressProbe)
	measure       func(egressProbe)
	sent          []sentFrame
	stopped       bool
}

func (f *fakeControls) sendIngressMember(registration pathRegistration, member netip.Addr, packet []byte) error {
	frame, err := protocol.DecodeControlFrame(packet)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, sentFrame{registration: registration, frame: frame, member: member})
	return nil
}

func (f *fakeControls) listenMeasure(_ egressListen, handle func(egressProbe)) (func(), error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.measure = handle
	return func() {}, nil
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

func egressAck(slot uint16, sequence uint32, source netip.Addr, transport protocol.TransportID, port uint16, received time.Time) egressProbe {
	return egressProbe{
		frame: protocol.ControlFrame{
			Type: protocol.ControlRegisterACK, Transport: transport, Status: protocol.ControlStatusOK,
			PathID: slot, Sequence: sequence, ListenPort: 51820, ServerPort: 9000,
			InstanceNonce: 42, AdvertisedIP: netip.MustParseAddr("192.0.2.10"),
		},
		source:    source,
		transport: transport,
		port:      port,
		received:  received,
	}
}

// The ACK of the first egress path comes from its pool, and the ACK of the
// second one comes from its server.
func firstEgressAck(slot uint16, sequence uint32, received time.Time) egressProbe {
	return egressAck(slot, sequence, netip.MustParseAddr("203.0.113.4"), protocol.TransportICMP, 9200, received)
}

func secondEgressAck(slot uint16, sequence uint32, received time.Time) egressProbe {
	return egressAck(slot, sequence, netip.MustParseAddr("198.51.100.1"), protocol.TransportUDP, 9300, received)
}

func (f splitFixture) report(t *testing.T, slot int, sequence uint32, sentAt time.Time) {
	t.Helper()
	f.controller.mu.Lock()
	epoch := f.controller.slots[slot].epoch
	f.controller.mu.Unlock()
	probe := pathProbeResult{slot: slot, epoch: epoch, sequence: sequence, sentAt: sentAt, result: registerAcked}
	if err := f.controller.handleProbe(probe); err != nil {
		t.Fatalf("handleProbe: %v", err)
	}
}

func (f splitFixture) egressRTT(t *testing.T, slot int) time.Duration {
	t.Helper()
	paths, err := f.controller.Paths()
	if err != nil {
		t.Fatalf("Paths: %v", err)
	}
	for _, path := range paths {
		if path.Direction == directionEgress && path.ID == slot {
			return time.Duration(path.RTTSeconds * float64(time.Second))
		}
	}
	t.Fatalf("egress path %d is missing", slot)
	return 0
}

func TestAnEgressAckBeforeTheRoundReportGivesTheRTTAfterIt(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	sentAt := time.Now().Add(-time.Second)
	fixture.controls.handle(firstEgressAck(0, 5, sentAt.Add(30*time.Millisecond)))
	if rtt := fixture.egressRTT(t, 0); rtt != 0 {
		t.Fatalf("RTT before the report = %v, want none", rtt)
	}
	fixture.report(t, 0, 5, sentAt)
	if rtt := fixture.egressRTT(t, 0); rtt != 30*time.Millisecond {
		t.Fatalf("RTT after the report = %v, want 30ms", rtt)
	}
	if rtt := fixture.egressRTT(t, 1); rtt != 0 {
		t.Fatalf("RTT of the other egress path = %v, want none", rtt)
	}
}

func TestAnEgressAckAfterTheRoundReportGivesTheRTTAtOnce(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	sentAt := time.Now().Add(-time.Second)
	fixture.report(t, 0, 5, sentAt)
	fixture.controls.handle(secondEgressAck(0, 5, sentAt.Add(45*time.Millisecond)))
	if rtt := fixture.egressRTT(t, 1); rtt != 45*time.Millisecond {
		t.Fatalf("RTT = %v, want 45ms", rtt)
	}
	// An ACK of an older round does not change it.
	fixture.controls.handle(secondEgressAck(0, 4, sentAt.Add(10*time.Millisecond)))
	if rtt := fixture.egressRTT(t, 1); rtt != 45*time.Millisecond {
		t.Fatalf("RTT after an older ACK = %v, want 45ms", rtt)
	}
}

func TestTheEarlierEgressAckOfARoundCounts(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	sentAt := time.Now().Add(-time.Second)
	fixture.controls.handle(firstEgressAck(0, 5, sentAt.Add(20*time.Millisecond)))
	fixture.controls.handle(firstEgressAck(0, 5, sentAt.Add(50*time.Millisecond)))
	fixture.report(t, 0, 5, sentAt)
	if rtt := fixture.egressRTT(t, 0); rtt != 20*time.Millisecond {
		t.Fatalf("RTT with two ACKs before the report = %v, want 20ms", rtt)
	}
	fixture.controls.handle(firstEgressAck(0, 5, sentAt.Add(25*time.Millisecond)))
	if rtt := fixture.egressRTT(t, 0); rtt != 20*time.Millisecond {
		t.Fatalf("RTT with a later copy after the report = %v, want 20ms", rtt)
	}
}

func TestAnEgressAckThatDoesNotQualifyGivesNoRTT(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	sentAt := time.Now().Add(-time.Second)
	arrival := sentAt.Add(30 * time.Millisecond)
	notOK := firstEgressAck(0, 5, arrival)
	notOK.frame.Status = protocol.ControlStatusNoReflector
	otherGroup := firstEgressAck(2, 5, arrival)
	otherGroup.frame.ListenPort = 51821
	otherNonce := firstEgressAck(0, 5, arrival)
	otherNonce.frame.InstanceNonce = 43
	for name, ack := range map[string]egressProbe{
		"source outside the egress paths": egressAck(0, 5, netip.MustParseAddr("203.0.114.4"), protocol.TransportICMP, 9200, arrival),
		"other port":                      egressAck(0, 5, netip.MustParseAddr("203.0.113.4"), protocol.TransportICMP, 9201, arrival),
		"ingress path of another group":   otherGroup,
		"status that is not OK":           notOK,
		"other nonce":                     otherNonce,
		"unknown ingress path":            firstEgressAck(7, 5, arrival),
		"arrival before the send":         firstEgressAck(0, 5, sentAt.Add(-time.Millisecond)),
	} {
		fixture.controls.handle(ack)
		fixture.report(t, 0, 5, sentAt)
		fixture.report(t, 2, 5, sentAt)
		for slot := range 2 {
			if rtt := fixture.egressRTT(t, slot); rtt != 0 {
				t.Fatalf("%s: RTT of egress path %d = %v, want none", name, slot, rtt)
			}
		}
	}
}

func TestTheEgressRTTPairsWithTheBestHealthyIngressPath(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	now := time.Now()
	sentAt := now.Add(-time.Second)
	fixture.report(t, 0, 5, sentAt)
	fixture.report(t, 1, 8, sentAt)
	fixture.controls.handle(firstEgressAck(0, 5, sentAt.Add(20*time.Millisecond)))
	fixture.controls.handle(firstEgressAck(1, 8, sentAt.Add(40*time.Millisecond)))
	fixture.controls.handle(secondEgressAck(0, 5, sentAt.Add(30*time.Millisecond)))
	if rtt := fixture.egressRTT(t, 0); rtt != 20*time.Millisecond {
		t.Fatalf("RTT with the best ingress path 0 = %v, want 20ms", rtt)
	}
	// Without a healthy ingress path 0, ingress path 1 is the best one. The
	// second egress path has no sample for it, so its latest sample shows.
	fixture.miss(t, 0, missLimit)
	if rtt := fixture.egressRTT(t, 0); rtt != 40*time.Millisecond {
		t.Fatalf("RTT with the best ingress path 1 = %v, want 40ms", rtt)
	}
	if rtt := fixture.egressRTT(t, 1); rtt != 30*time.Millisecond {
		t.Fatalf("RTT without a sample for the best ingress path = %v, want the latest sample 30ms", rtt)
	}
}

func TestAStaleEgressRTTDoesNotShow(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	sentAt := time.Now().Add(-egressRTTMaxAge - time.Minute)
	fixture.report(t, 0, 5, sentAt)
	fixture.controls.handle(firstEgressAck(0, 5, sentAt.Add(20*time.Millisecond)))
	if rtt := fixture.egressRTT(t, 0); rtt != 0 {
		t.Fatalf("RTT of a stale sample = %v, want none", rtt)
	}
	fresh := time.Now().Add(-time.Second)
	fixture.report(t, 0, 6, fresh)
	fixture.controls.handle(firstEgressAck(0, 6, fresh.Add(25*time.Millisecond)))
	if rtt := fixture.egressRTT(t, 0); rtt != 25*time.Millisecond {
		t.Fatalf("RTT of a fresh sample = %v, want 25ms", rtt)
	}
}

func TestRemovingAPathClearsItsEgressRTT(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	sentAt := time.Now().Add(-time.Second)
	fixture.report(t, 0, 5, sentAt)
	fixture.report(t, 1, 5, sentAt)
	fixture.controls.handle(firstEgressAck(0, 5, sentAt.Add(20*time.Millisecond)))
	fixture.controls.handle(secondEgressAck(1, 5, sentAt.Add(40*time.Millisecond)))
	if err := fixture.controller.RemoveEgressPath(0); err != nil {
		t.Fatalf("RemoveEgressPath: %v", err)
	}
	added, err := fixture.controller.AddEgressPath("198.51.100.1:9200/icmp via 203.0.113.0/28", 51820)
	if err != nil || added.ID != 0 {
		t.Fatalf("AddEgressPath = %#v, %v, want egress path 0", added, err)
	}
	if rtt := fixture.egressRTT(t, 0); rtt != 0 {
		t.Fatalf("RTT of a replaced egress path = %v, want none", rtt)
	}
	// The ingress path 1 leaves, and the sample of the second egress path goes
	// with it.
	if err := fixture.controller.RemovePath(1); err != nil {
		t.Fatalf("RemovePath: %v", err)
	}
	if rtt := fixture.egressRTT(t, 1); rtt != 0 {
		t.Fatalf("RTT after the ingress path left = %v, want none", rtt)
	}
}
