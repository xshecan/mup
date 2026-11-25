package app

import (
	"context"
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/xshecan/mup/api"
	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/measure"
	"github.com/xshecan/mup/protocol"
)

func (f splitFixture) path(t *testing.T, direction string, id int) api.Path {
	t.Helper()
	paths, err := f.controller.Paths()
	if err != nil {
		t.Fatalf("Paths: %v", err)
	}
	for _, path := range paths {
		if path.ID == id && path.Direction == direction {
			return path
		}
	}
	t.Fatalf("%s path %d is missing", direction, id)
	return api.Path{}
}

func (f splitFixture) setIngressCount(slot int, packets uint64) {
	f.dataplane.mu.Lock()
	defer f.dataplane.mu.Unlock()
	f.dataplane.ingressCounts[slot] = dataplane.PathCounter{Packets: packets, Bytes: packets * 1000}
}

func (f splitFixture) setEgressCount(slot int, packets uint64) {
	f.dataplane.mu.Lock()
	defer f.dataplane.mu.Unlock()
	f.dataplane.egressCounts[slot] = dataplane.PathCounter{Packets: packets, Bytes: packets * 1000}
}

// measureReplyOf turns a MEASURE into its reply with the count of the server,
// as it arrives from source.
func measureReplyOf(frame protocol.ControlFrame, serverCount uint32, source netip.Addr, transport protocol.TransportID, port uint16, received time.Time) egressProbe {
	frame.Type = protocol.ControlMeasureReply
	frame.PeerCount = serverCount
	return egressProbe{frame: frame, source: source, transport: transport, port: port, received: received}
}

func measuresOf(sent []sentFrame) []sentFrame {
	var measures []sentFrame
	for _, frame := range sent {
		if frame.frame.Type == protocol.ControlMeasure {
			measures = append(measures, frame)
		}
	}
	return measures
}

func near(a, b float64) bool {
	return math.Abs(a-b) < 1e-6
}

func TestAMeasureRoundSendsOneFrameOnEachIngressPath(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	fixture.setIngressCount(0, 41)
	fixture.setIngressCount(1, 0xFFFFFFFF)
	fixture.controller.measureRound(time.Now())
	measures := measuresOf(fixture.controls.takeSent())
	if len(measures) != 3 {
		t.Fatalf("MEASURE frames = %#v, want one on each of the 3 ingress paths", measures)
	}
	want := map[uint16]struct {
		transport protocol.TransportID
		port      uint16
		listen    uint16
		code      uint32
	}{
		0: {protocol.TransportUDP, 9000, 51820, 42},
		1: {protocol.TransportICMP, 9100, 51820, 1},
		2: {protocol.TransportUDP, 5000, 51821, 1},
	}
	for _, sent := range measures {
		frame := sent.frame
		expected, ok := want[frame.PathID]
		if !ok || sent.member.IsValid() || frame.Flags != 0 || frame.Sequence != 1 || frame.Transport != expected.transport ||
			frame.ServerPort != expected.port || frame.ListenPort != expected.listen || frame.LeaseSeconds != expected.code ||
			frame.InstanceNonce != 42 || sent.registration.pathID != frame.PathID {
			t.Fatalf("MEASURE = %#v through %s, want %#v", frame, sent.member, expected)
		}
	}
	fixture.controller.measureRound(time.Now())
	for _, sent := range measuresOf(fixture.controls.takeSent()) {
		if sent.frame.Sequence != 2 {
			t.Fatalf("second round sequence = %d, want 2 on each path", sent.frame.Sequence)
		}
	}
}

func TestAMeasureWithoutAnAnswerChangesNothingButTheMeasurement(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	before, err := fixture.controller.Paths()
	if err != nil {
		t.Fatalf("Paths: %v", err)
	}
	start := time.Now().Add(-30 * time.Second)
	for round := 0; round <= 15; round++ {
		fixture.setIngressCount(0, uint64(round)*100)
		fixture.controller.measureRound(start.Add(time.Duration(round) * measureInterval))
	}
	after, err := fixture.controller.Paths()
	if err != nil {
		t.Fatalf("Paths: %v", err)
	}
	for index := range before {
		if before[index].Healthy != after[index].Healthy || before[index].Misses != after[index].Misses {
			t.Fatalf("path %d changed from %#v to %#v", index, before[index], after[index])
		}
	}
	// An older server never answers, so the loss stays unknown.
	path := fixture.path(t, directionIngress, 0)
	if path.LossPercent != nil || path.LossLongPercent != nil || path.ProbeLossPercent != nil || path.RTTAvgSeconds != 0 {
		t.Fatalf("measurement without answers = %#v, want empty", path.Measurement)
	}
	if path.RatePacketsPerSecond != 50 || path.RateBitsPerSecond != 50*1000*8 {
		t.Fatalf("rate = %v pps %v bps, want 50 pps", path.RatePacketsPerSecond, path.RateBitsPerSecond)
	}
}

func TestMeasureRepliesGiveTheLossAndTheRTTOfBothDirections(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	start := time.Now().Add(-40 * time.Second)
	egressSource := netip.MustParseAddr("198.51.100.1")
	for round := 0; round <= 20; round++ {
		sentAt := start.Add(time.Duration(round) * measureInterval)
		// The client sent 100 packets in each round, and the server received 90.
		fixture.setIngressCount(0, uint64(round)*100)
		fixture.controller.measureRound(sentAt)
		for _, sent := range measuresOf(fixture.controls.takeSent()) {
			if sent.frame.PathID != 0 {
				continue
			}
			serverCount := measure.EncodeCount(uint64(round) * 90)
			// The reply comes on the second egress path, and a later copy on
			// the same path does not count again.
			reply := measureReplyOf(sent.frame, serverCount, egressSource, protocol.TransportUDP, 9300, sentAt.Add(30*time.Millisecond))
			fixture.controls.handle(reply)
			reply.received = sentAt.Add(80 * time.Millisecond)
			fixture.controls.handle(reply)
		}
	}
	ingress := fixture.path(t, directionIngress, 0)
	if ingress.LossPercent == nil || !near(*ingress.LossPercent, 10) || ingress.LossLongPercent == nil || !near(*ingress.LossLongPercent, 10) {
		t.Fatalf("ingress loss = %#v, want 10%% in both windows", ingress.Measurement)
	}
	if ingress.ProbeLossPercent == nil || *ingress.ProbeLossPercent != 0 || !near(ingress.RTTAvgSeconds, 0.03) || ingress.RTTJitterSeconds != 0 {
		t.Fatalf("ingress probes = %#v, want no probe loss and 30ms", ingress.Measurement)
	}
	egress := fixture.path(t, directionEgress, 1)
	if !near(egress.RTTAvgSeconds, 0.03) || !near(egress.RTTSeconds, 0.03) {
		t.Fatalf("egress RTT = %v avg %v, want 30ms from the MEASURE replies", egress.RTTSeconds, egress.RTTAvgSeconds)
	}
	if other := fixture.path(t, directionEgress, 0); other.RTTAvgSeconds != 0 {
		t.Fatalf("RTT of the egress path without replies = %v, want none", other.RTTAvgSeconds)
	}
	if other := fixture.path(t, directionIngress, 1); other.ProbeLossPercent != nil || other.LossPercent != nil {
		t.Fatalf("path without answers = %#v, want empty", other.Measurement)
	}
}

func TestAMeasureReplyOnThePathSocketGivesTheIngressRTT(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	sentAt := time.Now().Add(-time.Second)
	fixture.controller.measureRound(sentAt)
	for _, sent := range measuresOf(fixture.controls.takeSent()) {
		if sent.frame.PathID != 2 {
			continue
		}
		// The group of listen port 51821 has no egress paths, so the reply
		// comes on the socket of the path.
		fixture.controls.measure(measureReplyOf(sent.frame, 0, netip.MustParseAddr("198.51.100.3"), protocol.TransportUDP, 5000, sentAt.Add(20*time.Millisecond)))
	}
	fixture.controller.mu.Lock()
	rtt, ok := fixture.controller.ingressMeasures[2].probes.RTTLast()
	fixture.controller.mu.Unlock()
	if !ok || rtt != 20*time.Millisecond {
		t.Fatalf("ingress RTT = %v, %v, want 20ms", rtt, ok)
	}
	// A server that sends no count gives no loss.
	if path := fixture.path(t, "", 2); path.LossPercent != nil {
		t.Fatalf("loss without a server count = %v, want unknown", *path.LossPercent)
	}
}

func TestAMeasureReplyOfAnotherClientIsIgnored(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	sentAt := time.Now().Add(-time.Second)
	fixture.controller.measureRound(sentAt)
	sent := measuresOf(fixture.controls.takeSent())[0]
	for _, alter := range []func(*protocol.ControlFrame){
		func(f *protocol.ControlFrame) { f.InstanceNonce = 43 },
		func(f *protocol.ControlFrame) { f.ListenPort = 51899 },
		func(f *protocol.ControlFrame) { f.PathID = 7 },
	} {
		frame := sent.frame
		alter(&frame)
		fixture.controls.handle(measureReplyOf(frame, 5, netip.MustParseAddr("198.51.100.1"), protocol.TransportUDP, 9300, sentAt.Add(time.Millisecond)))
	}
	fixture.controller.mu.Lock()
	defer fixture.controller.mu.Unlock()
	for slot, m := range fixture.controller.ingressMeasures {
		if m == nil {
			continue
		}
		if _, ok := m.probes.RTTLast(); ok {
			t.Fatalf("path %d took a reply of another client", slot)
		}
	}
}

func newReflectFixture(t *testing.T) splitFixture {
	t.Helper()
	group := testGroup(t, 51820, config.ModeFailover, "198.51.100.1:9000/icmp via 203.0.113.0/30")
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
	fixture := splitFixture{controls: controls}
	fixture.controller = controller
	fixture.dataplane = fake
	fixture.registrations = controls.registrations
	return fixture
}

func TestAMeasureOfAReflectPathGoesThroughEachMember(t *testing.T) {
	t.Parallel()

	fixture := newReflectFixture(t)
	answered := netip.MustParseAddr("203.0.113.1")
	if err := fixture.registrations[0].writeMembers([]netip.Addr{answered}); err != nil {
		t.Fatalf("writeMembers: %v", err)
	}
	start := time.Now().Add(-20 * time.Second)
	for round := 0; round <= 10; round++ {
		sentAt := start.Add(time.Duration(round) * measureInterval)
		fixture.setIngressCount(0, uint64(round)*100)
		fixture.controller.measureRound(sentAt)
		measures := measuresOf(fixture.controls.takeSent())
		if len(measures) != 4 {
			t.Fatalf("MEASURE frames = %#v, want one through each of the 4 candidates", measures)
		}
		for index, sent := range measures {
			frame := sent.frame
			if sent.member != netip.AddrFrom4([4]byte{203, 0, 113, byte(index)}) || frame.ReturnIP != sent.member ||
				frame.Flags != protocol.ControlFlagIngressReflect|protocol.ControlFlagReturnIP ||
				frame.Transport != protocol.TransportICMP || frame.Sequence != uint32(round+1) {
				t.Fatalf("MEASURE %d = %#v through %s", index, frame, sent.member)
			}
			// Only the member 203.0.113.1 answers, on the egress path.
			if sent.member == answered {
				reply := measureReplyOf(frame, measure.EncodeCount(uint64(round)*100), netip.MustParseAddr("198.51.100.1"), protocol.TransportUDP, 9300, sentAt.Add(40*time.Millisecond))
				fixture.controls.handle(reply)
			}
		}
	}
	path := fixture.path(t, directionIngress, 0)
	if path.ProbeLossPercent == nil || *path.ProbeLossPercent != 0 || path.LossPercent == nil || *path.LossPercent != 0 || !near(path.RTTAvgSeconds, 0.04) {
		t.Fatalf("reflect path = %#v, want the measurement of its answering member", path.Measurement)
	}
	if egress := fixture.path(t, directionEgress, 0); !near(egress.RTTAvgSeconds, 0.04) {
		t.Fatalf("egress RTT = %v, want 40ms", egress.RTTAvgSeconds)
	}

	list, err := fixture.controller.Members()
	if err != nil || len(list.Members) != 4 {
		t.Fatalf("Members = %#v, %v, want the 4 candidates", list, err)
	}
	for _, member := range list.Members {
		if member.Direction != directionIngress || member.PathID != 0 || member.ListenPort != 51820 {
			t.Fatalf("member = %#v", member)
		}
		if member.Address == answered.String() {
			if !member.Healthy || member.ProbeLossPercent == nil || *member.ProbeLossPercent != 0 || !near(member.RTTAvgSeconds, 0.04) {
				t.Fatalf("answering member = %#v", member)
			}
			continue
		}
		// The other members never answered, so their probe loss is unknown.
		if member.Healthy || member.ProbeLossPercent != nil || member.RTTAvgSeconds != 0 {
			t.Fatalf("silent member = %#v", member)
		}
	}
}

func TestAClientWithoutReflectPathsListsNoMembers(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	list, err := fixture.controller.Members()
	if err != nil || list.Members == nil || len(list.Members) != 0 {
		t.Fatalf("Members = %#v, %v, want an empty list", list, err)
	}
}

func TestTheProbeOfAnEgressPathCarriesTheCountsOfBothEnds(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	start := time.Now().Add(-40 * time.Second)
	for round := 0; round <= 20; round++ {
		// The server sent 200 packets in each round, and the client got 150.
		fixture.setEgressCount(1, uint64(round)*150)
		probe := egressProbe{
			frame: protocol.ControlFrame{
				Type: protocol.ControlProbe, Transport: protocol.TransportUDP, Flags: protocol.ControlFlagEgressPath,
				PathID: 1, Sequence: uint32(round + 1), ListenPort: 51820, ServerPort: 9300,
				LeaseSeconds: measure.EncodeCount(uint64(round) * 200), InstanceNonce: 42, AdvertisedIP: netip.MustParseAddr("192.0.2.10"),
			},
			source:    netip.MustParseAddr("198.51.100.1"),
			transport: protocol.TransportUDP,
			port:      9300,
			received:  start.Add(time.Duration(round) * measureInterval),
		}
		fixture.controls.handle(probe)
		sent := fixture.controls.takeSent()
		if len(sent) != 1 || sent[0].frame.Type != protocol.ControlProbeReply || sent[0].frame.LeaseSeconds != measure.EncodeCount(uint64(round)*150) {
			t.Fatalf("probe replies = %#v, want one with the count of the client", sent)
		}
	}
	egress := fixture.path(t, directionEgress, 1)
	if egress.LossPercent == nil || !near(*egress.LossPercent, 25) || egress.LossLongPercent == nil || !near(*egress.LossLongPercent, 25) {
		t.Fatalf("egress loss = %#v, want 25%%", egress.Measurement)
	}
}

func TestTheProbeOfAnOlderServerGivesNoEgressLoss(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	start := time.Now().Add(-20 * time.Second)
	for round := 0; round <= 10; round++ {
		fixture.setEgressCount(1, uint64(round)*150)
		fixture.controls.handle(egressProbe{
			frame: protocol.ControlFrame{
				Type: protocol.ControlProbe, Transport: protocol.TransportUDP, Flags: protocol.ControlFlagEgressPath,
				PathID: 1, Sequence: uint32(round + 1), ListenPort: 51820, ServerPort: 9300,
				InstanceNonce: 42, AdvertisedIP: netip.MustParseAddr("192.0.2.10"),
			},
			source:    netip.MustParseAddr("198.51.100.1"),
			transport: protocol.TransportUDP,
			port:      9300,
			received:  start.Add(time.Duration(round) * measureInterval),
		})
	}
	fixture.controls.takeSent()
	if egress := fixture.path(t, directionEgress, 1); egress.LossPercent != nil || egress.LossLongPercent != nil {
		t.Fatalf("egress loss with an older server = %#v, want unknown", egress.Measurement)
	}
}

func TestAPathThatLeavesStartsItsMeasurementAgain(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	fixture.controller.measureRound(time.Now())
	fixture.controls.takeSent()
	if err := fixture.controller.RemovePath(0); err != nil {
		t.Fatalf("RemovePath: %v", err)
	}
	if err := fixture.controller.RemoveEgressPath(1); err != nil {
		t.Fatalf("RemoveEgressPath: %v", err)
	}
	fixture.controller.mu.Lock()
	defer fixture.controller.mu.Unlock()
	if fixture.controller.ingressMeasures[0] != nil || fixture.controller.egressMeasures[1] != nil {
		t.Fatal("a removed path keeps its measurement")
	}
}
