package app

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/control"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/measure"
	"github.com/xshecan/mup/protocol"
)

var (
	measureClient = netip.MustParseAddr("192.0.2.10")
	measureLocal  = netip.MustParseAddr("198.51.100.1")
	measureKey    = dataplane.ClientKey{AdvertisedIP: measureClient, InstanceNonce: 7}
)

func measureRegister(pathID uint16, transport protocol.TransportID) control.RegistrationRequest {
	return control.RegistrationRequest{
		Frame: protocol.ControlFrame{
			Type: protocol.ControlRegister, Transport: transport, PathID: pathID, Sequence: 1,
			ListenPort: 51820, ServerPort: 9000, LeaseSeconds: registrationLeaseSeconds,
			InstanceNonce: 7, AdvertisedIP: measureClient,
		},
		Path: control.PathKey{Local: measureLocal, Source: measureClient, Transport: transport, ServerPort: 9000},
	}
}

func measureOf(request control.RegistrationRequest, code uint32) protocol.ControlFrame {
	frame := request.Frame
	frame.Type = protocol.ControlMeasure
	frame.Sequence = 3
	frame.LeaseSeconds = code
	return frame
}

func TestTheServerAnswersAMeasureOnlyOnARegisteredPath(t *testing.T) {
	t.Parallel()

	now := time.Unix(1000, 0)
	registry := control.NewRegistry(9000, 9000, registrationLeaseSeconds*time.Second)
	counters := &fakeServerCounters{}
	request := measureRegister(2, protocol.TransportUDP)
	frame := measureOf(request, 101)
	if _, err := acceptMeasure(frame, protocol.TransportUDP, 9000, measureClient, measureLocal, registry, counters, now); !errors.Is(err, control.ErrMeasureUnknown) {
		t.Fatalf("acceptMeasure before REGISTER error = %v, want %v", err, control.ErrMeasureUnknown)
	}
	if len(registry.PathIDs(now)) != 0 || len(counters.counterLog) != 0 {
		t.Fatalf("a MEASURE created state: paths %v, counters %v", registry.PathIDs(now), counters.counterLog)
	}

	if _, err := registry.Register(now, request); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Without a counter the reply carries no count.
	packet, err := acceptMeasure(frame, protocol.TransportUDP, 9000, measureClient, measureLocal, registry, counters, now)
	if err != nil {
		t.Fatalf("acceptMeasure: %v", err)
	}
	reply, err := protocol.DecodeControlFrame(packet)
	if err != nil || reply.Type != protocol.ControlMeasureReply || reply.PeerCount != 0 {
		t.Fatalf("reply = %#v, %v, want a MEASURE_REPLY without a count", reply, err)
	}

	counters.ingress(t, 2, 5000)
	packet, err = acceptMeasure(frame, protocol.TransportUDP, 9000, measureClient, measureLocal, registry, counters, now)
	if err != nil {
		t.Fatalf("acceptMeasure: %v", err)
	}
	reply, err = protocol.DecodeControlFrame(packet)
	want := frame
	want.Type, want.PeerCount = protocol.ControlMeasureReply, measure.EncodeCount(5000)
	if err != nil || reply != want {
		t.Fatalf("reply = %#v, %v, want %#v", reply, err, want)
	}

	// The checks of a REGISTER apply, and a MEASURE refreshes no lease.
	spoofed := netip.MustParseAddr("192.0.2.99")
	if _, err := acceptMeasure(frame, protocol.TransportUDP, 9000, spoofed, measureLocal, registry, counters, now); !errors.Is(err, control.ErrRegistrationSource) {
		t.Fatalf("acceptMeasure from another source error = %v", err)
	}
	if _, err := acceptMeasure(frame, protocol.TransportICMP, 9000, measureClient, measureLocal, registry, counters, now); !errors.Is(err, control.ErrRegistrationTransport) {
		t.Fatalf("acceptMeasure on another transport error = %v", err)
	}
	later := now.Add(registrationLeaseSeconds * time.Second)
	if _, err := acceptMeasure(frame, protocol.TransportUDP, 9000, measureClient, measureLocal, registry, counters, later.Add(-time.Second)); err != nil {
		t.Fatalf("acceptMeasure before the lease ends: %v", err)
	}
	if _, err := acceptMeasure(frame, protocol.TransportUDP, 9000, measureClient, measureLocal, registry, counters, later); !errors.Is(err, control.ErrMeasureUnknown) {
		t.Fatalf("acceptMeasure after the lease error = %v, want %v", err, control.ErrMeasureUnknown)
	}
}

func TestTheServerAnswersAMeasureThroughAReflectMember(t *testing.T) {
	t.Parallel()

	now := time.Unix(1000, 0)
	registry := control.NewRegistry(9000, 9000, registrationLeaseSeconds*time.Second)
	counters := &fakeServerCounters{}
	member := netip.MustParseAddr("203.0.113.2")
	request := measureRegister(4, protocol.TransportICMP)
	request.Frame.Flags = protocol.ControlFlagIngressReflect | protocol.ControlFlagReturnIP
	request.Frame.ReturnIP = member
	request.Path.Source = member
	if _, err := registry.Register(now, request); err != nil {
		t.Fatalf("Register: %v", err)
	}
	counters.ingress(t, 4, 77)
	packet, err := acceptMeasure(measureOf(request, 80), protocol.TransportICMP, 9000, member, measureLocal, registry, counters, now)
	if err != nil {
		t.Fatalf("acceptMeasure: %v", err)
	}
	reply, err := protocol.DecodeControlFrame(packet)
	if err != nil || reply.ReturnIP != member || reply.Flags&protocol.ControlFlagIngressReflect == 0 || reply.PeerCount != measure.EncodeCount(77) {
		t.Fatalf("reply = %#v, %v, want the member and the count", reply, err)
	}
	// Another member of the pool did not register.
	if _, err := acceptMeasure(measureOf(request, 80), protocol.TransportICMP, 9000, netip.MustParseAddr("203.0.113.3"), measureLocal, registry, counters, now); !errors.Is(err, control.ErrMeasureUnknown) {
		t.Fatalf("acceptMeasure through another member error = %v", err)
	}
}

// ingress makes an ingress counter of the measure client with packets.
func (f *fakeServerCounters) ingress(t *testing.T, pathID uint16, packets uint64) {
	t.Helper()
	if err := f.EnsureServerPathCounter(measureKey, pathID, dataplane.PathCounterIngress); err != nil {
		t.Fatalf("EnsureServerPathCounter: %v", err)
	}
	f.setCounter(measureKey, pathID, dataplane.PathCounterIngress, packets)
}

func TestIngressCountersFollowTheLivePaths(t *testing.T) {
	t.Parallel()

	now := time.Unix(1000, 0)
	registry := control.NewRegistry(9000, 9000, registrationLeaseSeconds*time.Second)
	store := &fakeServerCounters{}
	counters := newIngressCounters(store)
	first := measureRegister(0, protocol.TransportUDP)
	second := measureRegister(0, protocol.TransportICMP)
	for _, request := range []control.RegistrationRequest{first, second} {
		if _, err := registry.Register(now, request); err != nil {
			t.Fatalf("Register: %v", err)
		}
		counters.ensure(measureKey, request.Frame.PathID)
	}
	third := measureRegister(3, protocol.TransportUDP)
	third.Path.Local = netip.MustParseAddr("198.51.100.2")
	if _, err := registry.Register(now.Add(10*time.Second), third); err != nil {
		t.Fatalf("Register: %v", err)
	}
	counters.ensure(measureKey, 3)
	if !slices.Equal(store.counterLog, []string{"ensure", "ensure"}) {
		t.Fatalf("counters = %v, want one for each path ID", store.counterLog)
	}
	store.setCounter(measureKey, 0, dataplane.PathCounterIngress, 9)
	counters.ensure(measureKey, 0)
	if counter, _, _ := store.ServerPathCounter(measureKey, 0, dataplane.PathCounterIngress); counter.Packets != 9 {
		t.Fatalf("a refresh reset the counter to %d", counter.Packets)
	}

	counters.prune(registry, now.Add(20*time.Second))
	if !store.hasCounter(measureKey, 0, dataplane.PathCounterIngress) || !store.hasCounter(measureKey, 3, dataplane.PathCounterIngress) {
		t.Fatal("prune deleted the counter of a live path")
	}
	// Both paths of ID 0 end with the first lease, and path 3 lives on.
	counters.prune(registry, now.Add(30*time.Second))
	if store.hasCounter(measureKey, 0, dataplane.PathCounterIngress) || !store.hasCounter(measureKey, 3, dataplane.PathCounterIngress) {
		t.Fatalf("counters after the first lease = %v", store.counterLog)
	}
	counters.prune(registry, now.Add(40*time.Second))
	if store.hasCounter(measureKey, 3, dataplane.PathCounterIngress) {
		t.Fatal("prune kept the counter of an expired path")
	}
}

func TestEgressCountersFollowTheEgressPaths(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	registry := newTestEgressRegistry(plane)
	now := time.Unix(1000, 0)
	if err := registry.register(egressFrame(2, 9300, protocol.TransportUDP, config.ModeFailover), now); err != nil {
		t.Fatalf("register: %v", err)
	}
	if !plane.hasCounter(egressKeyOf, 2, dataplane.PathCounterEgress) {
		t.Fatal("a new egress path has no counter")
	}
	plane.setCounter(egressKeyOf, 2, dataplane.PathCounterEgress, 40)
	if err := registry.register(egressFrame(2, 9300, protocol.TransportUDP, config.ModeFailover), now.Add(10*time.Second)); err != nil {
		t.Fatalf("register again: %v", err)
	}
	if counter, _, _ := plane.ServerPathCounter(egressKeyOf, 2, dataplane.PathCounterEgress); counter.Packets != 40 {
		t.Fatalf("a refresh reset the counter to %d", counter.Packets)
	}
	registry.sync(now.Add(10*time.Second + registry.lease + time.Second))
	if plane.hasCounter(egressKeyOf, 2, dataplane.PathCounterEgress) {
		t.Fatal("an expired egress path keeps its counter")
	}
	// A client that restarts loses its egress paths and their counters.
	if err := registry.register(egressFrame(1, 9300, protocol.TransportUDP, config.ModeFailover), now); err != nil {
		t.Fatalf("register: %v", err)
	}
	registry.revoke(egressKeyOf, now)
	if plane.hasCounter(egressKeyOf, 1, dataplane.PathCounterEgress) {
		t.Fatal("a revoked egress path keeps its counter")
	}
}

func TestTheServerMeasuresAnEgressPoolPath(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	plane.members[dataplane.PoolKey{Base: egressPool, Transport: protocol.TransportICMP}] = egressMembers
	registry := newTestEgressRegistry(plane)
	start := time.Now().Add(-40 * time.Second)
	if err := registry.register(poolFrame(0, 9200), start); err != nil {
		t.Fatalf("register: %v", err)
	}
	sender := &recordingEgressSender{}
	service := &egressService{registry: registry, sender: sender, logger: discardLogger}
	for round := 0; round <= 20; round++ {
		now := start.Add(time.Duration(round) * egressProbeInterval)
		// Keep the path alive, as the REGISTER rounds of the client do.
		if err := registry.register(poolFrame(0, 9200), now); err != nil {
			t.Fatalf("register: %v", err)
		}
		// The server sent 100 packets in each round, and the client got 80.
		plane.setCounter(egressKeyOf, 0, dataplane.PathCounterEgress, uint64(round)*100)
		sender.frames = nil
		service.probe(now)
		if len(sender.frames) != len(egressMembers) {
			t.Fatalf("probes = %#v, want one for each member", sender.frames)
		}
		for index, probe := range sender.frames {
			if probe.LeaseSeconds != measure.EncodeCount(uint64(round)*100) {
				t.Fatalf("probe count = %d, want the count before the round", probe.LeaseSeconds)
			}
			member := sender.sent[len(sender.sent)-len(egressMembers)+index].member
			// The third member never answers, and an older reply of the
			// second member comes twice.
			if member == egressMembers[2] {
				continue
			}
			reply := probeReply(0, protocol.TransportICMP, member)
			reply.Sequence = probe.Sequence
			reply.LeaseSeconds = measure.EncodeCount(uint64(round)*80 + uint64(index))
			delay := time.Duration(10*(index+1)) * time.Millisecond
			registry.confirm(reply, now.Add(delay))
			if member == egressMembers[1] {
				registry.confirm(reply, now.Add(delay+time.Second))
			}
		}
	}
	// The last probe of the silent member is lost once its timeout passed.
	now := start.Add(20*egressProbeInterval + measure.ProbeTimeout + time.Second)
	groups := registry.clients(now)[egressKeyOf]
	if len(groups) != 1 || len(groups[0].Paths) != 1 {
		t.Fatalf("clients = %#v", groups)
	}
	path := groups[0].Paths[0]
	if path.LossPercent == nil || !near(*path.LossPercent, 20) || path.LossLongPercent == nil || !near(*path.LossLongPercent, 20) {
		t.Fatalf("egress loss = %#v, want 20%%", path.Measurement)
	}
	if path.ProbeLossPercent == nil || !near(*path.ProbeLossPercent, 100.0/3) || !near(path.RTTAvgSeconds, 0.015) {
		t.Fatalf("egress probes = %#v, want a third lost and 15ms", path.Measurement)
	}
	if path.RatePacketsPerSecond != 50 {
		t.Fatalf("egress rate = %v pps, want 50", path.RatePacketsPerSecond)
	}

	members := registry.members(now)
	if len(members) != len(egressMembers) {
		t.Fatalf("members = %#v, want one for each pool member", members)
	}
	for index, member := range members {
		if member.Client != egressClient.String() || member.Direction != directionEgress || member.PathID != 0 ||
			member.ListenPort != 51820 || member.Address != egressMembers[index].String() {
			t.Fatalf("member %d = %#v", index, member)
		}
		if index == 2 {
			if member.Healthy || member.ProbeLossPercent != nil {
				t.Fatalf("silent member = %#v, want unhealthy without a probe loss", member)
			}
			continue
		}
		wantRTT := float64(10*(index+1)) / 1000
		if !member.Healthy || member.ProbeLossPercent == nil || *member.ProbeLossPercent != 0 || !near(member.RTTAvgSeconds, wantRTT) {
			t.Fatalf("member %d = %#v, want no loss and %vs", index, member, wantRTT)
		}
	}
}

func TestAnOlderClientGivesNoEgressLoss(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	registry := newTestEgressRegistry(plane)
	start := time.Now().Add(-40 * time.Second)
	sender := &recordingEgressSender{}
	service := &egressService{registry: registry, sender: sender, logger: discardLogger}
	for round := 0; round <= 20; round++ {
		now := start.Add(time.Duration(round) * egressProbeInterval)
		if err := registry.register(egressFrame(1, 9300, protocol.TransportUDP, config.ModeFailover), now); err != nil {
			t.Fatalf("register: %v", err)
		}
		plane.setCounter(egressKeyOf, 1, dataplane.PathCounterEgress, uint64(round)*100)
		sender.frames = nil
		service.probe(now)
		for _, probe := range sender.frames {
			// An older client answers without a count.
			reply := probeReply(1, protocol.TransportUDP, egressServer)
			reply.Sequence = probe.Sequence
			registry.confirm(reply, now.Add(5*time.Millisecond))
		}
	}
	path := registry.clients(start.Add(40*time.Second + time.Second))[egressKeyOf][0].Paths[0]
	if path.LossPercent != nil || path.LossLongPercent != nil {
		t.Fatalf("egress loss with an older client = %#v, want unknown", path.Measurement)
	}
	if path.ProbeLossPercent == nil || *path.ProbeLossPercent != 0 || !near(path.RTTAvgSeconds, 0.005) {
		t.Fatalf("egress probes = %#v, want no loss and 5ms", path.Measurement)
	}
}

func TestTheServerInspectorListsTheEgressMembers(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	registry := newTestEgressRegistry(plane)
	if err := registry.register(egressFrame(1, 9300, protocol.TransportUDP, config.ModeFailover), time.Now()); err != nil {
		t.Fatalf("register: %v", err)
	}
	inspector := newServerInspector(config.Server{}, fakeServerDataplane{}, time.Unix(0, 0), &egressService{registry: registry})
	list, err := inspector.Members()
	if err != nil || len(list.Members) != 1 || list.Members[0].Address != egressServer.String() || !list.Members[0].Healthy {
		t.Fatalf("Members = %#v, %v, want the server address of the direct path", list, err)
	}
	empty, err := newServerInspector(config.Server{}, fakeServerDataplane{}, time.Unix(0, 0), nil).Members()
	if err != nil || empty.Members == nil || len(empty.Members) != 0 {
		t.Fatalf("Members without egress paths = %#v, %v", empty, err)
	}
}
