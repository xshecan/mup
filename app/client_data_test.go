package app

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/measure"
	"github.com/xshecan/mup/protocol"
)

// dataFixture drives the MEASURE rounds of a client whose groups have no
// egress paths, so each reply comes on the socket of its path. It keeps the
// totals of the packets that the client sent and that the server received on
// each path.
type dataFixture struct {
	splitFixture
	start  time.Time
	round  int
	sent   [config.MaxPaths]uint64
	served [config.MaxPaths]uint64
	// loss is the share of the data that each path loses, and rtt the round
	// trip time of its MEASURE. A path in silent gets no answer.
	loss   map[int]float64
	rtt    map[int]time.Duration
	silent map[int]bool
}

func newDataFixture(t *testing.T, groups ...config.Group) *dataFixture {
	t.Helper()
	client := config.Client{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), Groups: groups}
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
	fixture := &dataFixture{
		start:  time.Now().Add(-20 * time.Minute),
		loss:   map[int]float64{},
		rtt:    map[int]time.Duration{},
		silent: map[int]bool{},
	}
	fixture.controls = controls
	fixture.controller = controller
	fixture.dataplane = fake
	fixture.registrations = controls.registrations
	return fixture
}

func lossGroup(t *testing.T, mode config.Mode, limit config.LossLimit, prefer config.Prefer) config.Group {
	t.Helper()
	group := testGroup(t, 51820, mode, "198.51.100.1:9000/udp", "198.51.100.2:9100/udp")
	group.MaxLoss, group.Prefer = limit, prefer
	return group
}

// now is the time of the latest round.
func (f *dataFixture) now() time.Time {
	return f.start.Add(time.Duration(f.round) * measureInterval)
}

// run runs rounds MEASURE rounds and answers each MEASURE of a path that is
// not silent with its loss and its round trip time.
func (f *dataFixture) run(t *testing.T, rounds int) {
	t.Helper()
	for range rounds {
		f.round++
		sentAt := f.now()
		for slot := range f.sent {
			f.sent[slot] += 100
			f.served[slot] += uint64(100 * (1 - f.loss[slot]))
			f.setIngressCount(slot, f.sent[slot])
		}
		f.controller.measureRound(sentAt)
		for _, sent := range measuresOf(f.controls.takeSent()) {
			slot := int(sent.frame.PathID)
			if f.silent[slot] {
				continue
			}
			rtt := f.rtt[slot]
			if rtt == 0 {
				rtt = 20 * time.Millisecond
			}
			reply := measureReplyOf(sent.frame, measure.EncodeCount(f.served[slot]), sent.registration.path.Server, protocol.TransportUDP, sent.registration.path.ServerPort, sentAt.Add(rtt))
			f.controls.measure(reply)
		}
	}
}

func (f *dataFixture) state() (uint8, uint32) {
	f.dataplane.mu.Lock()
	defer f.dataplane.mu.Unlock()
	return f.dataplane.mask, f.dataplane.generation
}

// first is the path that the failover mode tries first: the path of the mask
// with the lowest priority in the dataplane, or -1 for an empty mask. A path
// that was never written has the priority of the plan.
func (f *dataFixture) first() int {
	f.dataplane.mu.Lock()
	defer f.dataplane.mu.Unlock()
	selected, priority := -1, 0
	for slot := range config.MaxPaths {
		if f.dataplane.mask&(1<<slot) == 0 {
			continue
		}
		settings, ok := f.dataplane.paths[slot]
		if !ok {
			settings = f.controller.initial[slot]
		}
		if selected < 0 || int(settings.Priority) < priority {
			selected, priority = slot, int(settings.Priority)
		}
	}
	return selected
}

// runUntilFirst runs rounds until the failover mode tries path want first,
// and fails after limit rounds.
func (f *dataFixture) runUntilFirst(t *testing.T, want, limit int) {
	t.Helper()
	for range limit {
		if f.first() == want {
			return
		}
		f.run(t, 1)
	}
	t.Fatalf("first path = %d after %d rounds, want %d", f.first(), limit, want)
}

// runUntil runs rounds until the mask is want, and fails after limit rounds.
func (f *dataFixture) runUntil(t *testing.T, want uint8, limit int) {
	t.Helper()
	for range limit {
		if mask, _ := f.state(); mask == want {
			return
		}
		f.run(t, 1)
	}
	mask, _ := f.state()
	t.Fatalf("mask = %#b after %d rounds, want %#b", mask, limit, want)
}

func TestAClientMovesItsDataOffALossyIngressPathAndBackAfterTheHold(t *testing.T) {
	t.Parallel()

	fixture := newDataFixture(t, lossGroup(t, config.ModeFailover, 50, config.PreferOrder))
	fixture.loss[0] = 0.2
	fixture.runUntil(t, 0b10, 10)
	degradedAt := fixture.now()
	_, generation := fixture.state()
	path := fixture.path(t, "", 0)
	if !path.Healthy || !path.Degraded || path.Reason != "loss 20% above 5%" || path.InUse {
		t.Fatalf("lossy path = %#v, want healthy, degraded and not in use", path)
	}
	if other := fixture.path(t, "", 1); !other.InUse || other.Degraded {
		t.Fatalf("other path = %#v, want in use", other)
	}

	// The loss ends, but the path waits for its hold.
	fixture.loss[0] = 0
	for fixture.now().Sub(degradedAt) < measure.LossHoldFirst-measureInterval {
		fixture.run(t, 1)
		if mask, current := fixture.state(); mask != 0b10 || current != generation {
			t.Fatalf("mask = %#b generation %d at %v after the degradation, want %#b and %d", mask, current, fixture.now().Sub(degradedAt), 0b10, generation)
		}
	}
	fixture.runUntil(t, 0b11, 3)
	if _, current := fixture.state(); current != generation+1 {
		t.Fatalf("generation = %d after the recovery, want %d", current, generation+1)
	}
	if path := fixture.path(t, "", 0); path.Degraded || path.Reason != "" || !path.InUse {
		t.Fatalf("recovered path = %#v, want in use", path)
	}
}

func TestAllLossyPathsKeepCarryingTheData(t *testing.T) {
	t.Parallel()

	fixture := newDataFixture(t, lossGroup(t, config.ModeBalancer, 50, config.PreferOrder))
	fixture.loss[0], fixture.loss[1] = 0.2, 0.3
	fixture.run(t, 10)
	if mask, _ := fixture.state(); mask != 0b11 {
		t.Fatalf("mask = %#b, want both paths", mask)
	}
	for slot := range 2 {
		if path := fixture.path(t, "", slot); !path.Degraded || !path.InUse {
			t.Fatalf("path %d = %#v, want degraded and still in use", slot, path)
		}
	}
}

func TestTheGenerationBumpsOnlyWhenTheMaskChanges(t *testing.T) {
	t.Parallel()

	fixture := newDataFixture(t, lossGroup(t, config.ModeFailover, 50, config.PreferOrder))
	fixture.run(t, 5)
	mask, generation := fixture.state()
	fixture.run(t, 5)
	if current, again := fixture.state(); current != mask || again != generation {
		t.Fatalf("state = %#b %d without a change, want %#b %d", current, again, mask, generation)
	}
	fixture.loss[1] = 0.5
	fixture.runUntil(t, 0b01, 10)
	if _, current := fixture.state(); current != generation+1 {
		t.Fatalf("generation = %d, want %d", current, generation+1)
	}
	// A health change that leaves the mask as it is keeps the generation.
	fixture.miss(t, 1, missLimit)
	if current, again := fixture.state(); current != 0b01 || again != generation+1 {
		t.Fatalf("state after path 1 failed = %#b %d, want %#b %d", current, again, 0b01, generation+1)
	}
	if path := fixture.path(t, "", 1); path.Healthy || path.Degraded {
		t.Fatalf("failed path = %#v, want unhealthy and not degraded", path)
	}
}

func TestPreferLatencyPicksTheFasterIngressPathAndKeepsIt(t *testing.T) {
	t.Parallel()

	fixture := newDataFixture(t, lossGroup(t, config.ModeFailover, 0, config.PreferLatency))
	fixture.rtt[0], fixture.rtt[1] = 50*time.Millisecond, 20*time.Millisecond
	// The data set keeps both paths, so a full path can spill, and the
	// choice is the path that the failover mode tries first. The order picks
	// path 0 until the RTTs are known, and the faster path takes over after
	// it stayed better for the switch time.
	if mask, _ := fixture.state(); mask != 0b11 || fixture.first() != 0 {
		t.Fatalf("first mask = %#b with path %d first, want both with path 0 first", mask, fixture.first())
	}
	fixture.run(t, 5)
	if first := fixture.first(); first != 0 {
		t.Fatalf("path %d is first right after the RTTs are known, want path 0", first)
	}
	fixture.runUntilFirst(t, 1, 7)
	if mask, _ := fixture.state(); mask != 0b11 {
		t.Fatalf("mask = %#b, want both paths", mask)
	}
	if path := fixture.path(t, "", 1); !path.InUse || path.Priority != 1 {
		t.Fatalf("fast path = %#v, want in use with its configured priority", path)
	}
	if path := fixture.path(t, "", 0); path.InUse || path.Degraded || path.Priority != 0 {
		t.Fatalf("slow path = %#v, want healthy, not in use, with its configured priority", path)
	}
	// A small gain of the other path moves nothing.
	fixture.rtt[0] = 19 * time.Millisecond
	for range 40 {
		fixture.run(t, 1)
		if first := fixture.first(); first != 1 {
			t.Fatalf("path %d is first after a small change, want path 1", first)
		}
	}
	// The current path that fails moves the data at once.
	fixture.miss(t, 1, missLimit)
	if mask, _ := fixture.state(); mask != 0b01 || fixture.first() != 0 {
		t.Fatalf("mask = %#b after path 1 failed, want path 0", mask)
	}
}

func TestWithoutSettingsThePathStateIsTheHealth(t *testing.T) {
	t.Parallel()

	fixture := newDataFixture(t, lossGroup(t, config.ModeFailover, 0, config.PreferOrder),
		testGroup(t, 51821, config.ModeBalancer, "198.51.100.3:5000/udp"))
	fixture.loss[0], fixture.rtt[1] = 0.5, 5*time.Millisecond
	check := func(when string) {
		t.Helper()
		mask, generation := fixture.controller.health.Snapshot()
		if current, again := fixture.state(); current != mask || again != generation {
			t.Fatalf("%s: state = %#b %d, want the health %#b %d", when, current, again, mask, generation)
		}
	}
	check("start")
	for range 20 {
		fixture.run(t, 1)
		check("round")
	}
	fixture.miss(t, 0, missLimit)
	check("miss")
	fixture.run(t, 3)
	check("round after the miss")
	for _, path := range []int{0, 1, 2} {
		if got := fixture.path(t, "", path); got.Degraded {
			t.Fatalf("path %d = %#v, want no degradation without a loss limit", path, got)
		}
	}
}

func TestADegradedMemberLeavesThePublishedList(t *testing.T) {
	t.Parallel()

	group := testGroup(t, 51820, config.ModeFailover, "198.51.100.1:9000/icmp via 203.0.113.0/30")
	group.EgressPaths = append(group.EgressPaths, mustParsePath(t, "198.51.100.1:9300/udp"))
	group.MaxLoss = 50
	fixture := newDataFixture(t, group)
	good, lossy := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")
	if err := fixture.registrations[0].writeMembers([]netip.Addr{good, lossy}); err != nil {
		t.Fatalf("writeMembers: %v", err)
	}
	published := func() []netip.Addr {
		fixture.dataplane.mu.Lock()
		defer fixture.dataplane.mu.Unlock()
		return fixture.dataplane.reflect[0]
	}
	answers := map[netip.Addr]func(round int) bool{
		good:  func(int) bool { return true },
		lossy: func(round int) bool { return round%2 == 0 },
	}
	run := func(rounds int) {
		for range rounds {
			fixture.round++
			sentAt := fixture.now()
			fixture.controller.measureRound(sentAt)
			for _, sent := range measuresOf(fixture.controls.takeSent()) {
				if answer := answers[sent.member]; answer != nil && answer(fixture.round) {
					reply := measureReplyOf(sent.frame, 0, netip.MustParseAddr("198.51.100.1"), protocol.TransportUDP, 9300, sentAt.Add(30*time.Millisecond))
					fixture.controls.handle(reply)
				}
			}
		}
	}
	run(10)
	if got := published(); !slices.Equal(got, []netip.Addr{good}) {
		t.Fatalf("published members = %v, want only %s", got, good)
	}
	list, err := fixture.controller.Members()
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	for _, member := range list.Members {
		switch member.Address {
		case lossy.String():
			if !member.Healthy || !member.Degraded {
				t.Fatalf("lossy member = %#v, want healthy and degraded", member)
			}
		case good.String():
			if !member.Healthy || member.Degraded {
				t.Fatalf("good member = %#v, want healthy and not degraded", member)
			}
		}
	}
	// A new round of the control loop keeps the degraded member out.
	if err := fixture.registrations[0].writeMembers([]netip.Addr{good, lossy}); err != nil {
		t.Fatalf("writeMembers: %v", err)
	}
	if got := published(); !slices.Equal(got, []netip.Addr{good}) {
		t.Fatalf("published members after a control round = %v, want only %s", got, good)
	}
	// When the last members degrade too, all healthy members stay.
	answers[good] = func(round int) bool { return round%2 == 0 }
	run(5)
	if got := published(); !slices.Equal(got, []netip.Addr{good, lossy}) {
		t.Fatalf("published members = %v, want both when both are degraded", got)
	}
}

func TestWithoutSettingsTheMemberListIsTheHealthyList(t *testing.T) {
	t.Parallel()

	fixture := newReflectFixture(t)
	members := []netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")}
	if err := fixture.registrations[0].writeMembers(members); err != nil {
		t.Fatalf("writeMembers: %v", err)
	}
	start := time.Now().Add(-time.Minute)
	for round := range 15 {
		sentAt := start.Add(time.Duration(round) * measureInterval)
		fixture.controller.measureRound(sentAt)
		// Only the first member answers, so the second loses every probe.
		for _, sent := range measuresOf(fixture.controls.takeSent()) {
			if sent.member == members[0] {
				fixture.controls.handle(measureReplyOf(sent.frame, 0, netip.MustParseAddr("198.51.100.1"), protocol.TransportUDP, 9300, sentAt.Add(time.Millisecond)))
			}
		}
	}
	fixture.dataplane.mu.Lock()
	defer fixture.dataplane.mu.Unlock()
	if got := fixture.dataplane.reflect[0]; !slices.Equal(got, members) {
		t.Fatalf("published members = %v, want the healthy list %v", got, members)
	}
}

func TestTheEgressRegisterCarriesTheEgressSettings(t *testing.T) {
	t.Parallel()

	group := testGroup(t, 51820, config.ModeFailover, "198.51.100.1:9000/udp")
	group.EgressPaths = append(group.EgressPaths, mustParsePath(t, "198.51.100.1:9300/udp"))
	group.EgressMaxLoss, group.EgressPrefer = 25, config.PreferLatency
	fixture := newDataFixture(t, group)
	frames := decodeFrames(t, fixture.registrations[0].egressFrames(1))
	if len(frames) != 1 {
		t.Fatalf("EGRESS_REGISTER frames = %#v", frames)
	}
	seconds, settings := protocol.UnpackEgressLease(frames[0].LeaseSeconds)
	if seconds != registrationLeaseSeconds || settings != (protocol.EgressSettings{MaxLossTenths: 25, PreferLatency: true}) {
		t.Fatalf("lease = %d, %#v", seconds, settings)
	}
	status, err := fixture.controller.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if got := status.Client.Groups[0]; got.EgressMaxLossPercent != 2.5 || got.EgressPrefer != "latency" || got.MaxLossPercent != 0 || got.Prefer != "" {
		t.Fatalf("group = %#v", got)
	}
	// Without settings the lease stays 30, as an older client sends it.
	plain := newSplitFixture(t)
	for _, frame := range decodeFrames(t, plain.registrations[0].egressFrames(1)) {
		if frame.LeaseSeconds != registrationLeaseSeconds {
			t.Fatalf("lease without settings = %#x, want %d", frame.LeaseSeconds, registrationLeaseSeconds)
		}
	}
}
