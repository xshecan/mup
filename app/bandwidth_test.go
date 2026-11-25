package app

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/protocol"
)

func mbit(rate uint64) dataplane.RateLimit {
	return dataplane.RateLimit{BitsPerSecond: rate * 1_000_000}
}

func TestBalancerWeightsFollowTheRates(t *testing.T) {
	t.Parallel()

	perMember := dataplane.RateLimit{BitsPerSecond: 5_000_000, PerMember: true}
	for name, tt := range map[string]struct {
		mode   config.Mode
		shares []rateShare
		want   [config.MaxPaths]uint8
	}{
		"all limited": {config.ModeBalancer, []rateShare{{id: 0, limit: mbit(10)}, {id: 1, limit: mbit(20)}, {id: 3, limit: mbit(5)}},
			[config.MaxPaths]uint8{0: 128, 1: 255, 3: 64}},
		"equal rates": {config.ModeBalancer, []rateShare{{id: 2, limit: mbit(7)}, {id: 5, limit: mbit(7)}},
			[config.MaxPaths]uint8{2: 255, 5: 255}},
		"one unlimited": {config.ModeBalancer, []rateShare{{id: 0, limit: mbit(10)}, {id: 1}}, [config.MaxPaths]uint8{}},
		"per member counts every member": {config.ModeBalancer, []rateShare{{id: 0, limit: perMember, members: 4}, {id: 1, limit: mbit(10)}},
			[config.MaxPaths]uint8{0: 255, 1: 128}},
		"a per member path without members counts one": {config.ModeBalancer, []rateShare{{id: 0, limit: perMember}, {id: 1, limit: mbit(10)}},
			[config.MaxPaths]uint8{0: 128, 1: 255}},
		"a tiny rate keeps a weight of one": {config.ModeBalancer, []rateShare{{id: 0, limit: dataplane.RateLimit{BitsPerSecond: 8_000}}, {id: 1, limit: mbit(100_000)}},
			[config.MaxPaths]uint8{0: 1, 1: 255}},
		"failover":  {config.ModeFailover, []rateShare{{id: 0, limit: mbit(10)}, {id: 1, limit: mbit(20)}}, [config.MaxPaths]uint8{}},
		"repeater":  {config.ModeRepeater, []rateShare{{id: 0, limit: mbit(10)}, {id: 1, limit: mbit(20)}}, [config.MaxPaths]uint8{}},
		"no paths":  {config.ModeBalancer, nil, [config.MaxPaths]uint8{}},
		"one path":  {config.ModeBalancer, []rateShare{{id: 4, limit: mbit(1)}}, [config.MaxPaths]uint8{4: 255}},
		"no limits": {config.ModeBalancer, []rateShare{{id: 0}, {id: 1}}, [config.MaxPaths]uint8{}},
	} {
		if got := balancerWeights(tt.mode, tt.shares); got != tt.want {
			t.Fatalf("%s: weights = %v, want %v", name, got, tt.want)
		}
	}
}

func TestTheClientPlanCarriesTheIngressLimitsAndWeights(t *testing.T) {
	t.Parallel()

	balanced := testGroup(t, 51820, config.ModeBalancer,
		"198.51.100.1:9000/udp bw 10mbit", "198.51.100.2:9000/udp bw 20mbit")
	failover := testGroup(t, 51821, config.ModeFailover,
		"198.51.100.3:9000/udp bw 5mbit", "198.51.100.4:9000/udp")
	mixed := testGroup(t, 51822, config.ModeBalancer,
		"198.51.100.5:9000/udp bw 5mbit", "198.51.100.6:9000/udp")
	client := config.Client{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), Groups: []config.Group{balanced, failover, mixed}}
	plan, err := buildPlan(config.App{Client: &client}, 42, fakeResolver{catchAll: 2})
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	want := []struct {
		limit  dataplane.RateLimit
		weight uint8
	}{{mbit(10), 128}, {mbit(20), 255}, {mbit(5), 0}, {dataplane.RateLimit{}, 0}, {mbit(5), 0}, {dataplane.RateLimit{}, 0}}
	for slot, w := range want {
		got := plan.client.Paths[slot]
		if got.Limit != w.limit || got.Weight != w.weight || got.Priority != uint8(slot) {
			t.Fatalf("path %d = limit %#v weight %d priority %d, want %#v %d %d", slot, got.Limit, got.Weight, got.Priority, w.limit, w.weight, slot)
		}
	}
}

func TestTheLimitOfAnIngressPathReachesTheDataplaneAndTheAPI(t *testing.T) {
	t.Parallel()

	fixture := newDataFixture(t, testGroup(t, 51820, config.ModeBalancer, "198.51.100.1:9000/udp bw 10mbit"))
	if path := fixture.path(t, "", 0); path.BandwidthBitsPerSecond != 10e6 || path.BandwidthPerMember {
		t.Fatalf("API path = %#v, want the limit", path)
	}
	// A path added at run time takes its limit from the route text, and the
	// weights of the group follow it.
	added, err := fixture.controller.AddPath("198.51.100.2:9000/udp bw 30mbit", 51820)
	if err != nil {
		t.Fatalf("AddPath: %v", err)
	}
	if added.BandwidthBitsPerSecond != 30e6 {
		t.Fatalf("added path = %#v", added)
	}
	fixture.dataplane.mu.Lock()
	first, second := fixture.dataplane.paths[0], fixture.dataplane.paths[1]
	fixture.dataplane.mu.Unlock()
	if second.Limit != mbit(30) || second.Weight != 255 || first.Limit != mbit(10) || first.Weight != 85 {
		t.Fatalf("paths = %#v and %#v, want the limits with the weights 85 and 255", first, second)
	}
	// A path without a limit makes the shares equal again.
	if _, err := fixture.controller.AddPath("198.51.100.3:9000/udp", 51820); err != nil {
		t.Fatalf("AddPath: %v", err)
	}
	fixture.dataplane.mu.Lock()
	for slot := range 3 {
		if got := fixture.dataplane.paths[slot]; got.Weight != 0 {
			fixture.dataplane.mu.Unlock()
			t.Fatalf("path %d weight = %d with an unlimited path in the group, want 0", slot, got.Weight)
		}
	}
	fixture.dataplane.mu.Unlock()
	// The removal of the unlimited path brings the weights back.
	if err := fixture.controller.RemovePath(2); err != nil {
		t.Fatalf("RemovePath: %v", err)
	}
	fixture.dataplane.mu.Lock()
	first, second = fixture.dataplane.paths[0], fixture.dataplane.paths[1]
	fixture.dataplane.mu.Unlock()
	if first.Weight != 85 || second.Weight != 255 {
		t.Fatalf("weights after the removal = %d and %d, want 85 and 255", first.Weight, second.Weight)
	}
	// The weights count only in the balancer mode.
	if err := fixture.controller.SetMode("failover", 51820); err != nil {
		t.Fatalf("SetMode: %v", err)
	}
	fixture.dataplane.mu.Lock()
	first, second = fixture.dataplane.paths[0], fixture.dataplane.paths[1]
	fixture.dataplane.mu.Unlock()
	if first.Weight != 0 || second.Weight != 0 || first.Limit != mbit(10) || second.Limit != mbit(30) {
		t.Fatalf("paths in the failover mode = %#v and %#v", first, second)
	}
}

func TestAPerMemberLimitOfAnIngressReflectPathKeepsItsMembers(t *testing.T) {
	t.Parallel()

	group := testGroup(t, 51820, config.ModeBalancer, "198.51.100.1:9000/icmp via 203.0.113.0/30 bw 5mbit per-member", "198.51.100.2:9000/udp bw 10mbit")
	group.EgressPaths = append(group.EgressPaths, mustParsePath(t, "198.51.100.1:9300/udp"))
	fixture := newDataFixture(t, group)
	settings := fixture.controller.initial[0]
	if settings.Limit != (dataplane.RateLimit{BitsPerSecond: 5_000_000, PerMember: true}) || settings.Weight != 255 || fixture.controller.initial[1].Weight != 128 {
		t.Fatalf("plan = %#v and %#v, want the per member limit of 4 members", settings, fixture.controller.initial[1])
	}
	members := []netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")}
	if err := fixture.registrations[0].writeMembers(members); err != nil {
		t.Fatalf("writeMembers: %v", err)
	}
	// A change of the weight writes the path again, and the members follow.
	if _, err := fixture.controller.AddPath("198.51.100.3:9000/udp", 51820); err != nil {
		t.Fatalf("AddPath: %v", err)
	}
	fixture.dataplane.mu.Lock()
	defer fixture.dataplane.mu.Unlock()
	if got := fixture.dataplane.paths[0]; got.Weight != 0 || !got.Limit.PerMember {
		t.Fatalf("reflect path = %#v, want weight 0 and its limit", got)
	}
	if got := fixture.dataplane.reflect[0]; len(got) != 2 {
		t.Fatalf("members after the write = %v, want both", got)
	}
	// The new path is written, then the group, then path 0 with its
	// members right after it, then path 1.
	log := fixture.dataplane.log
	if n := len(log); n < 5 || log[n-5] != "set" || log[n-4] != "group" || log[n-3] != "set" || log[n-2] != "reflect 0 2" || log[n-1] != "set" {
		t.Fatalf("log = %v, want the members right after path 0", log)
	}
}

func TestWithoutABandwidthTheClientWritesNothingNew(t *testing.T) {
	t.Parallel()

	fixture := newDataFixture(t, testGroup(t, 51820, config.ModeBalancer, "198.51.100.1:9000/udp", "198.51.100.2:9000/udp"))
	for slot, settings := range fixture.controller.initial {
		if settings.Limit != (dataplane.RateLimit{}) || settings.Weight != 0 {
			t.Fatalf("plan path %d = %#v", slot, settings)
		}
	}
	fixture.dataplane.mu.Lock()
	before := len(fixture.dataplane.log)
	fixture.dataplane.mu.Unlock()
	if _, err := fixture.controller.AddPath("198.51.100.3:9000/udp", 51820); err != nil {
		t.Fatalf("AddPath: %v", err)
	}
	if err := fixture.controller.SetMode("failover", 51820); err != nil {
		t.Fatalf("SetMode: %v", err)
	}
	fixture.dataplane.mu.Lock()
	defer fixture.dataplane.mu.Unlock()
	sets := 0
	for _, entry := range fixture.dataplane.log[before:] {
		if entry == "set" {
			sets++
		}
	}
	if sets != 1 {
		t.Fatalf("log = %v, want one write of the new path only", fixture.dataplane.log[before:])
	}
	if got := fixture.dataplane.paths[2]; got.Priority != 2 || got.Weight != 0 || got.Limit != (dataplane.RateLimit{}) {
		t.Fatalf("new path = %#v", got)
	}
}

// egressLimitGroup is a group with an egress path with a limit, one without,
// and one with a limit per member.
func egressLimitGroup(t *testing.T) config.Group {
	t.Helper()
	group := testGroup(t, 51820, config.ModeFailover, "198.51.100.1:9000/udp", "198.51.100.2:9100/icmp")
	group.EgressMode = config.ModeBalancer
	for _, raw := range []string{
		"198.51.100.1:9300/udp bw 10mbit",
		"198.51.100.1:9301/udp",
		"198.51.100.1:9200/icmp via 203.0.113.0/28 per-packet bw 2mbit per-member",
	} {
		group.EgressPaths = append(group.EgressPaths, mustParsePath(t, raw))
	}
	return group
}

func TestAnEgressLimitFollowsEachEgressRegisterOfALimitedPath(t *testing.T) {
	t.Parallel()

	fixture := newDataFixture(t, egressLimitGroup(t))
	for _, registration := range []pathRegistration{fixture.registrations[0], fixture.registrations[1]} {
		packets := registration.egressFrames(7)
		var frames []protocol.ControlFrame
		for _, packet := range packets {
			frame, err := protocol.DecodeControlFrame(packet)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			frames = append(frames, frame)
		}
		registers, limits := 0, map[uint16]protocol.ControlFrame{}
		for index, frame := range frames {
			switch frame.Type {
			case protocol.ControlEgressRegister:
				registers++
			case protocol.ControlEgressLimit:
				if index == 0 || frames[index-1].Type != protocol.ControlEgressRegister || frames[index-1].PathID != frame.PathID {
					t.Fatalf("frames = %#v, want each EGRESS_LIMIT right after the EGRESS_REGISTER of its path", frames)
				}
				limits[frame.PathID] = frame
				// The head is the head of the EGRESS_REGISTER without flags.
				head := bytes.Clone(packets[index-1][:36])
				head[5], head[7], head[18], head[19] = byte(protocol.ControlEgressLimit), 0, 0, 0
				clear(head[24:28])
				if !bytes.Equal(head, packets[index][:36]) {
					t.Fatalf("EGRESS_LIMIT head = %x, want %x", packets[index][:36], head)
				}
			default:
				t.Fatalf("frame = %#v", frame)
			}
		}
		if registers != 3 || len(limits) != 2 {
			t.Fatalf("frames = %#v, want 3 EGRESS_REGISTER frames and 2 EGRESS_LIMIT frames", frames)
		}
		if got := limits[0]; got.LimitKbps != 10_000 || got.LimitFlags != 0 || got.Transport != protocol.TransportUDP || got.ServerPort != 9300 ||
			got.ListenPort != 51820 || got.InstanceNonce != 42 || got.AdvertisedIP != netip.MustParseAddr("192.0.2.10") {
			t.Fatalf("limit of path 0 = %#v", got)
		}
		if got := limits[2]; got.LimitKbps != 2_000 || got.LimitFlags != protocol.EgressLimitPerMember || got.Transport != protocol.TransportICMP || got.ServerPort != 9200 {
			t.Fatalf("limit of path 2 = %#v", got)
		}
	}
	// The API shows the limits of the egress paths.
	if path := fixture.path(t, directionEgress, 0); path.BandwidthBitsPerSecond != 10e6 || path.BandwidthPerMember {
		t.Fatalf("egress path 0 = %#v", path)
	}
	if path := fixture.path(t, directionEgress, 2); path.BandwidthBitsPerSecond != 2e6 || !path.BandwidthPerMember {
		t.Fatalf("egress path 2 = %#v", path)
	}
	if path := fixture.path(t, directionEgress, 1); path.BandwidthBitsPerSecond != 0 || path.BandwidthPerMember {
		t.Fatalf("egress path 1 = %#v", path)
	}
	// A path that the client removes goes with a lease of zero and no limit.
	if err := fixture.controller.RemoveEgressPath(0); err != nil {
		t.Fatalf("RemoveEgressPath: %v", err)
	}
	for _, frame := range decodeFrames(t, fixture.registrations[0].egressFrames(8)) {
		if frame.Type == protocol.ControlEgressLimit && frame.PathID == 0 {
			t.Fatalf("a removed path sends a limit: %#v", frame)
		}
	}
	// A path added at run time with a limit sends it too.
	if _, err := fixture.controller.AddEgressPath("198.51.100.1:9302/udp bw 1.5gbit", 51820); err != nil {
		t.Fatalf("AddEgressPath: %v", err)
	}
	found := false
	for _, frame := range decodeFrames(t, fixture.registrations[0].egressFrames(9)) {
		if frame.Type == protocol.ControlEgressLimit && frame.ServerPort == 9302 {
			found = frame.LimitKbps == 1_500_000
		}
	}
	if !found {
		t.Fatalf("the added path sends no limit of 1.5gbit")
	}
}

// TestAnEgressRegisterIsTheSameWithALimit checks that a limit changes no
// byte of the EGRESS_REGISTER, so an older server sees the frames of v0.5.4
// and drops only the EGRESS_LIMIT that it does not know.
func TestAnEgressRegisterIsTheSameWithALimit(t *testing.T) {
	t.Parallel()

	registration := pathRegistration{advertisedIP: netip.MustParseAddr("192.0.2.10"), listenPort: 51820, nonce: 42}
	for _, raw := range []string{"198.51.100.1:9300/udp", "198.51.100.1:9200/icmp via 203.0.113.0/28 per-packet src 5000-6000", "198.51.100.1:9300/udp via 203.0.113.9 bridge 192.0.2.7"} {
		plain, err := config.NormalizeEgressPath(mustParsePath(t, raw), false)
		if err != nil {
			t.Fatalf("NormalizeEgressPath: %v", err)
		}
		limited := plain
		limited.BandwidthBitsPerSecond, limited.BandwidthPerMember = 10_000_000, plain.ReturnIP.IsValid()
		want, err := egressRegisterFrame(registration, 1, plain, config.ModeBalancer, 5, registrationLeaseSeconds)
		if err != nil {
			t.Fatalf("egressRegisterFrame: %v", err)
		}
		got, err := egressRegisterFrame(registration, 1, limited, config.ModeBalancer, 5, registrationLeaseSeconds)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s: EGRESS_REGISTER with a limit = %x, %v, want %x", raw, got, err, want)
		}
		if _, err := protocol.DecodeControlFrame(want); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	// Without a limit an ingress path sends only EGRESS_REGISTER frames.
	plain := newSplitFixture(t)
	for _, frame := range decodeFrames(t, plain.registrations[0].egressFrames(1)) {
		if frame.Type != protocol.ControlEgressRegister {
			t.Fatalf("frame without a limit = %#v", frame)
		}
	}
}

func egressLimitOf(id, port uint16, transport protocol.TransportID, kbps, flags uint32) protocol.ControlFrame {
	return protocol.ControlFrame{
		Type:          protocol.ControlEgressLimit,
		Transport:     transport,
		PathID:        id,
		ListenPort:    51820,
		ServerPort:    port,
		InstanceNonce: 7,
		AdvertisedIP:  egressClient,
		LimitKbps:     kbps,
		LimitFlags:    flags,
	}
}

func TestTheServerKeepsChangesAndDropsAnEgressLimit(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	registry := newTestEgressRegistry(plane)
	service := &egressService{registry: registry, logger: discardLogger}
	now := time.Unix(1000, 0)
	key := egressKey{client: egressKeyOf, id: 0}
	register := egressFrame(0, 9300, protocol.TransportUDP, config.ModeFailover)
	limit := egressLimitOf(0, 9300, protocol.TransportUDP, 10_000, 0)
	step := func(frames ...protocol.ControlFrame) {
		t.Helper()
		now = now.Add(egressProbeInterval)
		for _, frame := range frames {
			if !service.handle(frame, egressClient, false) {
				t.Fatalf("handle(%#v) = false", frame)
			}
		}
		registry.sync(now)
	}
	// A limit for a path that the server does not keep creates nothing.
	step(limit)
	if len(plane.paths) != 0 || len(registry.paths) != 0 {
		t.Fatalf("paths = %#v", plane.paths)
	}
	step(register)
	if got := plane.paths[key].Limit; got != (dataplane.RateLimit{}) {
		t.Fatalf("limit without an EGRESS_LIMIT = %#v", got)
	}
	step(register, limit)
	if got := plane.paths[key].Limit; got != mbit(10) {
		t.Fatalf("limit = %#v, want 10 mbit", got)
	}
	view := registry.clients(now)[egressKeyOf][0].Paths[0]
	if view.BandwidthBitsPerSecond != 10e6 || view.BandwidthPerMember {
		t.Fatalf("API egress path = %#v", view)
	}
	// A new rate replaces the old one with the next sync.
	changed := limit
	changed.LimitKbps = 20_000
	step(register, changed)
	if got := plane.paths[key].Limit; got != mbit(20) {
		t.Fatalf("limit = %#v, want 20 mbit", got)
	}
	// Two EGRESS_REGISTER frames without a limit keep it, and the third drops it.
	step(register)
	step(register)
	if got := plane.paths[key].Limit; got != mbit(20) {
		t.Fatalf("limit after two frames without it = %#v, want 20 mbit", got)
	}
	step(register)
	if got := plane.paths[key].Limit; got != (dataplane.RateLimit{}) {
		t.Fatalf("limit after three frames without it = %#v, want none", got)
	}
	// A rate of zero removes the limit at once.
	step(register, limit)
	removal := limit
	removal.LimitKbps = 0
	step(register, removal)
	if got := plane.paths[key].Limit; got != (dataplane.RateLimit{}) {
		t.Fatalf("limit after a rate of zero = %#v, want none", got)
	}
	// A limit from another source, or for another port of the path, changes nothing.
	if !service.handle(limit, netip.MustParseAddr("198.51.100.77"), false) {
		t.Fatalf("handle of a foreign EGRESS_LIMIT = false")
	}
	other := limit
	other.ServerPort = 9301
	if err := registry.limit(other, now); err == nil {
		t.Fatalf("limit for another server port succeeded")
	}
	registry.sync(now)
	if got := plane.paths[key].Limit; got != (dataplane.RateLimit{}) {
		t.Fatalf("limit after foreign frames = %#v, want none", got)
	}
}

func TestTheServerWeighsALimitedBalancerGroup(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	plane.members[dataplane.PoolKey{Base: egressPool, Transport: protocol.TransportICMP}] = egressMembers
	registry := newTestEgressRegistry(plane)
	now := time.Unix(1000, 0)
	pool := poolFrame(1, 9200)
	pool.EgressMode = uint8(config.ModeBalancer)
	frames := []protocol.ControlFrame{egressFrame(0, 9300, protocol.TransportUDP, config.ModeBalancer), pool}
	for _, frame := range frames {
		if err := registry.register(frame, now); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	registry.sync(now)
	if got := plane.groups[egressGroupOf].Weights; got != ([dataplane.MaxEgressPaths]uint8{}) {
		t.Fatalf("weights without limits = %v", got)
	}
	// The pool path has three members with 10 mbit each, so it has 30 mbit.
	for _, limit := range []protocol.ControlFrame{
		egressLimitOf(0, 9300, protocol.TransportUDP, 15_000, 0),
		egressLimitOf(1, 9200, protocol.TransportICMP, 10_000, protocol.EgressLimitPerMember),
	} {
		if err := registry.limit(limit, now); err != nil {
			t.Fatalf("limit: %v", err)
		}
	}
	registry.sync(now)
	if got := plane.groups[egressGroupOf].Weights; got != ([dataplane.MaxEgressPaths]uint8{0: 128, 1: 255}) {
		t.Fatalf("weights = %v, want 128 and 255", got)
	}
	if got := plane.paths[egressKey{client: egressKeyOf, id: 1}].Limit; got != (dataplane.RateLimit{BitsPerSecond: 10_000_000, PerMember: true}) {
		t.Fatalf("pool limit = %#v", got)
	}
	// One path without a limit gives equal shares again.
	if err := registry.limit(egressLimitOf(0, 9300, protocol.TransportUDP, 0, 0), now); err != nil {
		t.Fatalf("limit: %v", err)
	}
	registry.sync(now)
	if got := plane.groups[egressGroupOf]; got.Weights != ([dataplane.MaxEgressPaths]uint8{}) || got.HasPreferred {
		t.Fatalf("group = %#v, want no weights and no preferred path", got)
	}
}

func TestTheServerWithoutEgressLimitsWritesTheEntriesOfBefore(t *testing.T) {
	t.Parallel()

	// An older client sends no EGRESS_LIMIT, so the entries have no limit,
	// no weights, and no preferred path.
	driver := newEgressDriver(egressFrame(0, 9300, protocol.TransportUDP, config.ModeBalancer), egressFrame(1, 9301, protocol.TransportUDP, config.ModeBalancer))
	driver.run(t, 3)
	for id := range uint16(2) {
		if got := driver.plane.paths[egressKey{client: egressKeyOf, id: id}].Limit; got != (dataplane.RateLimit{}) {
			t.Fatalf("path %d limit = %#v", id, got)
		}
	}
	group := driver.plane.groups[egressGroupOf]
	if group.Weights != ([dataplane.MaxEgressPaths]uint8{}) || group.HasPreferred || group.Preferred != 0 || group.HealthyMask != 0b11 {
		t.Fatalf("group = %#v", group)
	}
}

func TestTheLatencyChoiceOfTheServerNamesThePreferredPath(t *testing.T) {
	t.Parallel()

	settings := protocol.EgressSettings{PreferLatency: true}
	driver := newEgressDriver(settingsFrame(0, 9300, config.ModeFailover, settings), settingsFrame(1, 9301, config.ModeFailover, settings),
		settingsFrame(2, 9302, config.ModeFailover, settings))
	driver.rtt[0], driver.rtt[1], driver.rtt[2] = 60*time.Millisecond, 40*time.Millisecond, 15*time.Millisecond
	driver.run(t, 1)
	if group := driver.plane.groups[egressGroupOf]; !group.HasPreferred || group.Preferred != 0 || group.HealthyMask != 0b111 {
		t.Fatalf("first group = %#v, want path 0 preferred in the usable set", group)
	}
	driver.runUntilFirst(t, 2, 12)
	if group := driver.plane.groups[egressGroupOf]; !group.HasPreferred || group.Preferred != 2 || group.HealthyMask != 0b111 {
		t.Fatalf("group = %#v, want path 2 preferred in the usable set", group)
	}
	if view := driver.egressPath(t, 2); !view.active {
		t.Fatalf("preferred path = %#v, want active", view)
	}
}

func TestTheLatencyChoiceOfTheClientWritesThePriorities(t *testing.T) {
	t.Parallel()

	group := testGroup(t, 51820, config.ModeFailover, "198.51.100.1:9000/udp", "198.51.100.2:9100/udp", "198.51.100.3:9200/udp")
	group.Prefer = config.PreferLatency
	fixture := newDataFixture(t, group)
	fixture.rtt[0], fixture.rtt[1], fixture.rtt[2] = 50*time.Millisecond, 40*time.Millisecond, 10*time.Millisecond
	sets := func() int {
		fixture.dataplane.mu.Lock()
		defer fixture.dataplane.mu.Unlock()
		count := 0
		for _, entry := range fixture.dataplane.log {
			if entry == "set" {
				count++
			}
		}
		return count
	}
	if got := sets(); got != 0 {
		t.Fatalf("writes before a choice = %d, want 0", got)
	}
	fixture.runUntilFirst(t, 2, 15)
	fixture.dataplane.mu.Lock()
	var priorities [3]uint8
	for slot := range priorities {
		priorities[slot] = fixture.dataplane.paths[slot].Priority
	}
	fixture.dataplane.mu.Unlock()
	if priorities != [3]uint8{1, 2, 0} {
		t.Fatalf("priorities = %v, want the chosen path 2 first and then the order", priorities)
	}
	if mask, _ := fixture.state(); mask != 0b111 {
		t.Fatalf("mask = %#b, want every usable path", mask)
	}
	// The API keeps the configured priorities.
	for slot := range 3 {
		if path := fixture.path(t, "", slot); path.Priority != uint8(slot) || path.InUse != (slot == 2) {
			t.Fatalf("path %d = %#v", slot, path)
		}
	}
	// The priorities stay while the choice stays.
	written := sets()
	fixture.run(t, 10)
	if got := sets(); got != written {
		t.Fatalf("writes = %d without a new choice, want %d", got, written)
	}
	// The chosen path fails, so the next path by latency takes its place.
	fixture.miss(t, 2, missLimit)
	fixture.dataplane.mu.Lock()
	for slot := range priorities {
		priorities[slot] = fixture.dataplane.paths[slot].Priority
	}
	fixture.dataplane.mu.Unlock()
	if priorities != [3]uint8{1, 0, 2} || fixture.first() != 1 {
		t.Fatalf("priorities after path 2 failed = %v with path %d first, want path 1 first", priorities, fixture.first())
	}
	// The order mode writes the configured priorities back.
	if err := fixture.controller.SetMode("balancer", 51820); err != nil {
		t.Fatalf("SetMode: %v", err)
	}
	fixture.dataplane.mu.Lock()
	for slot := range priorities {
		priorities[slot] = fixture.dataplane.paths[slot].Priority
	}
	fixture.dataplane.mu.Unlock()
	if priorities != [3]uint8{0, 1, 2} {
		t.Fatalf("priorities in the balancer mode = %v, want the configured ones", priorities)
	}
}
