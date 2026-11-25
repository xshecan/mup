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
	"github.com/xshecan/mup/protocol"
)

type fakeEgressPlane struct {
	paths   map[egressKey]dataplane.EgressPathEntry
	groups  map[egressGroupKey]dataplane.EgressGroupEntry
	members map[dataplane.PoolKey][]netip.Addr
	pools   []dataplane.PoolKey
	fakeServerCounters
}

func newFakeEgressPlane() *fakeEgressPlane {
	return &fakeEgressPlane{
		paths:   map[egressKey]dataplane.EgressPathEntry{},
		groups:  map[egressGroupKey]dataplane.EgressGroupEntry{},
		members: map[dataplane.PoolKey][]netip.Addr{},
	}
}

func (f *fakeEgressPlane) SetServerEgressPath(entry dataplane.EgressPathEntry) error {
	f.paths[egressKey{client: entry.Client, id: entry.PathID}] = entry
	return nil
}

func (f *fakeEgressPlane) DeleteServerEgressPath(client dataplane.ClientKey, id uint16) error {
	delete(f.paths, egressKey{client: client, id: id})
	return nil
}

func (f *fakeEgressPlane) SetServerEgressGroup(entry dataplane.EgressGroupEntry) error {
	f.groups[egressGroupKey{client: entry.Client, listenPort: entry.ListenPort}] = entry
	return nil
}

func (f *fakeEgressPlane) DeleteServerEgressGroup(client dataplane.ClientKey, listenPort uint16) error {
	delete(f.groups, egressGroupKey{client: client, listenPort: listenPort})
	return nil
}

func (f *fakeEgressPlane) ObservePool(base netip.Addr, _ uint8, transport protocol.TransportID) error {
	f.pools = append(f.pools, dataplane.PoolKey{Base: base, Transport: transport})
	return nil
}

func (f *fakeEgressPlane) PoolMembers(key dataplane.PoolKey) []netip.Addr {
	return f.members[key]
}

var (
	egressClient  = netip.MustParseAddr("192.0.2.10")
	egressServer  = netip.MustParseAddr("203.0.113.5")
	egressPool    = netip.MustParseAddr("198.51.100.0")
	egressMembers = []netip.Addr{netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2"), netip.MustParseAddr("198.51.100.3")}
	egressKeyOf   = dataplane.ClientKey{AdvertisedIP: egressClient, InstanceNonce: 7}
	egressGroupOf = egressGroupKey{client: egressKeyOf, listenPort: 51820}
)

func newTestEgressRegistry(plane *fakeEgressPlane) *egressRegistry {
	locate := func(server, destination netip.Addr) (int, error) {
		if server != egressServer {
			return 0, errEgressNotLocal
		}
		return 3, nil
	}
	return newEgressRegistry(config.PortRange{First: 9000, Last: 9999}, plane, locate, discardLogger)
}

func egressFrame(id uint16, port uint16, transport protocol.TransportID, mode config.Mode) protocol.ControlFrame {
	return protocol.ControlFrame{
		Type:          protocol.ControlEgressRegister,
		Transport:     transport,
		PathID:        id,
		ListenPort:    51820,
		ServerPort:    port,
		LeaseSeconds:  registrationLeaseSeconds,
		InstanceNonce: 7,
		AdvertisedIP:  egressClient,
		EgressMode:    uint8(mode),
		EgressServer:  egressServer,
	}
}

func poolFrame(id uint16, port uint16) protocol.ControlFrame {
	frame := egressFrame(id, port, protocol.TransportICMP, config.ModeRepeater)
	frame.Flags = protocol.ControlFlagReturnPool | protocol.ControlFlagBalancePerPacket
	frame.ReturnIP = egressPool
	frame.ReturnPrefix = 28
	return frame
}

func probeReply(id uint16, transport protocol.TransportID, member netip.Addr) protocol.ControlFrame {
	return protocol.ControlFrame{
		Type:          protocol.ControlProbeReply,
		Transport:     transport,
		Flags:         protocol.ControlFlagEgressPath | protocol.ControlFlagReturnIP,
		PathID:        id,
		InstanceNonce: 7,
		AdvertisedIP:  egressClient,
		ReturnIP:      member,
	}
}

func TestEgressRegistryKeepsAEgressPathAndItsGroup(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	plane.members[dataplane.PoolKey{Base: egressPool, Transport: protocol.TransportICMP}] = egressMembers
	registry := newTestEgressRegistry(plane)
	now := time.Unix(1000, 0)
	if err := registry.register(poolFrame(0, 9200), now); err != nil {
		t.Fatalf("register pool path: %v", err)
	}
	if err := registry.register(egressFrame(2, 9300, protocol.TransportUDP, config.ModeRepeater), now); err != nil {
		t.Fatalf("register direct path: %v", err)
	}
	pool := plane.paths[egressKey{client: egressKeyOf, id: 0}]
	if !pool.Pool || !pool.PerPacket || pool.Ifindex != 3 || !slices.Equal(pool.Members, egressMembers) {
		t.Fatalf("pool entry = %#v", pool)
	}
	if direct := plane.paths[egressKey{client: egressKeyOf, id: 2}]; direct.Pool || direct.ReturnIP.IsValid() || direct.ServerPort != 9300 {
		t.Fatalf("direct entry = %#v", direct)
	}
	group := plane.groups[egressGroupOf]
	if group.ListenPort != 51820 || group.Mode != config.ModeRepeater || group.PathMask != 0b101 || group.HealthyMask != 0b101 {
		t.Fatalf("group entry = %#v", group)
	}
	if len(plane.pools) != 1 || plane.pools[0].Base != egressPool {
		t.Fatalf("observed pools = %v", plane.pools)
	}
}

func TestEgressRegistryRejectsBadFrames(t *testing.T) {
	t.Parallel()

	registry := newTestEgressRegistry(newFakeEgressPlane())
	now := time.Unix(1000, 0)
	notLocal := egressFrame(0, 9200, protocol.TransportUDP, config.ModeFailover)
	notLocal.EgressServer = netip.MustParseAddr("203.0.113.99")
	for name, frame := range map[string]protocol.ControlFrame{
		"port outside":    egressFrame(0, 8000, protocol.TransportUDP, config.ModeFailover),
		"server not here": notLocal,
	} {
		if err := registry.register(frame, now); err == nil {
			t.Fatalf("%s: register succeeded", name)
		}
	}
	if err := registry.register(notLocal, now); !errors.Is(err, errEgressNotLocal) {
		t.Fatalf("register error = %v, want %v", err, errEgressNotLocal)
	}
	if len(registry.paths) != 0 {
		t.Fatalf("registry kept %d paths", len(registry.paths))
	}
}

func TestEgressRegistryHealthFollowsTheProbeReplies(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	plane.members[dataplane.PoolKey{Base: egressPool, Transport: protocol.TransportICMP}] = egressMembers
	registry := newTestEgressRegistry(plane)
	start := time.Unix(1000, 0)
	if err := registry.register(poolFrame(0, 9200), start); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := registry.register(egressFrame(1, 9300, protocol.TransportUDP, config.ModeRepeater), start); err != nil {
		t.Fatalf("register: %v", err)
	}
	// After the first window, only the members whose probes came back stay.
	later := start.Add(egressHealthWindow + time.Second)
	if !registry.confirm(probeReply(0, protocol.TransportICMP, egressMembers[2]), later) {
		t.Fatal("confirm of a pool member failed")
	}
	if registry.confirm(probeReply(0, protocol.TransportICMP, netip.MustParseAddr("198.51.100.77")), later) {
		t.Fatal("confirm accepted a member outside the pool")
	}
	if registry.confirm(probeReply(5, protocol.TransportICMP, egressMembers[0]), later) {
		t.Fatal("confirm accepted an unknown path")
	}
	registry.sync(later)
	pool := plane.paths[egressKey{client: egressKeyOf, id: 0}]
	if !slices.Equal(pool.Members, egressMembers[2:]) {
		t.Fatalf("healthy members = %v, want %v", pool.Members, egressMembers[2:])
	}
	if group := plane.groups[egressGroupOf]; group.HealthyMask != 0b01 || group.PathMask != 0b11 {
		t.Fatalf("group = %#v, want only path 0 healthy", group)
	}
	// A direct path is healthy again with one reply, whatever the reply names.
	if !registry.confirm(probeReply(1, protocol.TransportUDP, egressServer), later) {
		t.Fatal("confirm of the direct path failed")
	}
	registry.sync(later)
	if group := plane.groups[egressGroupOf]; group.HealthyMask != 0b11 {
		t.Fatalf("group = %#v, want both paths healthy", group)
	}
}

func TestEgressRegistryWithdrawsAndExpiresPaths(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	registry := newTestEgressRegistry(plane)
	now := time.Unix(1000, 0)
	for id := range uint16(2) {
		if err := registry.register(egressFrame(id, 9200+id, protocol.TransportUDP, config.ModeFailover), now); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	withdraw := egressFrame(1, 9201, protocol.TransportUDP, config.ModeFailover)
	withdraw.LeaseSeconds = 0
	if err := registry.register(withdraw, now); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if _, ok := plane.paths[egressKey{client: egressKeyOf, id: 1}]; ok {
		t.Fatal("withdrawn path is still in the dataplane")
	}
	if group := plane.groups[egressGroupOf]; group.PathMask != 0b01 {
		t.Fatalf("group = %#v after the withdrawal", group)
	}
	registry.sync(now.Add(registrationLeaseSeconds*time.Second + time.Second))
	if len(plane.paths) != 0 || len(plane.groups) != 0 || len(registry.paths) != 0 || len(registry.groups) != 0 {
		t.Fatalf("expired state: plane %d paths %d groups, registry %d paths %d groups",
			len(plane.paths), len(plane.groups), len(registry.paths), len(registry.groups))
	}
}

func TestEgressRegistryTargets(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	plane.members[dataplane.PoolKey{Base: egressPool, Transport: protocol.TransportICMP}] = egressMembers
	registry := newTestEgressRegistry(plane)
	now := time.Unix(1000, 0)
	if err := registry.register(poolFrame(0, 9200), now); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := registry.register(egressFrame(1, 9300, protocol.TransportUDP, config.ModeRepeater), now); err != nil {
		t.Fatalf("register: %v", err)
	}
	probes := registry.probeTargets(now)
	if len(probes) != len(egressMembers)+1 {
		t.Fatalf("probe targets = %d, want one for each member and one for the direct path", len(probes))
	}
	for _, target := range probes {
		if target.pathID == 1 && target.member.IsValid() {
			t.Fatalf("direct target has member %s", target.member)
		}
	}
	seen := map[netip.Addr]bool{}
	for range egressMembers {
		targets := registry.ackTargets(egressKeyOf, now)
		if len(targets) != 2 {
			t.Fatalf("ACK targets = %d, want one for each egress path", len(targets))
		}
		for _, target := range targets {
			if target.pathID == 0 {
				seen[target.member] = true
			}
		}
	}
	if len(seen) != len(egressMembers) {
		t.Fatalf("the ACKs used %d members, want each of the %d in turn", len(seen), len(egressMembers))
	}
}

func egressFrameOf(port uint16, id uint16, mode config.Mode) protocol.ControlFrame {
	frame := egressFrame(id, 9200+id, protocol.TransportUDP, mode)
	frame.ListenPort = port
	return frame
}

func TestEgressRegistryKeepsOneGroupForEachListenPort(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	registry := newTestEgressRegistry(plane)
	now := time.Unix(1000, 0)
	second := egressGroupKey{client: egressKeyOf, listenPort: 51825}
	if err := registry.register(egressFrameOf(51820, 0, config.ModeFailover), now); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := registry.register(egressFrameOf(51825, 3, config.ModeRepeater), now); err != nil {
		t.Fatalf("register: %v", err)
	}
	if len(plane.groups) != 2 {
		t.Fatalf("plane has %d groups, want 2", len(plane.groups))
	}
	if g := plane.groups[egressGroupOf]; g.PathMask != 0b1 || g.Mode != config.ModeFailover {
		t.Fatalf("first group = %#v", g)
	}
	if g := plane.groups[second]; g.PathMask != 0b1000 || g.Mode != config.ModeRepeater {
		t.Fatalf("second group = %#v", g)
	}
	// A frame of one group leaves the other group as it is.
	if err := registry.register(egressFrameOf(51825, 4, config.ModeBalancer), now); err != nil {
		t.Fatalf("register: %v", err)
	}
	if g := plane.groups[egressGroupOf]; g.PathMask != 0b1 || g.Mode != config.ModeFailover {
		t.Fatalf("first group = %#v after a frame of the second group", g)
	}
	if g := plane.groups[second]; g.PathMask != 0b11000 || g.Mode != config.ModeBalancer {
		t.Fatalf("second group = %#v after its own frame", g)
	}
}

func TestEgressRegistryDeletesOnlyTheGroupThatLosesItsLastPath(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	registry := newTestEgressRegistry(plane)
	now := time.Unix(1000, 0)
	other := egressGroupKey{client: egressKeyOf, listenPort: 51825}
	for _, frame := range []protocol.ControlFrame{egressFrameOf(51820, 0, config.ModeFailover), egressFrameOf(51825, 1, config.ModeFailover)} {
		if err := registry.register(frame, now); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	withdraw := egressFrameOf(51825, 1, config.ModeFailover)
	withdraw.LeaseSeconds = 0
	if err := registry.register(withdraw, now); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if _, ok := plane.groups[other]; ok {
		t.Fatal("group of 51825 is still in the dataplane after its last path left")
	}
	if group := plane.groups[egressGroupOf]; group.PathMask != 0b1 {
		t.Fatalf("group of 51820 = %#v, want it kept", group)
	}
	// The path of the other group renews, so only the first group expires.
	later := now.Add(registrationLeaseSeconds*time.Second - time.Second)
	if err := registry.register(egressFrameOf(51825, 2, config.ModeFailover), later); err != nil {
		t.Fatalf("register: %v", err)
	}
	registry.sync(now.Add(registrationLeaseSeconds*time.Second + time.Second))
	if _, ok := plane.groups[egressGroupOf]; ok {
		t.Fatal("group of 51820 is still in the dataplane after its path expired")
	}
	if group := plane.groups[other]; group.PathMask != 0b100 {
		t.Fatalf("group of 51825 = %#v, want it kept", group)
	}
}

func TestEgressRegistryMovesAPathToAnotherListenPort(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	registry := newTestEgressRegistry(plane)
	now := time.Unix(1000, 0)
	moved := egressGroupKey{client: egressKeyOf, listenPort: 51825}
	for _, id := range []uint16{0, 1} {
		if err := registry.register(egressFrameOf(51820, id, config.ModeFailover), now); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	if err := registry.register(egressFrameOf(51825, 1, config.ModeRepeater), now); err != nil {
		t.Fatalf("register: %v", err)
	}
	if group := plane.groups[egressGroupOf]; group.PathMask != 0b01 {
		t.Fatalf("old group = %#v, want it to lose the path", group)
	}
	if group := plane.groups[moved]; group.PathMask != 0b10 || group.Mode != config.ModeRepeater {
		t.Fatalf("new group = %#v, want the moved path", group)
	}
	// The old group is deleted when the last path leaves it.
	if err := registry.register(egressFrameOf(51825, 0, config.ModeRepeater), now); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, ok := plane.groups[egressGroupOf]; ok {
		t.Fatal("old group is still in the dataplane without a path")
	}
	if group := plane.groups[moved]; group.PathMask != 0b11 {
		t.Fatalf("new group = %#v, want both paths", group)
	}
}

func TestEgressRegistryShowsEveryGroupOfAClientSortedByListenPort(t *testing.T) {
	t.Parallel()

	registry := newTestEgressRegistry(newFakeEgressPlane())
	now := time.Unix(1000, 0)
	for _, frame := range []protocol.ControlFrame{egressFrameOf(51825, 2, config.ModeRepeater), egressFrameOf(51820, 0, config.ModeFailover)} {
		if err := registry.register(frame, now); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	groups := registry.clients(now)[egressKeyOf]
	if len(groups) != 2 || groups[0].ListenPort != 51820 || groups[1].ListenPort != 51825 ||
		groups[0].Mode != "failover" || len(groups[0].Paths) != 1 || groups[0].Paths[0].ID != 0 ||
		groups[1].Mode != "repeater" || len(groups[1].Paths) != 1 || groups[1].Paths[0].ID != 2 {
		t.Fatalf("groups = %#v", groups)
	}
}

// reflectArrival registers an ingress reflect path of the egress client through
// a via host in a control registry, and returns the registry and the path.
func reflectArrival(t *testing.T, via netip.Addr) (*control.Registry, control.PathKey) {
	t.Helper()
	registry := control.NewRegistry(9000, 9999, registrationLeaseSeconds*time.Second)
	path := control.PathKey{Local: egressServer, Source: via, Transport: protocol.TransportUDP, ServerPort: 9000}
	_, err := registry.Register(time.Now(), control.RegistrationRequest{
		Frame: protocol.ControlFrame{
			Type:          protocol.ControlRegister,
			Transport:     protocol.TransportUDP,
			Flags:         protocol.ControlFlagIngressReflect | protocol.ControlFlagReturnIP,
			ListenPort:    51820,
			ServerPort:    9000,
			InstanceNonce: 7,
			AdvertisedIP:  egressClient,
			ReturnIP:      via,
		},
		Path: path,
	})
	if err != nil {
		t.Fatalf("register the reflect path: %v", err)
	}
	return registry, path
}

func TestEgressServiceTakesTheFramesOfAReflectPathFromItsViaHost(t *testing.T) {
	t.Parallel()

	via := netip.MustParseAddr("203.0.113.40")
	plane := newFakeEgressPlane()
	plane.members[dataplane.PoolKey{Base: egressPool, Transport: protocol.TransportICMP}] = egressMembers
	service := &egressService{registry: newTestEgressRegistry(plane), logger: discardLogger}
	registry, path := reflectArrival(t, via)

	register := poolFrame(0, 9200)
	if !arrivedOnReflectPath(registry, register, path, time.Now()) {
		t.Fatal("the EGRESS_REGISTER did not arrive on the reflect path")
	}
	if !service.handle(register, via, true) {
		t.Fatal("handle did not take the EGRESS_REGISTER")
	}
	egress := service.registry.paths[egressKey{client: egressKeyOf, id: 0}]
	if egress == nil {
		t.Fatal("the reflected EGRESS_REGISTER was refused")
	}
	reply := probeReply(0, protocol.TransportICMP, egressMembers[1])
	if !service.handle(reply, via, arrivedOnReflectPath(registry, reply, path, time.Now())) {
		t.Fatal("handle did not take the PROBE_REPLY")
	}
	if _, ok := egress.replies[egressMembers[1]]; !ok {
		t.Fatal("the reflected PROBE_REPLY was not confirmed")
	}
}

func TestEgressServiceRefusesTheFramesOfAnUnknownSource(t *testing.T) {
	t.Parallel()

	stranger := netip.MustParseAddr("203.0.113.41")
	plane := newFakeEgressPlane()
	plane.members[dataplane.PoolKey{Base: egressPool, Transport: protocol.TransportICMP}] = egressMembers
	service := &egressService{registry: newTestEgressRegistry(plane), logger: discardLogger}
	registry, path := reflectArrival(t, netip.MustParseAddr("203.0.113.40"))
	path.Source = stranger

	register := poolFrame(0, 9200)
	if arrivedOnReflectPath(registry, register, path, time.Now()) {
		t.Fatal("a frame from an unknown source arrived on the reflect path")
	}
	other := register
	other.InstanceNonce = 8
	if arrivedOnReflectPath(registry, other, control.PathKey{Local: egressServer, Source: netip.MustParseAddr("203.0.113.40"), Transport: protocol.TransportUDP, ServerPort: 9000}, time.Now()) {
		t.Fatal("a frame of another instance arrived on the reflect path")
	}
	if !service.handle(register, stranger, false) {
		t.Fatal("handle did not take the EGRESS_REGISTER")
	}
	if len(service.registry.paths) != 0 {
		t.Fatal("the EGRESS_REGISTER from an unknown source was kept")
	}
	// A path that the advertised IP registers ignores a reply from a stranger.
	if !service.handle(register, egressClient, false) {
		t.Fatal("handle did not take the EGRESS_REGISTER")
	}
	egress := service.registry.paths[egressKey{client: egressKeyOf, id: 0}]
	if !service.handle(probeReply(0, protocol.TransportICMP, egressMembers[1]), stranger, false) {
		t.Fatal("handle did not take the PROBE_REPLY")
	}
	if len(egress.replies) != 0 {
		t.Fatal("the PROBE_REPLY from an unknown source was confirmed")
	}
}

func TestEgressServiceStillTakesTheFramesFromTheAdvertisedIP(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	plane.members[dataplane.PoolKey{Base: egressPool, Transport: protocol.TransportICMP}] = egressMembers
	service := &egressService{registry: newTestEgressRegistry(plane), logger: discardLogger}

	if !service.handle(poolFrame(0, 9200), egressClient, false) {
		t.Fatal("handle did not take the EGRESS_REGISTER")
	}
	egress := service.registry.paths[egressKey{client: egressKeyOf, id: 0}]
	if egress == nil {
		t.Fatal("the EGRESS_REGISTER from the advertised IP was refused")
	}
	if !service.handle(probeReply(0, protocol.TransportICMP, egressMembers[2]), egressClient, false) {
		t.Fatal("handle did not take the PROBE_REPLY")
	}
	if _, ok := egress.replies[egressMembers[2]]; !ok {
		t.Fatal("the PROBE_REPLY from the advertised IP was not confirmed")
	}
}
