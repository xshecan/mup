package app

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/protocol"
)

type fakeEgressPlane struct {
	paths   map[egressKey]dataplane.EgressPathEntry
	groups  map[dataplane.ClientKey]dataplane.EgressGroupEntry
	members map[dataplane.PoolKey][]netip.Addr
	pools   []dataplane.PoolKey
}

func newFakeEgressPlane() *fakeEgressPlane {
	return &fakeEgressPlane{
		paths:   map[egressKey]dataplane.EgressPathEntry{},
		groups:  map[dataplane.ClientKey]dataplane.EgressGroupEntry{},
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
	f.groups[entry.Client] = entry
	return nil
}

func (f *fakeEgressPlane) DeleteServerEgressGroup(client dataplane.ClientKey) error {
	delete(f.groups, client)
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
	if err := registry.register(poolFrame(0, 9200), egressClient, now); err != nil {
		t.Fatalf("register pool path: %v", err)
	}
	if err := registry.register(egressFrame(2, 9300, protocol.TransportUDP, config.ModeRepeater), egressClient, now); err != nil {
		t.Fatalf("register direct path: %v", err)
	}
	pool := plane.paths[egressKey{client: egressKeyOf, id: 0}]
	if !pool.Pool || !pool.PerPacket || pool.Ifindex != 3 || !slices.Equal(pool.Members, egressMembers) {
		t.Fatalf("pool entry = %#v", pool)
	}
	if direct := plane.paths[egressKey{client: egressKeyOf, id: 2}]; direct.Pool || direct.ReturnIP.IsValid() || direct.ServerPort != 9300 {
		t.Fatalf("direct entry = %#v", direct)
	}
	group := plane.groups[egressKeyOf]
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
	for name, test := range map[string]struct {
		frame  protocol.ControlFrame
		source netip.Addr
	}{
		"other source":    {frame: egressFrame(0, 9200, protocol.TransportUDP, config.ModeFailover), source: netip.MustParseAddr("192.0.2.11")},
		"port outside":    {frame: egressFrame(0, 8000, protocol.TransportUDP, config.ModeFailover), source: egressClient},
		"server not here": {frame: notLocal, source: egressClient},
	} {
		if err := registry.register(test.frame, test.source, now); err == nil {
			t.Fatalf("%s: register succeeded", name)
		}
	}
	if err := registry.register(notLocal, egressClient, now); !errors.Is(err, errEgressNotLocal) {
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
	if err := registry.register(poolFrame(0, 9200), egressClient, start); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := registry.register(egressFrame(1, 9300, protocol.TransportUDP, config.ModeRepeater), egressClient, start); err != nil {
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
	if group := plane.groups[egressKeyOf]; group.HealthyMask != 0b01 || group.PathMask != 0b11 {
		t.Fatalf("group = %#v, want only path 0 healthy", group)
	}
	// A direct path is healthy again with one reply, whatever the reply names.
	if !registry.confirm(probeReply(1, protocol.TransportUDP, egressServer), later) {
		t.Fatal("confirm of the direct path failed")
	}
	registry.sync(later)
	if group := plane.groups[egressKeyOf]; group.HealthyMask != 0b11 {
		t.Fatalf("group = %#v, want both paths healthy", group)
	}
}

func TestEgressRegistryWithdrawsAndExpiresPaths(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	registry := newTestEgressRegistry(plane)
	now := time.Unix(1000, 0)
	for id := range uint16(2) {
		if err := registry.register(egressFrame(id, 9200+id, protocol.TransportUDP, config.ModeFailover), egressClient, now); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	withdraw := egressFrame(1, 9201, protocol.TransportUDP, config.ModeFailover)
	withdraw.LeaseSeconds = 0
	if err := registry.register(withdraw, egressClient, now); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if _, ok := plane.paths[egressKey{client: egressKeyOf, id: 1}]; ok {
		t.Fatal("withdrawn path is still in the dataplane")
	}
	if group := plane.groups[egressKeyOf]; group.PathMask != 0b01 {
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
	if err := registry.register(poolFrame(0, 9200), egressClient, now); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := registry.register(egressFrame(1, 9300, protocol.TransportUDP, config.ModeRepeater), egressClient, now); err != nil {
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
