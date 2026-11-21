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

type fakeDownPlane struct {
	paths   map[downKey]dataplane.DownPathEntry
	groups  map[dataplane.ClientKey]dataplane.DownGroupEntry
	members map[dataplane.PoolKey][]netip.Addr
	pools   []dataplane.PoolKey
}

func newFakeDownPlane() *fakeDownPlane {
	return &fakeDownPlane{
		paths:   map[downKey]dataplane.DownPathEntry{},
		groups:  map[dataplane.ClientKey]dataplane.DownGroupEntry{},
		members: map[dataplane.PoolKey][]netip.Addr{},
	}
}

func (f *fakeDownPlane) SetServerDownPath(entry dataplane.DownPathEntry) error {
	f.paths[downKey{client: entry.Client, id: entry.PathID}] = entry
	return nil
}

func (f *fakeDownPlane) DeleteServerDownPath(client dataplane.ClientKey, id uint16) error {
	delete(f.paths, downKey{client: client, id: id})
	return nil
}

func (f *fakeDownPlane) SetServerDownGroup(entry dataplane.DownGroupEntry) error {
	f.groups[entry.Client] = entry
	return nil
}

func (f *fakeDownPlane) DeleteServerDownGroup(client dataplane.ClientKey) error {
	delete(f.groups, client)
	return nil
}

func (f *fakeDownPlane) ObservePool(base netip.Addr, _ uint8, transport protocol.TransportID) error {
	f.pools = append(f.pools, dataplane.PoolKey{Base: base, Transport: transport})
	return nil
}

func (f *fakeDownPlane) PoolMembers(key dataplane.PoolKey) []netip.Addr {
	return f.members[key]
}

var (
	downClient  = netip.MustParseAddr("192.0.2.10")
	downServer  = netip.MustParseAddr("203.0.113.5")
	downPool    = netip.MustParseAddr("198.51.100.0")
	downMembers = []netip.Addr{netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2"), netip.MustParseAddr("198.51.100.3")}
	downKeyOf   = dataplane.ClientKey{AdvertisedIP: downClient, InstanceNonce: 7}
)

func newTestDownRegistry(plane *fakeDownPlane) *downRegistry {
	locate := func(server, destination netip.Addr) (int, error) {
		if server != downServer {
			return 0, errDownNotLocal
		}
		return 3, nil
	}
	return newDownRegistry(config.PortRange{First: 9000, Last: 9999}, plane, locate, discardLogger)
}

func downFrame(id uint16, port uint16, transport protocol.TransportID, mode config.Mode) protocol.ControlFrame {
	return protocol.ControlFrame{
		Type:          protocol.ControlDownRegister,
		Transport:     transport,
		PathID:        id,
		ListenPort:    51820,
		ServerPort:    port,
		LeaseSeconds:  registrationLeaseSeconds,
		InstanceNonce: 7,
		AdvertisedIP:  downClient,
		DownMode:      uint8(mode),
		DownServer:    downServer,
	}
}

func poolFrame(id uint16, port uint16) protocol.ControlFrame {
	frame := downFrame(id, port, protocol.TransportICMP, config.ModeBurst)
	frame.Flags = protocol.ControlFlagReturnPool | protocol.ControlFlagBalancePerPacket
	frame.ReturnIP = downPool
	frame.ReturnPrefix = 28
	return frame
}

func probeReply(id uint16, transport protocol.TransportID, member netip.Addr) protocol.ControlFrame {
	return protocol.ControlFrame{
		Type:          protocol.ControlProbeReply,
		Transport:     transport,
		Flags:         protocol.ControlFlagDownPath | protocol.ControlFlagReturnIP,
		PathID:        id,
		InstanceNonce: 7,
		AdvertisedIP:  downClient,
		ReturnIP:      member,
	}
}

func TestDownRegistryKeepsADownPathAndItsGroup(t *testing.T) {
	t.Parallel()

	plane := newFakeDownPlane()
	plane.members[dataplane.PoolKey{Base: downPool, Transport: protocol.TransportICMP}] = downMembers
	registry := newTestDownRegistry(plane)
	now := time.Unix(1000, 0)
	if err := registry.register(poolFrame(0, 9200), downClient, now); err != nil {
		t.Fatalf("register pool path: %v", err)
	}
	if err := registry.register(downFrame(2, 9300, protocol.TransportUDP, config.ModeBurst), downClient, now); err != nil {
		t.Fatalf("register direct path: %v", err)
	}
	pool := plane.paths[downKey{client: downKeyOf, id: 0}]
	if !pool.Pool || !pool.PerPacket || pool.Ifindex != 3 || !slices.Equal(pool.Members, downMembers) {
		t.Fatalf("pool entry = %#v", pool)
	}
	if direct := plane.paths[downKey{client: downKeyOf, id: 2}]; direct.Pool || direct.ReturnIP.IsValid() || direct.ServerPort != 9300 {
		t.Fatalf("direct entry = %#v", direct)
	}
	group := plane.groups[downKeyOf]
	if group.ListenPort != 51820 || group.Mode != config.ModeBurst || group.PathMask != 0b101 || group.HealthyMask != 0b101 {
		t.Fatalf("group entry = %#v", group)
	}
	if len(plane.pools) != 1 || plane.pools[0].Base != downPool {
		t.Fatalf("observed pools = %v", plane.pools)
	}
}

func TestDownRegistryRejectsBadFrames(t *testing.T) {
	t.Parallel()

	registry := newTestDownRegistry(newFakeDownPlane())
	now := time.Unix(1000, 0)
	notLocal := downFrame(0, 9200, protocol.TransportUDP, config.ModeFallback)
	notLocal.DownServer = netip.MustParseAddr("203.0.113.99")
	for name, test := range map[string]struct {
		frame  protocol.ControlFrame
		source netip.Addr
	}{
		"other source":    {frame: downFrame(0, 9200, protocol.TransportUDP, config.ModeFallback), source: netip.MustParseAddr("192.0.2.11")},
		"port outside":    {frame: downFrame(0, 8000, protocol.TransportUDP, config.ModeFallback), source: downClient},
		"server not here": {frame: notLocal, source: downClient},
	} {
		if err := registry.register(test.frame, test.source, now); err == nil {
			t.Fatalf("%s: register succeeded", name)
		}
	}
	if err := registry.register(notLocal, downClient, now); !errors.Is(err, errDownNotLocal) {
		t.Fatalf("register error = %v, want %v", err, errDownNotLocal)
	}
	if len(registry.paths) != 0 {
		t.Fatalf("registry kept %d paths", len(registry.paths))
	}
}

func TestDownRegistryHealthFollowsTheProbeReplies(t *testing.T) {
	t.Parallel()

	plane := newFakeDownPlane()
	plane.members[dataplane.PoolKey{Base: downPool, Transport: protocol.TransportICMP}] = downMembers
	registry := newTestDownRegistry(plane)
	start := time.Unix(1000, 0)
	if err := registry.register(poolFrame(0, 9200), downClient, start); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := registry.register(downFrame(1, 9300, protocol.TransportUDP, config.ModeBurst), downClient, start); err != nil {
		t.Fatalf("register: %v", err)
	}
	// After the first window, only the members whose probes came back stay.
	later := start.Add(downHealthWindow + time.Second)
	if !registry.confirm(probeReply(0, protocol.TransportICMP, downMembers[2]), later) {
		t.Fatal("confirm of a pool member failed")
	}
	if registry.confirm(probeReply(0, protocol.TransportICMP, netip.MustParseAddr("198.51.100.77")), later) {
		t.Fatal("confirm accepted a member outside the pool")
	}
	if registry.confirm(probeReply(5, protocol.TransportICMP, downMembers[0]), later) {
		t.Fatal("confirm accepted an unknown path")
	}
	registry.sync(later)
	pool := plane.paths[downKey{client: downKeyOf, id: 0}]
	if !slices.Equal(pool.Members, downMembers[2:]) {
		t.Fatalf("healthy members = %v, want %v", pool.Members, downMembers[2:])
	}
	if group := plane.groups[downKeyOf]; group.HealthyMask != 0b01 || group.PathMask != 0b11 {
		t.Fatalf("group = %#v, want only path 0 healthy", group)
	}
	// A direct path is healthy again with one reply, whatever the reply names.
	if !registry.confirm(probeReply(1, protocol.TransportUDP, downServer), later) {
		t.Fatal("confirm of the direct path failed")
	}
	registry.sync(later)
	if group := plane.groups[downKeyOf]; group.HealthyMask != 0b11 {
		t.Fatalf("group = %#v, want both paths healthy", group)
	}
}

func TestDownRegistryWithdrawsAndExpiresPaths(t *testing.T) {
	t.Parallel()

	plane := newFakeDownPlane()
	registry := newTestDownRegistry(plane)
	now := time.Unix(1000, 0)
	for id := range uint16(2) {
		if err := registry.register(downFrame(id, 9200+id, protocol.TransportUDP, config.ModeFallback), downClient, now); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	withdraw := downFrame(1, 9201, protocol.TransportUDP, config.ModeFallback)
	withdraw.LeaseSeconds = 0
	if err := registry.register(withdraw, downClient, now); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if _, ok := plane.paths[downKey{client: downKeyOf, id: 1}]; ok {
		t.Fatal("withdrawn path is still in the dataplane")
	}
	if group := plane.groups[downKeyOf]; group.PathMask != 0b01 {
		t.Fatalf("group = %#v after the withdrawal", group)
	}
	registry.sync(now.Add(registrationLeaseSeconds*time.Second + time.Second))
	if len(plane.paths) != 0 || len(plane.groups) != 0 || len(registry.paths) != 0 || len(registry.groups) != 0 {
		t.Fatalf("expired state: plane %d paths %d groups, registry %d paths %d groups",
			len(plane.paths), len(plane.groups), len(registry.paths), len(registry.groups))
	}
}

func TestDownRegistryTargets(t *testing.T) {
	t.Parallel()

	plane := newFakeDownPlane()
	plane.members[dataplane.PoolKey{Base: downPool, Transport: protocol.TransportICMP}] = downMembers
	registry := newTestDownRegistry(plane)
	now := time.Unix(1000, 0)
	if err := registry.register(poolFrame(0, 9200), downClient, now); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := registry.register(downFrame(1, 9300, protocol.TransportUDP, config.ModeBurst), downClient, now); err != nil {
		t.Fatalf("register: %v", err)
	}
	probes := registry.probeTargets(now)
	if len(probes) != len(downMembers)+1 {
		t.Fatalf("probe targets = %d, want one for each member and one for the direct path", len(probes))
	}
	for _, target := range probes {
		if target.pathID == 1 && target.member.IsValid() {
			t.Fatalf("direct target has member %s", target.member)
		}
	}
	seen := map[netip.Addr]bool{}
	for range downMembers {
		targets := registry.ackTargets(downKeyOf, now)
		if len(targets) != 2 {
			t.Fatalf("ACK targets = %d, want one for each down path", len(targets))
		}
		for _, target := range targets {
			if target.pathID == 0 {
				seen[target.member] = true
			}
		}
	}
	if len(seen) != len(downMembers) {
		t.Fatalf("the ACKs used %d members, want each of the %d in turn", len(seen), len(downMembers))
	}
}
