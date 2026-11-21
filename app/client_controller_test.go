package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/xshecan/mup/api"
	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/protocol"
)

var discardLogger = log.New(io.Discard, "", 0)

type fakeClientDataplane struct {
	mu         sync.Mutex
	log        []string
	paths      map[int]dataplane.PathSettings
	mask       uint8
	generation uint32
	groups     map[uint16]dataplane.GroupSettings
	attached   []int
	routes     []dataplane.ClientRoute
}

func (f *fakeClientDataplane) record(entry string) {
	f.log = append(f.log, entry)
}

func (f *fakeClientDataplane) UpdatePathState(mask uint8, generation uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("state")
	f.mask, f.generation = mask, generation
	return nil
}

func (f *fakeClientDataplane) SetPath(slot int, path dataplane.PathSettings) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("set")
	f.paths[slot] = path
	return nil
}

func (f *fakeClientDataplane) ClearPath(slot int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("clear")
	delete(f.paths, slot)
	return nil
}

func (f *fakeClientDataplane) SetDownPath(slot int, path *dataplane.DownPathSettings) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if path == nil {
		f.record(fmt.Sprintf("down %d clear", slot))
		return nil
	}
	f.record(fmt.Sprintf("down %d %s:%d", slot, path.Server, path.ServerPort))
	return nil
}

func (f *fakeClientDataplane) DownPathsSeen() ([dataplane.MaxDownPaths]time.Duration, error) {
	var seen [dataplane.MaxDownPaths]time.Duration
	for slot := range seen {
		seen[slot] = -1
	}
	return seen, nil
}

func (f *fakeClientDataplane) SetGroup(group dataplane.GroupSettings) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("group")
	f.groups[group.ListenPort] = group
	return nil
}

func (f *fakeClientDataplane) AttachClient(ifindexes []int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attached = append(f.attached, ifindexes...)
	return nil
}

func (f *fakeClientDataplane) Snapshot() (dataplane.StatsSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	snapshot := dataplane.StatsSnapshot{HealthyMask: uint32(f.mask), PathGeneration: f.generation, ClientRoutes: uint64(len(f.routes))}
	snapshot.Drops[protocol.DropNoPath] = 4
	return snapshot, nil
}

func (f *fakeClientDataplane) ClientRoutes() ([]dataplane.ClientRoute, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.routes), nil
}

type fakePathConn struct {
	closed chan struct{}
	once   sync.Once
}

func newFakePathConn() *fakePathConn {
	return &fakePathConn{closed: make(chan struct{})}
}

func (s *fakePathConn) Run(ctx context.Context, _ probeReporter) error {
	<-ctx.Done()
	_ = s.Close()
	return ctx.Err()
}

func (s *fakePathConn) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

type controllerFixture struct {
	controller    *clientController
	dataplane     *fakeClientDataplane
	conns         map[config.Path]*fakePathConn
	registrations map[int]pathRegistration
}

func newControllerFixture(t *testing.T, paths ...string) controllerFixture {
	t.Helper()
	return newGroupsFixture(t, testGroup(t, 51820, config.ModeFallback, paths...))
}

func testGroup(t *testing.T, listenPort uint16, mode config.Mode, paths ...string) config.Group {
	t.Helper()
	group := config.Group{ListenPort: listenPort, Mode: mode}
	for _, raw := range paths {
		path, err := config.ParsePath(raw)
		if err != nil {
			t.Fatalf("ParsePath(%q): %v", raw, err)
		}
		group.Paths = append(group.Paths, path)
	}
	return group
}

func newGroupsFixture(t *testing.T, groups ...config.Group) controllerFixture {
	t.Helper()
	client := config.Client{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), Groups: groups}
	plan, err := buildPlan(config.App{Client: &client}, 42, fakeResolver{catchAll: 2})
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	fake := &fakeClientDataplane{paths: map[int]dataplane.PathSettings{}, groups: map[uint16]dataplane.GroupSettings{}}
	fixture := controllerFixture{
		dataplane:     fake,
		conns:         map[config.Path]*fakePathConn{},
		registrations: map[int]pathRegistration{},
	}
	resolver := fakeResolver{routes: map[string]route{
		"198.51.100.3%":     {ifindex: 3},
		"198.51.100.4%":     {ifindex: 5},
		"198.51.100.4%eth4": {ifindex: 4},
	}}
	open := func(registration pathRegistration) (pathConn, error) {
		conn := newFakePathConn()
		fixture.conns[registration.path] = conn
		fixture.registrations[int(registration.pathID)] = registration
		return conn, nil
	}
	fixture.controller = newClientController(client, *plan.client, fake, resolver, pathOpener(open), time.Unix(100, 0), discardLogger)
	fixture.controller.interfaceName = func(ifindex int) string { return "if" + string(rune('0'+ifindex)) }
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := fixture.controller.start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	return fixture
}

func (f controllerFixture) reply(t *testing.T, slot int, sequence uint32) {
	t.Helper()
	f.controller.mu.Lock()
	epoch := f.controller.slots[slot].epoch
	f.controller.mu.Unlock()
	probe := pathProbeResult{slot: slot, epoch: epoch, sequence: sequence, sentAt: time.Now(), result: registerAcked}
	if err := f.controller.handleProbe(probe); err != nil {
		t.Fatalf("handleProbe: %v", err)
	}
}

func statusOf(err error) int {
	var failure *apiError
	if errors.As(err, &failure) {
		return failure.status
	}
	return 0
}

func TestControllerStartsWithHealthyPaths(t *testing.T) {
	t.Parallel()

	fixture := newControllerFixture(t, "198.51.100.1:5000/udp", "198.51.100.2:5000/icmp")
	if fixture.dataplane.mask != 0b11 {
		t.Fatalf("mask = %#b, want 0b11", fixture.dataplane.mask)
	}
	paths, err := fixture.controller.Paths()
	if err != nil || len(paths) != 2 {
		t.Fatalf("Paths = %v, %v", paths, err)
	}
	if !paths[0].InUse || paths[1].InUse {
		t.Fatalf("fallback in-use flags = %v, %v, want true, false", paths[0].InUse, paths[1].InUse)
	}
}

func TestAddPathUsesAFreeSlotAndWaitsForTheFirstACK(t *testing.T) {
	t.Parallel()

	fixture := newControllerFixture(t, "198.51.100.1:5000/udp", "198.51.100.2:5000/icmp")
	added, err := fixture.controller.AddPath("198.51.100.4%eth4:5000/icmp", 0)
	if err != nil {
		t.Fatalf("AddPath: %v", err)
	}
	if added.ID != 2 || added.Priority != 2 || added.Healthy || added.Interface != "eth4" {
		t.Fatalf("added path = %#v", added)
	}
	settings := fixture.dataplane.paths[2]
	if settings.Ifindex != 4 || settings.SourceIP != netip.MustParseAddr("192.0.2.10") || settings.Transport != protocol.TransportICMP {
		t.Fatalf("path settings = %#v", settings)
	}
	if !slices.Contains(fixture.dataplane.attached, 4) {
		t.Fatalf("attached = %v, want 4", fixture.dataplane.attached)
	}
	if fixture.dataplane.mask != 0b11 {
		t.Fatalf("mask before the first ACK = %#b, want 0b11", fixture.dataplane.mask)
	}
	if got := fixture.dataplane.groups[51820].PathMask; got != 0b111 {
		t.Fatalf("group mask = %#b, want 0b111", got)
	}
	fixture.reply(t, 2, 1)
	if fixture.dataplane.mask != 0b111 {
		t.Fatalf("mask after the first ACK = %#b, want 0b111", fixture.dataplane.mask)
	}
}

func TestAddPathRejectsInvalidPaths(t *testing.T) {
	t.Parallel()

	fixture := newControllerFixture(t, "198.51.100.1:5000/udp")
	tests := []struct {
		path string
		want int
	}{
		{path: "not a path", want: http.StatusBadRequest},
		{path: "198.51.100.1:5000/udp", want: http.StatusConflict},
		{path: "198.51.100.9:5000/udp", want: http.StatusBadRequest},
	}
	for _, test := range tests {
		if _, err := fixture.controller.AddPath(test.path, 0); statusOf(err) != test.want {
			t.Fatalf("AddPath(%q) error = %v, want status %d", test.path, err, test.want)
		}
	}
}

func TestAddPathRejectsANinthPath(t *testing.T) {
	t.Parallel()

	fixture := newControllerFixture(t,
		"198.51.100.3:5000/udp", "198.51.100.3:5000/icmp",
		"198.51.100.4%eth4:5000/udp", "198.51.100.4%eth4:5000/icmp",
		"198.51.100.3%eth4:5000/udp", "198.51.100.3%eth4:5000/icmp",
		"198.51.100.4:5000/udp",
	)
	if _, err := fixture.controller.AddPath("198.51.100.4:5000/icmp", 0); err != nil {
		t.Fatalf("AddPath of the eighth path: %v", err)
	}
	if _, err := fixture.controller.AddPath("198.51.100.3%eth9:5000/udp", 0); statusOf(err) != http.StatusConflict {
		t.Fatalf("AddPath of a ninth path error = %v, want status 409", err)
	}
}

func TestRemovePathClearsHealthBeforeConfiguration(t *testing.T) {
	t.Parallel()

	fixture := newControllerFixture(t, "198.51.100.1:5000/udp", "198.51.100.2:5000/icmp")
	path, _ := config.ParsePath("198.51.100.1:5000/udp")
	fixture.dataplane.log = nil
	if err := fixture.controller.RemovePath(0); err != nil {
		t.Fatalf("RemovePath: %v", err)
	}
	if !slices.Equal(fixture.dataplane.log, []string{"state", "group", "clear"}) {
		t.Fatalf("dataplane updates = %v, want [state group clear]", fixture.dataplane.log)
	}
	if got := fixture.dataplane.groups[51820].PathMask; got != 0b10 {
		t.Fatalf("group mask = %#b, want 0b10", got)
	}
	if fixture.dataplane.mask != 0b10 {
		t.Fatalf("mask = %#b, want 0b10", fixture.dataplane.mask)
	}
	select {
	case <-fixture.conns[path].closed:
	case <-time.After(time.Second):
		t.Fatal("the removed path kept its control socket")
	}
	if err := fixture.controller.RemovePath(0); statusOf(err) != http.StatusNotFound {
		t.Fatalf("second RemovePath error = %v, want status 404", err)
	}
	if err := fixture.controller.RemovePath(1); statusOf(err) != http.StatusConflict {
		t.Fatalf("RemovePath of the last path error = %v, want status 409", err)
	}
}

func TestReusedSlotIgnoresProbesOfTheOldPath(t *testing.T) {
	t.Parallel()

	fixture := newControllerFixture(t, "198.51.100.1:5000/udp", "198.51.100.2:5000/icmp")
	fixture.controller.mu.Lock()
	oldEpoch := fixture.controller.slots[1].epoch
	fixture.controller.mu.Unlock()
	if err := fixture.controller.RemovePath(1); err != nil {
		t.Fatalf("RemovePath: %v", err)
	}
	added, err := fixture.controller.AddPath("198.51.100.3:5000/udp", 0)
	if err != nil || added.ID != 1 {
		t.Fatalf("AddPath = %#v, %v, want slot 1", added, err)
	}
	stale := pathProbeResult{slot: 1, epoch: oldEpoch, sequence: 1, sentAt: time.Now(), result: registerAcked}
	if err := fixture.controller.handleProbe(stale); err != nil {
		t.Fatalf("handleProbe: %v", err)
	}
	if fixture.dataplane.mask != 0b1 {
		t.Fatalf("a stale probe changed the mask to %#b", fixture.dataplane.mask)
	}
}

func TestSetModeChangesInUsePaths(t *testing.T) {
	t.Parallel()

	fixture := newControllerFixture(t, "198.51.100.1:5000/udp", "198.51.100.2:5000/icmp")
	if err := fixture.controller.SetMode("sideways", 0); statusOf(err) != http.StatusBadRequest {
		t.Fatalf("SetMode(sideways) error = %v, want status 400", err)
	}
	if err := fixture.controller.SetMode("burst", 0); err != nil {
		t.Fatalf("SetMode: %v", err)
	}
	status, err := fixture.controller.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if fixture.dataplane.groups[51820].Mode != config.ModeBurst || status.Client.Groups[0].Mode != "burst" {
		t.Fatalf("mode = %v/%q, want burst", fixture.dataplane.groups[51820].Mode, status.Client.Groups[0].Mode)
	}
	if got := fixture.dataplane.groups[51820].PathMask; got != 0b11 {
		t.Fatalf("SetMode changed the group mask to %#b", got)
	}
	for _, path := range status.Client.Paths {
		if !path.InUse {
			t.Fatalf("burst mode does not use path %d", path.ID)
		}
	}
	if status.Drops[protocol.DropNoPath-1].Count != 4 || status.Drops[protocol.DropNoPath-1].Name != "NO_PATH" {
		t.Fatalf("drops = %#v", status.Drops)
	}
}

func twoGroupsFixture(t *testing.T) controllerFixture {
	t.Helper()
	first := testGroup(t, 51820, config.ModeFallback, "198.51.100.1:5000/udp", "198.51.100.2:5000/icmp")
	second := testGroup(t, 51821, config.ModeBurst, "203.0.113.1:6000/udp via 1.1.1.1", "203.0.113.2:6000/udp via 1.1.1.1")
	return newGroupsFixture(t, first, second)
}

func TestEachPathRegistersWithTheValuesOfItsGroup(t *testing.T) {
	t.Parallel()

	fixture := twoGroupsFixture(t)
	first, second := fixture.registrations[1], fixture.registrations[2]
	if first.listenPort != 51820 || first.returnIP.IsValid() || first.path.ServerPort != 5000 {
		t.Fatalf("first group registration = %#v", first)
	}
	if second.listenPort != 51821 || second.returnIP != netip.MustParseAddr("1.1.1.1") || second.path.ServerPort != 6000 {
		t.Fatalf("second group registration = %#v", second)
	}
	if first.advertisedIP != second.advertisedIP || first.nonce != second.nonce {
		t.Fatalf("the groups use different client keys: %#v, %#v", first, second)
	}
}

func TestInUsePathsFollowTheModeOfEachGroup(t *testing.T) {
	t.Parallel()

	fixture := twoGroupsFixture(t)
	paths, err := fixture.controller.Paths()
	if err != nil {
		t.Fatalf("Paths: %v", err)
	}
	var inUse []int
	for _, path := range paths {
		if path.InUse {
			inUse = append(inUse, path.ID)
		}
	}
	if !slices.Equal(inUse, []int{0, 2, 3}) {
		t.Fatalf("in-use paths = %v, want [0 2 3]", inUse)
	}
}

func TestSetModeChangesOneGroup(t *testing.T) {
	t.Parallel()

	fixture := twoGroupsFixture(t)
	if err := fixture.controller.SetMode("burst", 0); statusOf(err) != http.StatusBadRequest {
		t.Fatalf("SetMode without a group error = %v, want status 400", err)
	}
	if err := fixture.controller.SetMode("burst", 9); statusOf(err) != http.StatusNotFound {
		t.Fatalf("SetMode with an unknown group error = %v, want status 404", err)
	}
	if err := fixture.controller.SetMode("balancer", 51820); err != nil {
		t.Fatalf("SetMode: %v", err)
	}
	if got := fixture.dataplane.groups[51820].Mode; got != config.ModeBalancer {
		t.Fatalf("first group mode = %v", got)
	}
	if _, exists := fixture.dataplane.groups[51821]; exists {
		t.Fatal("SetMode wrote the other group")
	}
}

func TestAddPathGoesToTheNamedGroup(t *testing.T) {
	t.Parallel()

	fixture := twoGroupsFixture(t)
	if _, err := fixture.controller.AddPath("198.51.100.3:7000/udp", 0); statusOf(err) != http.StatusBadRequest {
		t.Fatalf("AddPath without a group error = %v, want status 400", err)
	}
	if _, err := fixture.controller.AddPath("198.51.100.3:7000/udp", 9); statusOf(err) != http.StatusNotFound {
		t.Fatalf("AddPath with an unknown group error = %v, want status 404", err)
	}
	if _, err := fixture.controller.AddPath("203.0.113.1:6000/icmp", 51820); statusOf(err) != http.StatusConflict {
		t.Fatalf("AddPath of a server of another group error = %v, want status 409", err)
	}
	added, err := fixture.controller.AddPath("198.51.100.3:7000/udp via 192.0.2.77", 51821)
	if err != nil {
		t.Fatalf("AddPath: %v", err)
	}
	if added.ID != 4 || added.ListenPort != 51821 || added.Port != 7000 || added.ReturnIP != "192.0.2.77" {
		t.Fatalf("added path = %#v", added)
	}
	if got := fixture.dataplane.groups[51821]; got.PathMask != 0b11100 || got.Mode != config.ModeBurst {
		t.Fatalf("group settings = %#v", got)
	}
	if got := fixture.dataplane.paths[4]; got.ReturnIP != netip.MustParseAddr("192.0.2.77") {
		t.Fatalf("path settings = %#v", got)
	}
	if got := fixture.registrations[4]; got.listenPort != 51821 || got.returnIP != netip.MustParseAddr("192.0.2.77") {
		t.Fatalf("registration = %#v", got)
	}
}

func TestAddPathKeepsTheReturnPool(t *testing.T) {
	t.Parallel()

	fixture := newControllerFixture(t, "198.51.100.1:5000/udp")
	added, err := fixture.controller.AddPath("198.51.100.3:5000/udp via 203.0.113.16/28 balance per-packet", 0)
	if err != nil {
		t.Fatalf("AddPath: %v", err)
	}
	if added.ReturnIP != "203.0.113.16/28" {
		t.Fatalf("added path return = %q, want the pool", added.ReturnIP)
	}
	got := fixture.dataplane.paths[added.ID]
	if got.ReturnIP != netip.MustParseAddr("203.0.113.16") || got.ReturnPrefix != 28 || got.Balance != config.BalancePerPacket {
		t.Fatalf("path settings = %#v, want the pool 203.0.113.16/28 with per-packet balance", got)
	}
}

func TestRemovePathKeepsTheLastPathOfEachGroup(t *testing.T) {
	t.Parallel()

	fixture := newGroupsFixture(t,
		testGroup(t, 51820, config.ModeFallback, "198.51.100.1:5000/udp"),
		testGroup(t, 51821, config.ModeFallback, "203.0.113.1:6000/udp", "203.0.113.2:6000/udp"),
	)
	if err := fixture.controller.RemovePath(0); statusOf(err) != http.StatusConflict {
		t.Fatalf("RemovePath of the last path of a group error = %v, want status 409", err)
	}
	if err := fixture.controller.RemovePath(1); err != nil {
		t.Fatalf("RemovePath: %v", err)
	}
	if got := fixture.dataplane.groups[51821].PathMask; got != 0b100 {
		t.Fatalf("group mask = %#b, want 0b100", got)
	}
	if err := fixture.controller.RemovePath(2); statusOf(err) != http.StatusConflict {
		t.Fatalf("RemovePath of the new last path error = %v, want status 409", err)
	}
}

func TestStatusReportsEachGroup(t *testing.T) {
	t.Parallel()

	fixture := twoGroupsFixture(t)
	fixture.dataplane.routes = []dataplane.ClientRoute{
		{Token: 1, Local: netip.MustParseAddrPort("192.0.2.10:51820")},
		{Token: 2, Local: netip.MustParseAddrPort("192.0.2.10:51821")},
		{Token: 3, Local: netip.MustParseAddrPort("192.0.2.10:51821")},
	}
	status, err := fixture.controller.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	want := []api.Group{
		{ListenPort: 51820, Mode: "fallback", Paths: 2, HealthyPaths: 2, Peers: 1},
		{ListenPort: 51821, Mode: "burst", Paths: 2, HealthyPaths: 2, Peers: 2},
	}
	if !slices.Equal(status.Client.Groups, want) {
		t.Fatalf("groups = %#v, want %#v", status.Client.Groups, want)
	}
}

func TestPeersReportsInterfaceAndIdleTime(t *testing.T) {
	t.Parallel()

	fixture := newControllerFixture(t, "198.51.100.1:5000/udp")
	fixture.dataplane.routes = []dataplane.ClientRoute{{
		Token:   7,
		Peer:    netip.MustParseAddrPort("203.0.113.8:41000"),
		Local:   netip.MustParseAddrPort("192.0.2.10:51820"),
		Ifindex: 3,
		Idle:    1500 * time.Millisecond,
	}}
	peers, err := fixture.controller.Peers()
	if err != nil || len(peers.Peers) != 1 {
		t.Fatalf("Peers = %#v, %v", peers, err)
	}
	peer := peers.Peers[0]
	if peer.Token != 7 || peer.Address != "203.0.113.8:41000" || peer.Interface != "if3" || peer.IdleSeconds != 1.5 {
		t.Fatalf("peer = %#v", peer)
	}
}

type failingPathConn struct{ err error }

func (s failingPathConn) Run(context.Context, probeReporter) error { return s.err }
func (s failingPathConn) Close() error                             { return nil }

func TestControllerRunStopsWhenAPathLoopFails(t *testing.T) {
	t.Parallel()

	path, _ := config.ParsePath("198.51.100.1:5000/udp")
	client := config.Client{
		AdvertisedIP: netip.MustParseAddr("192.0.2.10"),
		Groups:       []config.Group{{ListenPort: 51820, Paths: []config.Path{path}}},
	}
	settings := dataplane.ClientSettings{
		InstanceNonce: 1,
		Groups:        []dataplane.GroupSettings{{ListenPort: 51820, PathMask: 1}},
		Paths:         []dataplane.PathSettings{{Ifindex: 2, ServerPort: 5000}},
	}
	newFake := func() *fakeClientDataplane {
		return &fakeClientDataplane{paths: map[int]dataplane.PathSettings{}, groups: map[uint16]dataplane.GroupSettings{}}
	}
	want := errors.New("socket closed")
	open := func(pathRegistration) (pathConn, error) {
		return failingPathConn{err: want}, nil
	}
	controller := newClientController(client, settings, newFake(), fakeResolver{}, pathOpener(open), time.Now(), discardLogger)
	done := make(chan error, 1)
	go func() { done <- controller.run(context.Background()) }()
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("run error = %v, want %v", err, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not stop after a path failure")
	}

	ctx, cancel := context.WithCancel(context.Background())
	open = func(pathRegistration) (pathConn, error) { return newFakePathConn(), nil }
	controller = newClientController(client, settings, newFake(), fakeResolver{}, pathOpener(open), time.Now(), discardLogger)
	go func() { done <- controller.run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("run error after cancel = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not stop after cancel")
	}
}

func TestControllerMarksAPathWithoutReflectorUnhealthy(t *testing.T) {
	t.Parallel()

	fixture := newControllerFixture(t, "198.51.100.1:5000/udp", "198.51.100.2:5000/udp")
	fixture.controller.mu.Lock()
	epoch := fixture.controller.slots[1].epoch
	fixture.controller.mu.Unlock()
	start := time.Now().Add(-10 * time.Second)
	for sequence := uint32(1); sequence <= missLimit; sequence++ {
		probe := pathProbeResult{slot: 1, epoch: epoch, sequence: sequence,
			sentAt: start.Add(time.Duration(sequence) * time.Second), result: registerNoReflector}
		if err := fixture.controller.handleProbe(probe); err != nil {
			t.Fatalf("handleProbe: %v", err)
		}
	}
	paths, err := fixture.controller.Paths()
	if err != nil || len(paths) != 2 {
		t.Fatalf("Paths = %v, %v", paths, err)
	}
	if paths[1].Healthy || paths[1].Reason != "no reflector" {
		t.Fatalf("path 1 = healthy %v, reason %q, want unhealthy with no reflector", paths[1].Healthy, paths[1].Reason)
	}
	if fixture.dataplane.mask != 0b01 {
		t.Fatalf("mask = %#b, want only path 0", fixture.dataplane.mask)
	}
	// An OK ACK brings the path back and clears the reason.
	fixture.reply(t, 1, missLimit+1)
	paths, _ = fixture.controller.Paths()
	if !paths[1].Healthy || paths[1].Reason != "" {
		t.Fatalf("path 1 after an ACK = healthy %v, reason %q", paths[1].Healthy, paths[1].Reason)
	}
}

// miss reports REGISTER frames of a slot that got no answer.
func (f controllerFixture) miss(t *testing.T, slot, count int) {
	t.Helper()
	f.result(t, slot, count, registerMissed)
}

func (f controllerFixture) result(t *testing.T, slot, count int, result registerResult) {
	t.Helper()
	for range count {
		f.controller.mu.Lock()
		epoch := f.controller.slots[slot].epoch
		f.controller.mu.Unlock()
		probe := pathProbeResult{slot: slot, epoch: epoch, sequence: 1, sentAt: time.Now().Add(-time.Minute), result: result}
		if err := f.controller.handleProbe(probe); err != nil {
			t.Fatalf("handleProbe: %v", err)
		}
	}
}

// countPortPicks makes the fixture choose ports from a list, and counts the
// choices.
func (f controllerFixture) countPortPicks(ports ...uint16) *int {
	picks := new(int)
	f.controller.mu.Lock()
	defer f.controller.mu.Unlock()
	f.controller.pickPort = func(config.PortRange, uint16) uint16 {
		port := ports[*picks%len(ports)]
		*picks++
		return port
	}
	return picks
}

func TestControllerMovesAStuckPathToAnotherPort(t *testing.T) {
	t.Parallel()

	fixture := newControllerFixture(t, "198.51.100.1:5000/udp", "198.51.100.3:7000-7009/udp via 203.0.113.16/28")
	picks := fixture.countPortPicks(7004, 7008)
	oldPath, _ := config.ParsePath("198.51.100.3:7000/udp via 203.0.113.16/28")
	fixture.controller.mu.Lock()
	oldEpoch := fixture.controller.slots[1].epoch
	fixture.controller.mu.Unlock()

	fixture.miss(t, 1, portMoveMisses-1)
	if _, set := fixture.dataplane.paths[1]; *picks != 0 || set {
		t.Fatalf("the path moved after %d misses", portMoveMisses-1)
	}
	fixture.miss(t, 1, 1)
	if *picks != 1 {
		t.Fatalf("port picks = %d, want 1", *picks)
	}
	settings := fixture.dataplane.paths[1]
	if settings.ServerPort != 7004 || settings.ReturnPrefix != 28 || settings.Priority != 1 {
		t.Fatalf("path settings after the move = %#v", settings)
	}
	if got := fixture.registrations[1].path; got.ServerPort != 7004 || got.HasPortRange() {
		t.Fatalf("registration path = %s, want port 7004 alone", got)
	}
	select {
	case <-fixture.conns[oldPath].closed:
	case <-time.After(time.Second):
		t.Fatal("the old control loop kept running")
	}
	paths, _ := fixture.controller.Paths()
	if paths[1].Port != 7004 || paths[1].FirstPort != 7000 || paths[1].LastPort != 7009 || paths[1].Healthy {
		t.Fatalf("path 1 = %#v, want unhealthy on port 7004 of 7000-7009", paths[1])
	}
	stale := pathProbeResult{slot: 1, epoch: oldEpoch, sequence: 1, sentAt: time.Now(), result: registerAcked}
	if err := fixture.controller.handleProbe(stale); err != nil {
		t.Fatalf("handleProbe: %v", err)
	}
	if fixture.dataplane.mask&0b10 != 0 {
		t.Fatal("an answer on the old port made the moved path healthy")
	}

	// The next move without an answer waits twice as long.
	fixture.miss(t, 1, 2*portMoveMisses-1)
	if *picks != 1 {
		t.Fatalf("the path moved again after %d misses", 2*portMoveMisses-1)
	}
	fixture.miss(t, 1, 1)
	if *picks != 2 || fixture.dataplane.paths[1].ServerPort != 7008 {
		t.Fatalf("after the second wait: picks %d, port %d, want 2 and 7008", *picks, fixture.dataplane.paths[1].ServerPort)
	}

	// An answer makes the path healthy and resets the wait.
	fixture.reply(t, 1, 1)
	paths, _ = fixture.controller.Paths()
	if !paths[1].Healthy || paths[1].Port != 7008 {
		t.Fatalf("path 1 after an ACK = %#v, want healthy on port 7008", paths[1])
	}
	fixture.miss(t, 1, portMoveMisses)
	if *picks != 3 {
		t.Fatalf("port picks after an ACK and %d misses = %d, want 3", portMoveMisses, *picks)
	}
}

func TestControllerKeepsTheServerPortWithoutARange(t *testing.T) {
	t.Parallel()

	fixture := newControllerFixture(t, "198.51.100.1:5000/udp", "198.51.100.3:7000/udp")
	picks := fixture.countPortPicks(7001)
	fixture.miss(t, 1, 4*portMoveMisses)
	if _, set := fixture.dataplane.paths[1]; *picks != 0 || set {
		t.Fatalf("a path with one server port moved %d times", *picks)
	}
}

func TestControllerKeepsTheServerPortWhenTheServerAnswers(t *testing.T) {
	t.Parallel()

	// A path without a reflector reaches the server, so a new port does not
	// help it.
	fixture := newControllerFixture(t, "198.51.100.1:5000/udp", "198.51.100.3:7000-7009/udp via 203.0.113.16/28")
	picks := fixture.countPortPicks(7001)
	fixture.result(t, 1, 4*portMoveMisses, registerNoReflector)
	if *picks != 0 {
		t.Fatalf("a path that the server answers moved %d times", *picks)
	}
}

func TestControllerStaysOnItsPortWhenAMoveFails(t *testing.T) {
	t.Parallel()

	fixture := newControllerFixture(t, "198.51.100.1:5000/udp", "198.51.100.3:7000-7009/icmp")
	picks := fixture.countPortPicks(7005)
	fixture.controller.mu.Lock()
	fixture.controller.controls = pathOpener(func(pathRegistration) (pathConn, error) { return nil, errors.New("no socket") })
	epoch := fixture.controller.slots[1].epoch
	fixture.controller.mu.Unlock()
	fixture.miss(t, 1, portMoveMisses)
	fixture.controller.mu.Lock()
	current := fixture.controller.slots[1]
	fixture.controller.mu.Unlock()
	if _, set := fixture.dataplane.paths[1]; *picks != 1 || current.epoch != epoch || current.port != 7000 || set {
		t.Fatalf("after a failed move: picks %d, port %d, dataplane written %v", *picks, current.port, set)
	}
	// The next misses try again.
	fixture.miss(t, 1, portMoveMisses)
	if *picks != 2 {
		t.Fatalf("port picks = %d, want a second try", *picks)
	}
}

func TestAddPathRejectsAPortRangeThatOverlaps(t *testing.T) {
	t.Parallel()

	fixture := twoGroupsFixture(t)
	if _, err := fixture.controller.AddPath("198.51.100.1:4990-5000/udp", 51820); statusOf(err) != http.StatusConflict {
		t.Fatalf("AddPath of an overlapping range error = %v, want status 409", err)
	}
	if _, err := fixture.controller.AddPath("203.0.113.1:5990-6010/icmp", 51820); statusOf(err) != http.StatusConflict {
		t.Fatalf("AddPath of a range in a server port of another group error = %v, want status 409", err)
	}
	added, err := fixture.controller.AddPath("198.51.100.3:5001-5099/udp", 51820)
	if err != nil {
		t.Fatalf("AddPath: %v", err)
	}
	if added.Port != 5001 || added.FirstPort != 5001 || added.LastPort != 5099 {
		t.Fatalf("added path = %#v, want port 5001 of 5001-5099", added)
	}
	if got := fixture.dataplane.paths[added.ID].ServerPort; got != 5001 {
		t.Fatalf("dataplane server port = %d, want 5001", got)
	}
	if got := fixture.registrations[added.ID].path; got.ServerPort != 5001 || got.HasPortRange() {
		t.Fatalf("registration path = %s", got)
	}
}

func TestRandomOtherPortSkipsTheCurrentPort(t *testing.T) {
	t.Parallel()

	ports := config.PortRange{First: 7000, Last: 7002}
	seen := map[uint16]int{}
	for range 300 {
		port := randomOtherPort(ports, 7001)
		if port == 7001 || !ports.Contains(port) {
			t.Fatalf("randomOtherPort = %d, want 7000 or 7002", port)
		}
		seen[port]++
	}
	if seen[7000] == 0 || seen[7002] == 0 {
		t.Fatalf("ports chosen = %v, want both 7000 and 7002", seen)
	}
	two := config.PortRange{First: 9000, Last: 9001}
	if got := randomOtherPort(two, 9000); got != 9001 {
		t.Fatalf("randomOtherPort(9000-9001, 9000) = %d", got)
	}
	if got := randomOtherPort(two, 9001); got != 9000 {
		t.Fatalf("randomOtherPort(9000-9001, 9001) = %d", got)
	}
}

func TestPortMoveThresholdDoublesUpToALimit(t *testing.T) {
	t.Parallel()

	want := []int{10, 20, 40, 80, 160, 160}
	for moves, threshold := range want {
		if got := portMoveThreshold(moves); got != threshold {
			t.Fatalf("portMoveThreshold(%d) = %d, want %d", moves, got, threshold)
		}
	}
}
