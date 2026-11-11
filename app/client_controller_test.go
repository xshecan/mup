package app

import (
	"context"
	"errors"
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
	fixture.controller = newClientController(client, *plan.client, fake, resolver, open, time.Unix(100, 0))
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
	probe := pathProbeResult{slot: slot, epoch: epoch, sequence: sequence, sentAt: time.Now(), success: true}
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
	stale := pathProbeResult{slot: 1, epoch: oldEpoch, sequence: 1, sentAt: time.Now(), success: true}
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
	controller := newClientController(client, settings, newFake(), fakeResolver{}, open, time.Now())
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
	controller = newClientController(client, settings, newFake(), fakeResolver{}, open, time.Now())
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
