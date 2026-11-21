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
}

// fakeControls records what the controller asks of the control sockets.
type fakeControls struct {
	mu            sync.Mutex
	registrations map[int]pathRegistration
	listened      []downListen
	handle        func(downProbe)
	sent          []sentFrame
	stopped       bool
}

func (f *fakeControls) open(registration pathRegistration) (pathConn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.registrations[int(registration.pathID)] = registration
	return newFakePathConn(), nil
}

func (f *fakeControls) listenDown(listen downListen, handle func(downProbe)) (func(), error) {
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

func (f *fakeControls) sendUp(registration pathRegistration, packet []byte) error {
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
	group := testGroup(t, 51820, config.ModeFallback, "198.51.100.1:9000/udp", "198.51.100.2:9100/icmp")
	group.DownMode = config.ModeBalancer
	for _, raw := range []string{"198.51.100.1:9200/icmp via 203.0.113.0/28", "198.51.100.1:9300/udp"} {
		group.DownPaths = append(group.DownPaths, mustParsePath(t, raw))
	}
	paired := testGroup(t, 51821, config.ModeFallback, "198.51.100.3:5000/udp")
	client := config.Client{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), Groups: []config.Group{group, paired}}
	if err := client.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	plan, err := buildPlan(config.App{Client: &client}, 42, fakeResolver{catchAll: 2})
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	if len(plan.client.DownPaths) != 2 || plan.client.Groups[0].DownMask != 0b11 || plan.client.Groups[1].DownMask != 0 {
		t.Fatalf("plan down paths = %d, groups = %#v", len(plan.client.DownPaths), plan.client.Groups)
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

func TestSplitGroupSendsItsDownPaths(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	if len(fixture.controls.listened) != 1 || !slices.Equal(fixture.controls.listened[0].listenPorts, []uint16{51820}) ||
		fixture.controls.listened[0].nonce != 42 {
		t.Fatalf("listenDown = %#v, want the split group only", fixture.controls.listened)
	}
	if fixture.registrations[2].downs != nil {
		t.Fatal("the up path of the paired group sends down paths")
	}
	frames := decodeFrames(t, fixture.registrations[1].downFrames(9))
	if len(frames) != 2 {
		t.Fatalf("DOWN_REGISTER frames = %d, want 2", len(frames))
	}
	pool, direct := frames[0], frames[1]
	if pool.Type != protocol.ControlDownRegister || pool.Transport != protocol.TransportICMP || pool.ServerPort != 9200 ||
		pool.Flags != protocol.ControlFlagReturnPool || pool.ReturnIP != netip.MustParseAddr("203.0.113.0") || pool.ReturnPrefix != 28 ||
		pool.DownServer != netip.MustParseAddr("198.51.100.1") || pool.DownMode != uint8(config.ModeBalancer) ||
		pool.ListenPort != 51820 || pool.Sequence != 9 || pool.LeaseSeconds != registrationLeaseSeconds {
		t.Fatalf("pool frame = %#v", pool)
	}
	if direct.PathID != 1 || direct.Transport != protocol.TransportUDP || direct.Flags != 0 || direct.ReturnIP.IsValid() {
		t.Fatalf("direct frame = %#v", direct)
	}
}

func TestDownProbeIsAnsweredOnAnUpPath(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	probe := downProbe{
		frame: protocol.ControlFrame{
			Type: protocol.ControlProbe, Transport: protocol.TransportICMP, Flags: protocol.ControlFlagDownPath,
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
		t.Fatalf("probe replies = %#v, want one on up path 0", sent)
	}
	reply := sent[0].frame
	if reply.Type != protocol.ControlProbeReply || reply.Flags != protocol.ControlFlagDownPath|protocol.ControlFlagReturnIP ||
		reply.PathID != 0 || reply.Sequence != 77 || reply.ReturnIP != probe.source || reply.Transport != protocol.TransportICMP {
		t.Fatalf("probe reply = %#v", reply)
	}
	paths, _ := fixture.controller.Paths()
	var downs []bool
	for _, path := range paths {
		if path.Direction == directionDown {
			downs = append(downs, path.Healthy)
		}
	}
	if !slices.Equal(downs, []bool{true, false}) {
		t.Fatalf("down path health = %v, want only the probed path healthy", downs)
	}

	for name, bad := range map[string]downProbe{
		"source outside the pool": {frame: probe.frame, source: netip.MustParseAddr("203.0.114.4"), transport: protocol.TransportICMP, port: 9200},
		"other port":              {frame: probe.frame, source: probe.source, transport: protocol.TransportICMP, port: 9201},
		"other transport":         {frame: probe.frame, source: probe.source, transport: protocol.TransportUDP, port: 9200},
	} {
		fixture.controls.handle(bad)
		if sent := fixture.controls.takeSent(); len(sent) != 0 {
			t.Fatalf("%s: probe replies = %d, want none", name, len(sent))
		}
	}

	// Without a healthy up path, the reply goes on every up path.
	fixture.miss(t, 0, missLimit)
	fixture.miss(t, 1, missLimit)
	fixture.controls.handle(probe)
	if sent := fixture.controls.takeSent(); len(sent) != 2 {
		t.Fatalf("probe replies without a healthy up path = %d, want 2", len(sent))
	}
}

func TestDownPathRuntimeChanges(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	controller := fixture.controller
	added, err := controller.AddDownPath("198.51.100.1:9400/udp via 203.0.113.9", 51820)
	if err != nil {
		t.Fatalf("AddDownPath: %v", err)
	}
	if added.ID != 2 || added.Direction != directionDown || added.Healthy {
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
		"same down path": {raw: "198.51.100.1:9400/udp", port: 51820, status: http.StatusConflict},
		"interface":      {raw: "198.51.100.1%eth0:9500/udp", port: 51820, status: http.StatusBadRequest},
		"port range":     {raw: "198.51.100.1:9500-9510/udp", port: 51820, status: http.StatusBadRequest},
		"paired group":   {raw: "198.51.100.1:9500/udp", port: 51821, status: http.StatusConflict},
	} {
		if _, err := controller.AddDownPath(test.raw, test.port); statusOf(err) != test.status {
			t.Fatalf("%s: AddDownPath error = %v, want status %d", name, err, test.status)
		}
	}
	if _, err := controller.AddBridge("198.51.100.4:9600/udp via 203.0.113.9", 51820); statusOf(err) != http.StatusBadRequest {
		t.Fatalf("AddBridge with via error = %v, want bad request", err)
	}

	if err := controller.RemoveDownPath(1); err != nil {
		t.Fatalf("RemoveDownPath: %v", err)
	}
	if group := fixture.dataplane.groups[51820]; group.DownMask != 0b101 {
		t.Fatalf("group = %#v after the removal", group)
	}
	if err := controller.SetDownMode("burst", 51820); err != nil {
		t.Fatalf("SetDownMode: %v", err)
	}
	if group := fixture.dataplane.groups[51820]; group.DownMode != config.ModeBurst {
		t.Fatalf("group = %#v after the mode change", group)
	}
	if err := controller.SetDownMode("burst", 51821); statusOf(err) != http.StatusConflict {
		t.Fatalf("SetDownMode on a paired group error = %v", err)
	}
	frames := decodeFrames(t, fixture.registrations[0].downFrames(3))
	leases := map[uint16]uint32{}
	for _, frame := range frames {
		leases[frame.PathID] = frame.LeaseSeconds
		if frame.DownMode != uint8(config.ModeBurst) {
			t.Fatalf("frame %d has down mode %d, want burst", frame.PathID, frame.DownMode)
		}
	}
	if len(leases) != 3 || leases[0] != registrationLeaseSeconds || leases[1] != 0 || leases[2] != registrationLeaseSeconds {
		t.Fatalf("frame leases = %v, want the removed path withdrawn with a lease of zero", leases)
	}
	if err := controller.RemoveDownPath(0); err != nil {
		t.Fatalf("RemoveDownPath(0): %v", err)
	}
	if err := controller.RemoveDownPath(2); statusOf(err) != http.StatusConflict {
		t.Fatalf("RemoveDownPath of the last down path error = %v", err)
	}
}
