package app

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xshecan/mup/api"
	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/protocol"
)

func TestBridgePathRuntimeChanges(t *testing.T) {
	t.Parallel()

	fixture := newSplitFixture(t)
	controller := fixture.controller
	ingress, err := controller.AddBridge("5.6.7.8:9600/udp", 51820)
	if err != nil {
		t.Fatalf("AddBridge: %v", err)
	}
	if !ingress.Bridge || ingress.Direction != directionIngress || ingress.Server != "5.6.7.8" {
		t.Fatalf("ingress bridge = %#v", ingress)
	}
	if _, err := controller.AddBridge("5.6.7.8:9601/udp", 51821); statusOf(err) != http.StatusConflict {
		t.Fatalf("AddBridge in a paired group error = %v", err)
	}
	egress, err := controller.AddEgressBridge("5.6.7.8:9700/icmp via 203.0.113.0/28", 51820)
	if err != nil {
		t.Fatalf("AddEgressBridge: %v", err)
	}
	if !egress.Bridge || egress.Direction != directionEgress || egress.ID != 2 {
		t.Fatalf("egress bridge = %#v", egress)
	}
	frames := decodeFrames(t, fixture.registrations[0].egressFrames(1))
	bridged := frames[len(frames)-1]
	if bridged.PathID != 2 || bridged.Flags != protocol.ControlFlagReturnPool|protocol.ControlFlagBridge ||
		bridged.EgressServer != netip.MustParseAddr("5.6.7.8") {
		t.Fatalf("EGRESS_REGISTER of the egress bridge = %#v", bridged)
	}
	for _, frame := range frames[:len(frames)-1] {
		if frame.Flags&protocol.ControlFlagBridge != 0 {
			t.Fatalf("egress route %d has the bridge flag", frame.PathID)
		}
	}
}

func TestEgressRegistryKeepsAEgressBridge(t *testing.T) {
	t.Parallel()

	plane := newFakeEgressPlane()
	registry := newTestEgressRegistry(plane)
	bridge, local := netip.MustParseAddr("5.6.7.8"), netip.MustParseAddr("203.0.113.5")
	registry.route = func(address netip.Addr) (netip.Addr, int, error) {
		if address != bridge {
			return netip.Addr{}, 0, errors.New("no route")
		}
		return local, 4, nil
	}
	frame := egressFrame(0, 12000, protocol.TransportICMP, config.ModeFallback)
	frame.Flags = protocol.ControlFlagReturnIP | protocol.ControlFlagBridge
	frame.ReturnIP = netip.MustParseAddr("198.51.100.9")
	frame.EgressServer = bridge
	start := time.Unix(1000, 0)
	// A bridge is not an address of this host, and its port is a bridge port.
	if err := registry.register(frame, egressClient, start); err != nil {
		t.Fatalf("register: %v", err)
	}
	entry := plane.paths[egressKey{client: egressKeyOf, id: 0}]
	if !entry.Bridge || entry.LocalIP != local || entry.Ifindex != 4 || entry.Server != bridge || entry.ReturnIP != frame.ReturnIP {
		t.Fatalf("entry = %#v", entry)
	}
	// The bridge can serve another server, so the path waits for a reply.
	if group := plane.groups[egressKeyOf]; group.PathMask != 0b1 || group.HealthyMask != 0 {
		t.Fatalf("group = %#v, want the bridge unhealthy before its first reply", group)
	}
	targets := registry.probeTargets(start)
	if len(targets) != 1 || !targets[0].bridge || targets[0].localIP != local || targets[0].member != frame.ReturnIP {
		t.Fatalf("probe targets = %#v", targets)
	}
	if !registry.confirm(probeReply(0, protocol.TransportICMP, frame.ReturnIP), start.Add(time.Second)) {
		t.Fatal("confirm of the bridge failed")
	}
	registry.sync(start.Add(time.Second))
	if group := plane.groups[egressKeyOf]; group.HealthyMask != 0b1 {
		t.Fatalf("group = %#v, want the bridge healthy after its reply", group)
	}
	views := registry.clients(start.Add(time.Second))
	if paths := views[egressKeyOf].Paths; len(paths) != 1 || !paths[0].Bridge || !paths[0].Healthy {
		t.Fatalf("API view = %#v", views[egressKeyOf])
	}

	// A route to the bridge that fails rejects the frame.
	registry.route = func(netip.Addr) (netip.Addr, int, error) { return netip.Addr{}, 0, errors.New("no route") }
	frame.PathID = 1
	if err := registry.register(frame, egressClient, start); err == nil {
		t.Fatal("register without a route to the bridge succeeded")
	}
}

type fakeBridgeDataplane struct {
	addresses [][]netip.Addr
}

func (*fakeBridgeDataplane) Snapshot() (dataplane.StatsSnapshot, error) {
	var snapshot dataplane.StatsSnapshot
	snapshot.Drops[protocol.DropBridgeSource] = 3
	return snapshot, nil
}

func (*fakeBridgeDataplane) BridgeCounters() (dataplane.BridgeCounters, error) {
	return dataplane.BridgeCounters{IngressPackets: 5, IngressBytes: 500, EgressPackets: 7, EgressBytes: 700}, nil
}

func (f *fakeBridgeDataplane) SetBridgeAddresses(addresses []netip.Addr) error {
	f.addresses = append(f.addresses, addresses)
	return nil
}

func TestBridgeAPIServesTheStatus(t *testing.T) {
	t.Parallel()

	bridge := config.Bridge{
		Server: netip.MustParseAddr("46.102.130.95"),
		Port:   config.PortRange{First: 9000, Last: 9399},
		Allow:  []netip.Prefix{netip.MustParsePrefix("46.102.130.0/24")},
	}
	inspector := newBridgeInspector(bridge, &fakeBridgeDataplane{}, time.Unix(100, 0))
	inspector.addresses = func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("5.6.7.8")}, nil }
	client := newTestDaemonClient(t, newBridgeAPIHandler(inspector))
	status, err := client.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	got := status.Bridge
	if status.Role != api.RoleBridge || got == nil || got.Server != "46.102.130.95" || got.Port != 9000 || got.PortLast != 9399 ||
		len(got.Allow) != 1 || len(got.Addresses) != 1 || got.IngressPackets != 5 || got.EgressBytes != 700 {
		t.Fatalf("status = %#v", status)
	}
	if dropCountOf(status.Drops, "BRIDGE_SOURCE") != 3 {
		t.Fatalf("drops = %#v", status.Drops)
	}
	if _, err := client.Paths(context.Background()); responseStatus(err) != http.StatusConflict ||
		!strings.Contains(err.Error(), "bridge") {
		t.Fatalf("Paths on a bridge error = %v", err)
	}
	if _, err := client.Peers(context.Background()); responseStatus(err) != http.StatusConflict {
		t.Fatalf("Peers on a bridge error = %v", err)
	}
}

func dropCountOf(drops []api.Drop, name string) uint64 {
	for _, drop := range drops {
		if drop.Name == name {
			return drop.Count
		}
	}
	return 0
}

func TestBridgeRefreshesTheHostAddresses(t *testing.T) {
	t.Parallel()

	plane := &fakeBridgeDataplane{}
	inspector := newBridgeInspector(config.Bridge{}, plane, time.Unix(100, 0))
	calls := 0
	inspector.addresses = func() ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("5.6.7.8")}, nil
	}
	inspector.interval = 20 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := inspector.refreshAddresses(ctx, discardLogger); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("refreshAddresses = %v", err)
	}
	// The same addresses are written once.
	if calls != 2 || len(plane.addresses) != 1 {
		t.Fatalf("reads = %d, writes = %d, want 2 reads and 1 write", calls, len(plane.addresses))
	}
}

func TestCheckForwarding(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	for value, want := range map[string]error{"0\n": errForwardingOff, "1\n": nil} {
		path := filepath.Join(directory, strings.TrimSpace(value))
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := checkForwarding(path); !errors.Is(err, want) {
			t.Fatalf("checkForwarding(%q) = %v, want %v", value, err, want)
		}
	}
	if err := checkForwarding(filepath.Join(directory, "missing")); err != nil {
		t.Fatalf("checkForwarding of a missing file = %v", err)
	}
}

func TestBuildPlanForABridge(t *testing.T) {
	t.Parallel()

	bridge := config.Bridge{Server: netip.MustParseAddr("46.102.130.95"), Port: config.SinglePort(9000)}
	plan, err := buildPlan(config.App{Bridge: &bridge}, 0, fakeResolver{catchAll: 2})
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	if plan.pinRoot != defaultPinRoot+"/bridge" || plan.client != nil || plan.server != nil {
		t.Fatalf("plan = %#v", plan)
	}
	if _, err := buildPlan(config.App{}, 0, fakeResolver{catchAll: 2}); err == nil {
		t.Fatal("buildPlan without a role succeeded")
	}
}
