package app

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/protocol"
)

type fakeResolver struct {
	routes   map[string]route
	up       []int
	catchAll int
}

type route struct {
	source  netip.Addr
	ifindex int
}

func (r fakeResolver) Resolve(destination netip.Addr, interfaceName string) (netip.Addr, int, error) {
	if r.catchAll != 0 {
		return netip.Addr{}, r.catchAll, nil
	}
	returnRoute := r.routes[destination.String()+"%"+interfaceName]
	return returnRoute.source, returnRoute.ifindex, nil
}

func (r fakeResolver) UpInterfaceIndexes() ([]int, error) {
	return append([]int(nil), r.up...), nil
}

func TestBuildClientPlan(t *testing.T) {
	t.Parallel()

	resolver := fakeResolver{
		routes: map[string]route{
			"198.51.100.1%eth9": {source: netip.MustParseAddr("203.0.113.2"), ifindex: 9},
			"198.51.100.2%":     {source: netip.MustParseAddr("203.0.113.3"), ifindex: 7},
		},
		up: []int{2, 7, 9, 2},
	}
	plan, err := buildPlan(config.App{Client: &config.Client{
		AdvertisedIP: netip.MustParseAddr("192.0.2.10"),
		Groups: []config.Group{
			{ListenPort: 51820, Mode: config.ModeFallback, Paths: []config.Path{
				{Server: netip.MustParseAddr("198.51.100.1"), ServerPort: 5000, Transport: protocol.TransportUDP, Interface: "eth9"},
			}},
			{ListenPort: 51821, Mode: config.ModeBurst, ReturnIP: netip.MustParseAddr("1.1.1.1"), Paths: []config.Path{
				{Server: netip.MustParseAddr("198.51.100.2"), ServerPort: 6000, Transport: protocol.TransportICMP},
			}},
		},
	}}, 42, resolver)
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	if plan.client == nil || plan.server != nil || plan.client.InstanceNonce != 42 {
		t.Fatalf("unexpected role plan: %#v", plan)
	}
	if got := plan.client.Paths[0].SourceIP; got != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("client path source = %v, want advertised IP", got)
	}
	if got := plan.attachIfindexes; len(got) != 3 || got[0] != 2 || got[1] != 7 || got[2] != 9 {
		t.Fatalf("attach indexes = %v, want [2 7 9]", got)
	}
	if plan.client.HealthyMask != 0b11 {
		t.Fatalf("healthy mask = %#b, want 0b11", plan.client.HealthyMask)
	}
	want := []dataplane.GroupSettings{
		{ListenPort: 51820, Mode: config.ModeFallback, PathMask: 0b01},
		{ListenPort: 51821, Mode: config.ModeBurst, ReturnIP: netip.MustParseAddr("1.1.1.1"), PathMask: 0b10},
	}
	if !slices.Equal(plan.client.Groups, want) {
		t.Fatalf("groups = %#v, want %#v", plan.client.Groups, want)
	}
	if got := plan.client.Paths[1]; got.ServerPort != 6000 || got.Priority != 1 || got.Ifindex != 7 {
		t.Fatalf("second path = %#v", got)
	}
}

func TestBuildServerPlan(t *testing.T) {
	t.Parallel()

	resolver := fakeResolver{
		routes: map[string]route{
			"193.24.210.185%": {source: netip.MustParseAddr("192.0.2.5"), ifindex: 4},
		},
		up: []int{2, 4},
	}
	plan, err := buildPlan(config.App{Server: &config.Server{
		Port:   5000,
		Target: netip.MustParseAddrPort("193.24.210.185:51820"),
	}}, 0, resolver)
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	if plan.server == nil || plan.server.SourceIP != netip.MustParseAddr("192.0.2.5") ||
		plan.server.Ifindex != 4 {
		t.Fatalf("server plan = %#v", plan.server)
	}
}

func TestBuildClientPlanAcceptsBurst(t *testing.T) {
	t.Parallel()

	resolver := fakeResolver{
		routes: map[string]route{
			"198.51.100.1%": {source: netip.MustParseAddr("203.0.113.2"), ifindex: 2},
		},
		up: []int{2},
	}
	plan, err := buildPlan(config.App{Client: &config.Client{
		AdvertisedIP: netip.MustParseAddr("192.0.2.10"),
		Groups: []config.Group{{ListenPort: 51820, Mode: config.ModeBurst, Paths: []config.Path{{
			Server:     netip.MustParseAddr("198.51.100.1"),
			ServerPort: 5000,
			Transport:  protocol.TransportUDP,
		}}}},
	}}, 42, resolver)
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	if plan.client == nil || plan.client.Groups[0].Mode != config.ModeBurst {
		t.Fatalf("client plan = %#v, want burst mode", plan.client)
	}
}
