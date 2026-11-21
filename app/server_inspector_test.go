package app

import (
	"net/netip"
	"testing"
	"time"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/protocol"
)

type fakeServerDataplane struct {
	routes        []dataplane.ServerRoute
	registrations []dataplane.Registration
	paths         []dataplane.RegisteredPath
	reflectors    []dataplane.Reflector
}

func (f fakeServerDataplane) Snapshot() (dataplane.StatsSnapshot, error) {
	return dataplane.StatsSnapshot{
		Registrations:        uint64(len(f.registrations)),
		RegisteredPaths:      uint64(len(f.paths)),
		ServerRoutes:         uint64(len(f.routes)),
		TargetPortsAvailable: 40998,
	}, nil
}

func (f fakeServerDataplane) ServerRoutes() ([]dataplane.ServerRoute, error) { return f.routes, nil }

func (f fakeServerDataplane) Reflectors() ([]dataplane.Reflector, error) { return f.reflectors, nil }

func (f fakeServerDataplane) Registrations() ([]dataplane.Registration, error) {
	return f.registrations, nil
}

func (f fakeServerDataplane) RegisteredPaths() ([]dataplane.RegisteredPath, error) {
	return f.paths, nil
}

func TestServerInspectorGroupsPathsAndPeersByClient(t *testing.T) {
	t.Parallel()

	first := dataplane.ClientKey{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), InstanceNonce: 0x1f}
	second := dataplane.ClientKey{AdvertisedIP: netip.MustParseAddr("192.0.2.11"), InstanceNonce: 2}
	fake := fakeServerDataplane{
		registrations: []dataplane.Registration{
			{Client: first, ListenPort: 51820, ExpiresIn: 24 * time.Second, ReturnIP: netip.MustParseAddr("198.51.100.77")},
			{Client: second, ListenPort: 51821, ExpiresIn: -time.Second},
		},
		paths: []dataplane.RegisteredPath{
			{Client: first, PathID: 0, Transport: protocol.TransportUDP, Source: first.AdvertisedIP, Local: netip.MustParseAddr("203.0.113.5")},
			{Client: first, PathID: 1, Transport: protocol.TransportICMP, Source: first.AdvertisedIP, Local: netip.MustParseAddr("203.0.113.6")},
		},
		routes: []dataplane.ServerRoute{
			{Client: first, Token: 1, TargetPort: 20000, Transport: protocol.TransportUDP, Ifindex: 2, Idle: time.Second},
			{Client: first, Token: 2, TargetPort: 20001, Transport: protocol.TransportICMP, Ifindex: 2},
		},
	}
	inspector := newServerInspector(config.Server{Port: config.SinglePort(5000), Target: netip.MustParseAddrPort("198.51.100.7:51820")}, fake, time.Unix(0, 0), nil)
	inspector.interfaceName = func(int) string { return "eth0" }

	clients, err := inspector.Clients()
	if err != nil || len(clients) != 2 {
		t.Fatalf("Clients = %#v, %v", clients, err)
	}
	if clients[0].Nonce != "000000000000001f" || len(clients[0].Paths) != 2 || clients[0].Peers != 2 || clients[0].ReturnIP != "198.51.100.77" {
		t.Fatalf("first client = %#v", clients[0])
	}
	if len(clients[1].Paths) != 0 || clients[1].Peers != 0 || clients[1].LeaseSeconds != -1 {
		t.Fatalf("second client = %#v", clients[1])
	}

	status, err := inspector.Status()
	if err != nil || status.Server.Target != "198.51.100.7:51820" || status.Server.Peers != 2 || status.Server.PortsFree != 40998 {
		t.Fatalf("Status = %#v, %v", status.Server, err)
	}
	peers, err := inspector.Peers()
	if err != nil || len(peers.Routes) != 2 || peers.Routes[1].Transport != "icmp" || peers.Routes[0].Interface != "eth0" {
		t.Fatalf("Peers = %#v, %v", peers, err)
	}
}

func TestServerInspectorShowsReturnPools(t *testing.T) {
	t.Parallel()

	client := dataplane.ClientKey{AdvertisedIP: netip.MustParseAddr("91.216.217.188"), InstanceNonce: 7}
	orphan := dataplane.ClientKey{AdvertisedIP: netip.MustParseAddr("91.216.217.189"), InstanceNonce: 8}
	base := netip.MustParseAddr("94.184.45.48")
	fake := fakeServerDataplane{
		registrations: []dataplane.Registration{
			{Client: client, ListenPort: 51821, ReturnIP: base, ReturnPool: true},
			{Client: orphan, ListenPort: 51821, ReturnIP: base, ReturnPool: true},
		},
		paths: []dataplane.RegisteredPath{
			{Client: client, PathID: 0, Transport: protocol.TransportUDP, Source: client.AdvertisedIP, Local: netip.MustParseAddr("160.119.74.66"), ReturnIP: base, ReturnPrefix: 28},
		},
		routes: []dataplane.ServerRoute{
			{Client: client, Token: 9, TargetPort: 20000, Transport: protocol.TransportUDP, ReturnIP: base, ReturnPool: true},
		},
	}
	inspector := newServerInspector(config.Server{Port: config.SinglePort(9000), Target: netip.MustParseAddrPort("127.0.0.1:51820")}, fake, time.Unix(0, 0), nil)
	inspector.interfaceName = func(int) string { return "eth0" }

	clients, err := inspector.Clients()
	if err != nil || len(clients) != 2 {
		t.Fatalf("Clients = %#v, %v", clients, err)
	}
	if clients[0].ReturnIP != "94.184.45.48/28" || clients[0].Paths[0].ReturnIP != "94.184.45.48/28" {
		t.Fatalf("client return = %q, path return = %q, want the pool CIDR", clients[0].ReturnIP, clients[0].Paths[0].ReturnIP)
	}
	if clients[1].ReturnIP != "94.184.45.48 pool" {
		t.Fatalf("client without a path shows %q, want the base and the word pool", clients[1].ReturnIP)
	}
	peers, err := inspector.Peers()
	if err != nil || len(peers.Routes) != 1 || peers.Routes[0].ReturnIP != "94.184.45.48/28" {
		t.Fatalf("Peers = %#v, %v", peers, err)
	}
}
