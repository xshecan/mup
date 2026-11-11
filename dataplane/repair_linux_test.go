//go:build linux

package dataplane

import (
	"errors"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

func TestRepairClientRouteInvariants(t *testing.T) {
	collection := loadTestCollection(t)
	defer collection.Close()
	runtime := Runtime{objects: mupObjects{mupMaps: mupMaps{
		ClientPeerByEndpoint:  collection.Maps["client_peer_by_endpoint"],
		ClientEndpointByToken: collection.Maps["client_endpoint_by_token"],
	}}}

	validEndpoint := mupPeerEndpointKeyV1{SourceIp: 1, LocalIp: 2, SourcePort: 3, ListenPort: 4}
	missingReverse := mupPeerEndpointKeyV1{SourceIp: 5, LocalIp: 6, SourcePort: 7, ListenPort: 8}
	orphanReverse := mupPeerEndpointKeyV1{SourceIp: 9, LocalIp: 10, SourcePort: 11, ListenPort: 12}
	putMap(t, runtime.objects.ClientPeerByEndpoint, validEndpoint, mupPeerTokenValueV1{PeerToken: 1})
	putMap(t, runtime.objects.ClientEndpointByToken, uint32(1), mupPeerEndpointValueV1{Endpoint: validEndpoint})
	putMap(t, runtime.objects.ClientPeerByEndpoint, missingReverse, mupPeerTokenValueV1{PeerToken: 2})
	putMap(t, runtime.objects.ClientEndpointByToken, uint32(3), mupPeerEndpointValueV1{Endpoint: orphanReverse})

	if err := runtime.repairClientRouteInvariants(time.Second); err != nil {
		t.Fatalf("repairClientRouteInvariants: %v", err)
	}
	assertMapPresent(t, runtime.objects.ClientPeerByEndpoint, validEndpoint, &mupPeerTokenValueV1{})
	assertMapAbsent(t, runtime.objects.ClientPeerByEndpoint, missingReverse, &mupPeerTokenValueV1{})
	assertMapAbsent(t, runtime.objects.ClientEndpointByToken, uint32(3), &mupPeerEndpointValueV1{})
	if runtime.peerQuarantine.Len() != 2 {
		t.Fatalf("peer quarantine length = %d, want 2", runtime.peerQuarantine.Len())
	}
}

func putMap(t *testing.T, target *ebpf.Map, key, value any) {
	t.Helper()
	if err := target.Put(key, value); err != nil {
		t.Fatalf("put map entry: %v", err)
	}
}

func assertMapPresent(t *testing.T, target *ebpf.Map, key, value any) {
	t.Helper()
	if err := target.Lookup(key, value); err != nil {
		t.Fatalf("lookup expected map entry: %v", err)
	}
}

func assertMapAbsent(t *testing.T, target *ebpf.Map, key, value any) {
	t.Helper()
	if err := target.Lookup(key, value); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("lookup removed map entry = %v, want key not found", err)
	}
}

func TestRepairServerRouteInvariants(t *testing.T) {
	collection := loadTestCollection(t)
	defer collection.Close()
	runtime := Runtime{objects: mupObjects{mupMaps: mupMaps{
		ServerRouteByKey:  collection.Maps["server_route_by_key"],
		ServerRouteByPort: collection.Maps["server_route_by_port"],
	}}}

	validKey := mupServerRouteKeyV1{PeerToken: 1}
	missingReverse := mupServerRouteKeyV1{PeerToken: 2}
	orphanReverse := mupServerRouteKeyV1{PeerToken: 3}
	putMap(t, runtime.objects.ServerRouteByKey, validKey, mupServerRouteValueV1{TargetPort: 20000})
	putMap(t, runtime.objects.ServerRouteByPort, uint16(20000), mupServerReverseValueV1{RouteKey: validKey})
	putMap(t, runtime.objects.ServerRouteByKey, missingReverse, mupServerRouteValueV1{TargetPort: 20001})
	putMap(t, runtime.objects.ServerRouteByPort, uint16(20002), mupServerReverseValueV1{RouteKey: orphanReverse})

	if err := runtime.repairServerRouteInvariants(time.Second); err != nil {
		t.Fatalf("repairServerRouteInvariants: %v", err)
	}
	assertMapPresent(t, runtime.objects.ServerRouteByKey, validKey, &mupServerRouteValueV1{})
	assertMapAbsent(t, runtime.objects.ServerRouteByKey, missingReverse, &mupServerRouteValueV1{})
	assertMapAbsent(t, runtime.objects.ServerRouteByPort, uint16(20002), &mupServerReverseValueV1{})
	if runtime.portQuarantine.Len() != 2 {
		t.Fatalf("port quarantine length = %d, want 2", runtime.portQuarantine.Len())
	}
}
