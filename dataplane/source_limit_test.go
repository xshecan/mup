package dataplane

import (
	"maps"
	"testing"
)

func TestCountRoutesBySource(t *testing.T) {
	t.Parallel()

	routes := map[mupPeerEndpointKeyV1]mupPeerTokenValueV1{
		{SourceIp: 1, LocalIp: 9, SourcePort: 1000, ListenPort: 51820}: {PeerToken: 1},
		{SourceIp: 1, LocalIp: 9, SourcePort: 1001, ListenPort: 51820}: {PeerToken: 2},
		{SourceIp: 1, LocalIp: 9, SourcePort: 1000, ListenPort: 51821}: {PeerToken: 3},
		{SourceIp: 2, LocalIp: 9, SourcePort: 1000, ListenPort: 51820}: {PeerToken: 4},
	}
	want := map[uint32]uint32{1: 3, 2: 1}
	if got := countRoutesBySource(routes); !maps.Equal(got, want) {
		t.Fatalf("countRoutesBySource = %v, want %v", got, want)
	}
	if got := countRoutesBySource(nil); len(got) != 0 {
		t.Fatalf("countRoutesBySource(nil) = %v, want empty", got)
	}
}
