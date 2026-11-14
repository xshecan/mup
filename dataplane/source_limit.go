package dataplane

func countRoutesBySource(routes map[mupPeerEndpointKeyV1]mupPeerTokenValueV1) map[uint32]uint32 {
	counts := make(map[uint32]uint32)
	for endpoint := range routes {
		counts[endpoint.SourceIp]++
	}
	return counts
}
