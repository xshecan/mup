//go:build linux

package dataplane

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/xshecan/mup/protocol"
)

var (
	downDirectServer = netip.MustParseAddr("203.0.113.5")
	downMemberA      = netip.MustParseAddr("198.51.100.40")
	downMemberB      = netip.MustParseAddr("198.51.100.41")
)

// downReplyCollection loads a server with a target on this host, a route with
// token 9 at target port 20000, and two down paths for the client: a direct
// UDP path 0, and an ICMP path 1 that reflects through two pool members.
func downReplyCollection(t *testing.T, mode uint8, healthy uint8) *ebpf.Collection {
	t.Helper()
	collection, client := targetIngressCollection(t)
	put := func(name string, key, value any) {
		t.Helper()
		if err := collection.Maps[name].Update(key, value, ebpf.UpdateAny); err != nil {
			t.Fatalf("update %s: %v", name, err)
		}
	}
	routeKey := mupServerRouteKeyV1{Client: client, PeerToken: 9}
	routeValue := mupServerRouteValueV1{
		TargetPort: 20000, ServerPort: 5000, Transport: uint8(protocol.TransportUDP),
		ClientSourceIp: client.AdvertisedIp, ServerLocalIp: mustTestWord(t, ingressTarget), Ifindex: 1,
	}
	put("server_route_by_key", routeKey, routeValue)
	put("server_route_by_port", uint16(20000), mupServerReverseValueV1{RouteKey: routeKey, RouteValue: routeValue})
	put("server_down_groups", client, mupDownGroupV1{ListenPort: 51821, Mode: mode, PathMask: 0b11, HealthyMask: healthy, IcmpMask: 0b10})
	put("server_down_paths", mupDownPathKeyV1{Client: client, PathId: 0}, mupDownPathV1{
		ServerIp: mustTestWord(t, downDirectServer), Ifindex: 1, ServerPort: 9200, Transport: uint8(protocol.TransportUDP),
	})
	pool := mupDownPathV1{
		ServerIp: mustTestWord(t, downDirectServer), Ifindex: 1, ServerPort: 9300, Transport: uint8(protocol.TransportICMP),
		Flags: protocol.ControlFlagReturnPool, Count: 2,
	}
	pool.Members[0] = mustTestWord(t, downMemberA)
	pool.Members[1] = mustTestWord(t, downMemberB)
	put("server_down_paths", mupDownPathKeyV1{Client: client, PathId: 1}, pool)
	return collection
}

func targetReply(t *testing.T, collection *ebpf.Collection) (uint32, []byte) {
	t.Helper()
	reply := udpWireGuardFrame(t, ingressTarget, ingressClient, ingressTargetPort, 20000, 0)
	result, output, err := collection.Programs["mup_server_egress"].Test(reply)
	if err != nil {
		t.Fatalf("program test: %v", err)
	}
	return result, output
}

// assertReflectedICMP checks an Echo Request from the client to a pool member
// with the identifier of the down path, the token, and valid checksums.
func assertReflectedICMP(t *testing.T, frame []byte) {
	t.Helper()
	ip := frame[14:]
	l4 := ip[20:binary.BigEndian.Uint16(ip[2:4])]
	destination := netip.AddrFrom4([4]byte(ip[16:20]))
	if ip[9] != protocol.IPProtocolICMP || l4[0] != 8 || binary.BigEndian.Uint16(l4[4:6]) != 9300 {
		t.Fatalf("protocol %d, ICMP type %d, identifier %d, want an Echo Request with identifier 9300", ip[9], l4[0], binary.BigEndian.Uint16(l4[4:6]))
	}
	if source := netip.AddrFrom4([4]byte(ip[12:16])); source != ingressClient {
		t.Fatalf("source = %s, want the client %s", source, ingressClient)
	}
	if destination != downMemberA && destination != downMemberB {
		t.Fatalf("destination = %s, want a pool member", destination)
	}
	if onesComplement(ip[:20], 0) != 0 || onesComplement(l4, 0) != 0 {
		t.Fatal("a checksum is invalid")
	}
	if token := l4[9:12]; token[0] != 0 || token[1] != 0 || token[2] != 9 {
		t.Fatalf("token bytes = %x, want 000009", token)
	}
}

func TestServerSendsTheReplyOnAHealthyDownPath(t *testing.T) {
	// Fallback takes the lowest healthy down path.
	collection := downReplyCollection(t, 0, 0b10)
	result, output := targetReply(t, collection)
	if result != tcActOK && result != tcActRedirect {
		t.Fatalf("return value = %d, want pass or redirect", int32(result))
	}
	assertReflectedICMP(t, output)
	collection.Close()

	collection = downReplyCollection(t, 0, 0b11)
	_, output = targetReply(t, collection)
	assertUDPHeader(t, output, downDirectServer, ingressClient, 9200, 51821)
	collection.Close()

	// Balancer hashes the token and the healthy mask, as the client does.
	token, mask := uint32(9), uint32(0b11)
	hash := token*0x9e3779b1 ^ mask*0x85ebca6b
	hash ^= hash >> 16
	collection = downReplyCollection(t, 1, 0b11)
	_, output = targetReply(t, collection)
	if hash%2 == 0 {
		assertUDPHeader(t, output, downDirectServer, ingressClient, 9200, 51821)
	} else {
		assertReflectedICMP(t, output)
	}
	collection.Close()

	// Burst sends a copy on each healthy path, and the packet itself on the
	// highest one.
	collection = downReplyCollection(t, 2, 0b11)
	result, output = targetReply(t, collection)
	if result != tcActOK && result != tcActRedirect {
		t.Fatalf("burst return value = %d", int32(result))
	}
	assertReflectedICMP(t, output)
	collection.Close()
}

func TestServerDropsAReplyWithoutAHealthyDownPath(t *testing.T) {
	collection := downReplyCollection(t, 0, 0)
	defer collection.Close()
	result, _ := targetReply(t, collection)
	if drops := dropCount(t, collection, protocol.DropNoPath); result != tcActShot || drops != 1 {
		t.Fatalf("return value = %d, NO_PATH drops = %d, want a drop", int32(result), drops)
	}
}

// A down group of another listen port does not apply, so the reply follows
// the upstream path as before.
func TestServerFollowsTheUpstreamPathWithoutADownGroup(t *testing.T) {
	collection := downReplyCollection(t, 0, 0b11)
	defer collection.Close()
	client := mupClientKeyV1{AdvertisedIp: mustTestWord(t, ingressClient), InstanceNonce: 7}
	if err := collection.Maps["server_down_groups"].Update(client, mupDownGroupV1{ListenPort: 51999, PathMask: 0b11, HealthyMask: 0b11}, ebpf.UpdateAny); err != nil {
		t.Fatalf("update down group: %v", err)
	}
	_, output := targetReply(t, collection)
	assertUDPHeader(t, output, ingressTarget, ingressClient, 5000, 51821)
}

var (
	downClientAdvertised = netip.MustParseAddr("192.0.2.20")
	downPeer             = netip.MustParseAddr("203.0.113.7")
	downUpServer         = netip.MustParseAddr("198.51.100.9")
)

// downClientCollection loads a client with one up path and two down paths in
// group 51820: an ICMP path from the pool 198.51.100.32/28 on identifier
// 9300, and a direct UDP path from 198.51.100.9:9400. Token 5 is a peer.
func downClientCollection(t *testing.T, flags uint8) *ebpf.Collection {
	t.Helper()
	collection := loadTestCollection(t)
	put := func(name string, key, value any) {
		t.Helper()
		if err := collection.Maps[name].Update(key, value, ebpf.UpdateAny); err != nil {
			t.Fatalf("update %s: %v", name, err)
		}
	}
	advertised := mustTestWord(t, downClientAdvertised)
	put("client_config", uint32(0), mupClientConfigV1{InstanceNonce: 7, AdvertisedIp: advertised})
	put("path_groups", uint16(51820), mupPathGroupV1{PathMask: 1, DownMask: 0b11, Flags: flags})
	put("path_config", uint32(0), mupPathConfigV1{
		DestinationIp: mustTestWord(t, downUpServer), SourceIp: advertised,
		Ifindex: 1, ServerPort: 9000, Transport: uint8(protocol.TransportUDP),
	})
	put("client_down_paths", uint32(0), mupClientDownPathV1{
		ServerIp: mustTestWord(t, downUpServer), ReturnIp: mustTestWord(t, netip.MustParseAddr("198.51.100.32")),
		ServerPort: 9300, Transport: uint8(protocol.TransportICMP), Flags: protocol.ControlFlagReturnPool, Prefix: 28,
	})
	put("client_down_paths", uint32(1), mupClientDownPathV1{
		ServerIp: mustTestWord(t, downUpServer), ServerPort: 9400, Transport: uint8(protocol.TransportUDP),
	})
	endpoint := mupPeerEndpointKeyV1{
		SourceIp: mustTestWord(t, downPeer), LocalIp: advertised, SourcePort: 40000, ListenPort: 51820,
	}
	put("client_endpoint_by_token", uint32(5), mupPeerEndpointValueV1{Endpoint: endpoint, Ifindex: 1})
	put("client_peer_by_endpoint", endpoint, mupPeerTokenValueV1{PeerToken: 5})
	return collection
}

// icmpWireGuardFrame turns a UDP WireGuard frame into an ICMP Echo message
// with the identifier, keeping the payload and fixing the checksums.
func icmpWireGuardFrame(t *testing.T, source, destination netip.Addr, echoType uint8, identifier uint16, token uint32) []byte {
	t.Helper()
	frame := udpWireGuardFrame(t, source, destination, 1, 1, token)
	ip := frame[14:]
	ip[9] = protocol.IPProtocolICMP
	ip[10], ip[11] = 0, 0
	binary.BigEndian.PutUint16(ip[10:12], onesComplement(ip[:20], 0))
	l4 := ip[20:]
	l4[0], l4[1] = echoType, 0
	l4[2], l4[3] = 0, 0
	binary.BigEndian.PutUint16(l4[4:6], identifier)
	binary.BigEndian.PutUint16(l4[6:8], uint16(token))
	binary.BigEndian.PutUint16(l4[2:4], onesComplement(l4, 0))
	return frame
}

func TestClientAcceptsRepliesFromItsDownPaths(t *testing.T) {
	collection := downClientCollection(t, 0)
	defer collection.Close()
	program := collection.Programs["mup_client_ingress"]
	for name, frame := range map[string][]byte{
		"pool member":   icmpWireGuardFrame(t, netip.MustParseAddr("198.51.100.36"), downClientAdvertised, 0, 9300, 5),
		"direct server": udpWireGuardFrame(t, downUpServer, downClientAdvertised, 9400, 51820, 5),
		"up path":       udpWireGuardFrame(t, downUpServer, downClientAdvertised, 9000, 51820, 5),
	} {
		result, output, err := program.Test(frame)
		if err != nil {
			t.Fatalf("%s: program test: %v", name, err)
		}
		if result != tcActRedirect {
			t.Fatalf("%s: return value = %d, want the redirect", name, int32(result))
		}
		assertUDPHeader(t, output, downClientAdvertised, downPeer, 51820, 40000)
	}
	var down mupClientDownPathV1
	if err := collection.Maps["client_down_paths"].Lookup(uint32(0), &down); err != nil || down.LastSeenNs == 0 {
		t.Fatalf("down path 0 last seen = %d (%v), want a time", down.LastSeenNs, err)
	}

	for name, frame := range map[string][]byte{
		"outside the pool": icmpWireGuardFrame(t, netip.MustParseAddr("198.51.100.66"), downClientAdvertised, 0, 9300, 5),
		"other UDP port":   udpWireGuardFrame(t, downUpServer, downClientAdvertised, 9401, 51820, 5),
	} {
		before := dropCount(t, collection, protocol.DropDownstreamSource)
		result, _, err := program.Test(frame)
		if err != nil {
			t.Fatalf("%s: program test: %v", name, err)
		}
		if after := dropCount(t, collection, protocol.DropDownstreamSource); result != tcActShot || after != before+1 {
			t.Fatalf("%s: return value = %d, DOWNSTREAM_SOURCE drops %d to %d, want a drop", name, int32(result), before, after)
		}
	}
}

func TestClientDropsTheSecondCopyOfADownstreamBurst(t *testing.T) {
	collection := downClientCollection(t, groupFlagDedup)
	defer collection.Close()
	program := collection.Programs["mup_client_ingress"]
	copies := [][]byte{
		udpWireGuardFrame(t, downUpServer, downClientAdvertised, 9400, 51820, 5),
		icmpWireGuardFrame(t, netip.MustParseAddr("198.51.100.36"), downClientAdvertised, 0, 9300, 5),
	}
	var results []uint32
	for _, frame := range copies {
		result, _, err := program.Test(frame)
		if err != nil {
			t.Fatalf("program test: %v", err)
		}
		results = append(results, result)
	}
	if !slices.Equal(results, []uint32{tcActRedirect, tcActShot}) || dropCount(t, collection, protocol.DropDuplicate) != 1 {
		t.Fatalf("results = %v, DUPLICATE drops = %d, want the first copy only", results, dropCount(t, collection, protocol.DropDuplicate))
	}
	// Without the flag, both copies pass.
	plain := downClientCollection(t, 0)
	defer plain.Close()
	for _, frame := range copies {
		result, _, err := plain.Programs["mup_client_ingress"].Test(frame)
		if err != nil || result != tcActRedirect {
			t.Fatalf("plain group: return value = %d (%v), want the redirect", int32(result), err)
		}
	}
}

// A server with a remote target gets the replies at ingress, and the ingress
// program runs the down path sends inline.
func TestServerIngressSendsTheReplyOnADownPath(t *testing.T) {
	for _, mode := range []uint8{0, 2} {
		collection := downReplyCollection(t, mode, 0b11)
		source := netip.MustParseAddr("198.51.100.2")
		if err := collection.Maps["target_ingress"].Update(uint32(0), mupTargetIngressV1{}, ebpf.UpdateAny); err != nil {
			t.Fatalf("turn off ingress delivery: %v", err)
		}
		if err := collection.Maps["server_config"].Update(uint32(0), mupServerConfigV1{
			TargetIp: mustTestWord(t, ingressTarget), SourceIp: mustTestWord(t, source), Ifindex: 1,
			TargetPort: ingressTargetPort, ServerPort: 5000,
		}, ebpf.UpdateAny); err != nil {
			t.Fatalf("update server config: %v", err)
		}
		reply := udpWireGuardFrame(t, ingressTarget, source, ingressTargetPort, 20000, 0)
		result, output, err := collection.Programs["mup_server_ingress"].Test(reply)
		if err != nil {
			t.Fatalf("mode %d: program test: %v", mode, err)
		}
		if result != tcActRedirect {
			t.Fatalf("mode %d: return value = %d, want the redirect", mode, int32(result))
		}
		if mode == 0 {
			assertUDPHeader(t, output, downDirectServer, ingressClient, 9200, 51821)
		} else {
			assertReflectedICMP(t, output)
		}
		collection.Close()
	}
}
