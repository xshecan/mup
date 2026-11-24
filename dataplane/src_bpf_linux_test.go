//go:build linux

package dataplane

import (
	"bytes"
	"encoding/binary"
	"math"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/xshecan/mup/protocol"
)

// srcPacketCount is the number of packets that a test sends where the source
// value is random. Forty packets over a range of fifty values take one value
// with a chance far below one in a billion.
const srcPacketCount = 40

// srcSlot is the path slot of the client tests. A slot other than 0 shows
// that the tag is the slot plus one.
const srcSlot = 2

// srcClientCollection loads a client with one healthy path of the transport in
// group 51820 on slot srcSlot, and one free token. The path has the source range
// from first to last, or none for a first of 0.
func srcClientCollection(t *testing.T, transport protocol.TransportID, first, last uint16) *ebpf.Collection {
	t.Helper()
	collection := loadTestCollection(t)
	put := func(name string, key, value any) {
		t.Helper()
		if err := collection.Maps[name].Update(key, value, ebpf.UpdateAny); err != nil {
			t.Fatalf("update %s: %v", name, err)
		}
	}
	advertised := mustTestWord(t, zeroAdvertised)
	put("client_config", uint32(0), mupClientConfigV1{InstanceNonce: 7, AdvertisedIp: advertised})
	put("path_groups", uint16(51820), mupPathGroupV1{Mode: 0, PathMask: 1 << srcSlot})
	put("path_config", uint32(srcSlot), mupPathConfigV1{
		DestinationIp: mustTestWord(t, zeroServer), SourceIp: advertised,
		Ifindex: 1, ServerPort: 9000, Transport: uint8(transport),
	})
	put("client_path_src", uint32(srcSlot), mupPathSrcV1{First: first, Last: last})
	put("path_state", uint32(0), mupPathStateV1{HealthyMask: 1 << srcSlot})
	if err := collection.Maps["free_peer_tokens"].Update(nil, uint32(5), ebpf.UpdateAny); err != nil {
		t.Fatalf("push a peer token: %v", err)
	}
	return collection
}

// echoFrame is icmpWireGuardFrame with its own Echo sequence.
func echoFrame(t *testing.T, source, destination netip.Addr, echoType uint8, identifier, sequence uint16, token uint32) []byte {
	t.Helper()
	frame := icmpWireGuardFrame(t, source, destination, echoType, identifier, token)
	l4 := frame[14+20:]
	binary.BigEndian.PutUint16(l4[6:8], sequence)
	l4[2], l4[3] = 0, 0
	binary.BigEndian.PutUint16(l4[2:4], onesComplement(l4, 0))
	return frame
}

// transportOf returns the IPv4 header and the transport bytes of a frame.
func transportOf(frame []byte) ([]byte, []byte) {
	ip := frame[14:]
	return ip, ip[20:binary.BigEndian.Uint16(ip[2:4])]
}

// assertInRange checks that value is a value of the range, and records it.
func assertInRange(t *testing.T, name string, value, first, last uint16, seen map[uint16]bool) {
	t.Helper()
	if value < first || value > last {
		t.Fatalf("%s = %d, want a value of %d-%d", name, value, first, last)
	}
	seen[value] = true
}

// assertSeveral checks that the packets took more than one value.
func assertSeveral(t *testing.T, name string, seen map[uint16]bool) {
	t.Helper()
	if len(seen) < 2 {
		t.Fatalf("%s took %d values over %d packets, want random values", name, len(seen), srcPacketCount)
	}
}

func runProgram(t *testing.T, collection *ebpf.Collection, program string, frame []byte) (uint32, []byte) {
	t.Helper()
	result, output, err := collection.Programs[program].Test(frame)
	if err != nil {
		t.Fatalf("%s test: %v", program, err)
	}
	return result, output
}

func TestClientSendsUDPIngressFromThePortsOfTheSourceRange(t *testing.T) {
	collection := srcClientCollection(t, protocol.TransportUDP, 20000, 20049)
	defer collection.Close()
	seen := map[uint16]bool{}
	for range srcPacketCount {
		frame := udpWireGuardFrame(t, zeroUser, zeroAdvertised, 40000, 51820, 0)
		result, output := runProgram(t, collection, "mup_client_ingress", frame)
		if result != tcActRedirect {
			t.Fatalf("return value = %d, want the redirect %d", int32(result), tcActRedirect)
		}
		ip, udp := transportOf(output)
		assertInRange(t, "UDP source port", binary.BigEndian.Uint16(udp[0:2]), 20000, 20049, seen)
		if destination := binary.BigEndian.Uint16(udp[2:4]); destination != 9000 {
			t.Fatalf("UDP destination port = %d, want the server port 9000", destination)
		}
		if onesComplement(ip[:20], 0) != 0 || onesComplement(udp, pseudoHeaderSum(ip)) != 0 {
			t.Fatal("a checksum is invalid")
		}
	}
	assertSeveral(t, "the UDP source port", seen)

	plain := srcClientCollection(t, protocol.TransportUDP, 0, 0)
	defer plain.Close()
	for range 3 {
		frame := udpWireGuardFrame(t, zeroUser, zeroAdvertised, 40000, 51820, 0)
		result, output := runProgram(t, plain, "mup_client_ingress", frame)
		if result != tcActRedirect {
			t.Fatalf("without a range: return value = %d, want the redirect", int32(result))
		}
		assertUDPHeader(t, output, zeroAdvertised, zeroServer, 51820, 9000)
	}
}

func TestClientSendsICMPIngressWithAnIdentifierOfTheSourceRangeAndTheTag(t *testing.T) {
	collection := srcClientCollection(t, protocol.TransportICMP, 30000, 30049)
	defer collection.Close()
	seen := map[uint16]bool{}
	for range srcPacketCount {
		frame := udpWireGuardFrame(t, zeroUser, zeroAdvertised, 40000, 51820, 0)
		result, output := runProgram(t, collection, "mup_client_ingress", frame)
		if result != tcActRedirect {
			t.Fatalf("return value = %d, want the redirect %d", int32(result), tcActRedirect)
		}
		ip, icmp := transportOf(output)
		if ip[9] != protocol.IPProtocolICMP || icmp[0] != 8 {
			t.Fatalf("protocol %d, ICMP type %d, want an Echo Request", ip[9], icmp[0])
		}
		assertInRange(t, "ICMP identifier", binary.BigEndian.Uint16(icmp[4:6]), 30000, 30049, seen)
		if sequence := binary.BigEndian.Uint16(icmp[6:8]); sequence != (srcSlot+1)<<12|5 {
			t.Fatalf("ICMP sequence = %#x, want the tag %d and token 5", sequence, srcSlot+1)
		}
		if onesComplement(ip[:20], 0) != 0 || onesComplement(icmp, 0) != 0 {
			t.Fatal("a checksum is invalid")
		}
		if token := icmp[9:12]; token[0] != 0 || token[1] != 0 || token[2] != 5 {
			t.Fatalf("peer token bytes = %x, want 000005", token)
		}
	}
	assertSeveral(t, "the ICMP identifier", seen)
}

const (
	srcServerPathID = 2
	srcServerTag    = srcServerPathID + 1
)

// srcServerCollection is targetIngressCollection with an ICMP path 2 on port
// 5000 that has the source range 20000-20999: its exact entry and its tagged
// entry. The target port 30000 is free.
func srcServerCollection(t *testing.T) (*ebpf.Collection, mupClientKeyV1) {
	t.Helper()
	collection, client := targetIngressCollection(t)
	value := mupRegisteredPathValueV1{
		Client: client, ExpiresAtNs: math.MaxUint64, PathId: srcServerPathID, ListenPort: 51821,
		SrcFirst: 20000, SrcLast: 20999, ServerPort: 5000,
	}
	exact := mupRegisteredPathKeyV1{
		SourceIp: client.AdvertisedIp, LocalIp: mustTestWord(t, ingressTarget), ServerPort: 5000,
		Transport: uint8(protocol.TransportICMP),
	}
	tagged := exact
	tagged.ServerPort, tagged.Tag = 0, srcServerTag
	for _, key := range []mupRegisteredPathKeyV1{exact, tagged} {
		if err := collection.Maps["registered_paths"].Update(key, value, ebpf.UpdateAny); err != nil {
			t.Fatalf("update registered path: %v", err)
		}
	}
	if err := collection.Maps["free_target_ports"].Update(nil, uint16(30000), ebpf.UpdateAny); err != nil {
		t.Fatalf("push a target port: %v", err)
	}
	return collection, client
}

func assertSrcRoute(t *testing.T, collection *ebpf.Collection, client mupClientKeyV1) {
	t.Helper()
	var route mupServerRouteValueV1
	if err := collection.Maps["server_route_by_key"].Lookup(mupServerRouteKeyV1{Client: client, PeerToken: 9}, &route); err != nil {
		t.Fatalf("look up the route: %v", err)
	}
	if route.ServerPort != 5000 || route.Transport != uint8(protocol.TransportICMP) || route.PathId != srcServerPathID ||
		route.SrcFirst != 20000 || route.SrcLast != 20999 {
		t.Fatalf("route = %#v, want ICMP path 2 on port 5000 with the range 20000-20999", route)
	}
}

func TestServerAcceptsATaggedICMPPacketOfARegisteredRange(t *testing.T) {
	collection, client := srcServerCollection(t)
	defer collection.Close()
	frame := echoFrame(t, ingressClient, ingressTarget, 8, 20005, srcServerTag<<12|9, 9)
	result, output := runProgram(t, collection, "mup_server_ingress", frame)
	if result != tcActRedirect {
		t.Fatalf("return value = %d, want the redirect %d", int32(result), tcActRedirect)
	}
	assertUDPHeader(t, output, ingressClient, ingressTarget, 30000, ingressTargetPort)
	assertSrcRoute(t, collection, client)
}

func TestServerRefusesATaggedICMPPacketOutsideAnyRegisteredRange(t *testing.T) {
	for name, frame := range map[string]func(t *testing.T) []byte{
		"identifier outside the range": func(t *testing.T) []byte {
			return echoFrame(t, ingressClient, ingressTarget, 8, 21000, srcServerTag<<12|9, 9)
		},
		"tag of a slot without a path": func(t *testing.T) []byte {
			return echoFrame(t, ingressClient, ingressTarget, 8, 20005, 5<<12|9, 9)
		},
	} {
		collection, client := srcServerCollection(t)
		result, _ := runProgram(t, collection, "mup_server_ingress", frame(t))
		drops := dropCount(t, collection, protocol.DropNotRegistered)
		var route mupServerRouteValueV1
		routeErr := collection.Maps["server_route_by_key"].Lookup(mupServerRouteKeyV1{Client: client, PeerToken: 9}, &route)
		collection.Close()
		if result != tcActShot || drops != 1 {
			t.Fatalf("%s: return value = %d, NOT_REGISTERED drops = %d, want a drop", name, int32(result), drops)
		}
		if routeErr == nil {
			t.Fatalf("%s: the packet made the route %#v", name, route)
		}
	}
}

func TestServerTakesAnUntaggedICMPPacketAsBefore(t *testing.T) {
	collection, client := srcServerCollection(t)
	defer collection.Close()
	// The untagged form of a partial packet uses the server port.
	frame := echoFrame(t, ingressClient, ingressTarget, 8, 5000, 9, 9)
	result, output := runProgram(t, collection, "mup_server_ingress", frame)
	if result != tcActRedirect {
		t.Fatalf("return value = %d, want the redirect %d", int32(result), tcActRedirect)
	}
	assertUDPHeader(t, output, ingressClient, ingressTarget, 30000, ingressTargetPort)
	assertSrcRoute(t, collection, client)

	// An untagged ping outside the server ports is not for mup.
	ping := echoFrame(t, ingressClient, ingressTarget, 8, 20005, 9, 9)
	if result, output := runProgram(t, collection, "mup_server_ingress", ping); result != tcxNext || !bytes.Equal(output, ping) {
		t.Fatalf("untagged ping outside the ports: return value = %d, want TCX_NEXT and no change", int32(result))
	}
}

// putSrcRoute writes the route of token 9 at target port 20000 with the
// transport, path 2, and the source range.
func putSrcRoute(t *testing.T, collection *ebpf.Collection, client mupClientKeyV1, transport protocol.TransportID, first, last uint16) {
	t.Helper()
	routeKey := mupServerRouteKeyV1{Client: client, PeerToken: 9}
	routeValue := mupServerRouteValueV1{
		TargetPort: 20000, ServerPort: 5000, Transport: uint8(transport), PathId: srcServerPathID,
		ClientSourceIp: client.AdvertisedIp, ServerLocalIp: mustTestWord(t, ingressTarget), Ifindex: 1,
		ListenPort: 51821, SrcFirst: first, SrcLast: last,
	}
	if err := collection.Maps["server_route_by_key"].Update(routeKey, routeValue, ebpf.UpdateAny); err != nil {
		t.Fatalf("update forward route: %v", err)
	}
	reverse := mupServerReverseValueV1{RouteKey: routeKey, RouteValue: routeValue}
	if err := collection.Maps["server_route_by_port"].Update(uint16(20000), reverse, ebpf.UpdateAny); err != nil {
		t.Fatalf("update reverse route: %v", err)
	}
}

func assertReplyPasses(t *testing.T, result uint32) {
	t.Helper()
	if result != tcActOK && result != tcActRedirect {
		t.Fatalf("return value = %d, want pass or redirect", int32(result))
	}
}

func TestServerRepliesOnTheIngressPathFromTheSourceRange(t *testing.T) {
	collection, client := targetIngressCollection(t)
	defer collection.Close()
	putSrcRoute(t, collection, client, protocol.TransportUDP, 40000, 40049)
	seen := map[uint16]bool{}
	for range srcPacketCount {
		result, output := targetReply(t, collection)
		assertReplyPasses(t, result)
		ip, udp := transportOf(output)
		if source := netip.AddrFrom4([4]byte(ip[12:16])); source != ingressTarget || ip[9] != protocol.IPProtocolUDP {
			t.Fatalf("reply source %s, protocol %d, want UDP from %s", source, ip[9], ingressTarget)
		}
		assertInRange(t, "UDP source port", binary.BigEndian.Uint16(udp[0:2]), 40000, 40049, seen)
		if destination := binary.BigEndian.Uint16(udp[2:4]); destination != 51821 {
			t.Fatalf("UDP destination port = %d, want 51821", destination)
		}
		if onesComplement(ip[:20], 0) != 0 || onesComplement(udp, pseudoHeaderSum(ip)) != 0 {
			t.Fatal("a checksum is invalid")
		}
	}
	assertSeveral(t, "the UDP source port", seen)

	putSrcRoute(t, collection, client, protocol.TransportICMP, 40000, 40049)
	seen = map[uint16]bool{}
	for range srcPacketCount {
		result, output := targetReply(t, collection)
		assertReplyPasses(t, result)
		ip, icmp := transportOf(output)
		if ip[9] != protocol.IPProtocolICMP || icmp[0] != 0 {
			t.Fatalf("protocol %d, ICMP type %d, want an Echo Reply", ip[9], icmp[0])
		}
		assertInRange(t, "ICMP identifier", binary.BigEndian.Uint16(icmp[4:6]), 40000, 40049, seen)
		if sequence := binary.BigEndian.Uint16(icmp[6:8]); sequence != srcServerTag<<12|9 {
			t.Fatalf("ICMP sequence = %#x, want the tag %d and token 9", sequence, srcServerTag)
		}
		if onesComplement(ip[:20], 0) != 0 || onesComplement(icmp, 0) != 0 {
			t.Fatal("a checksum is invalid")
		}
	}
	assertSeveral(t, "the ICMP identifier", seen)
}

// setDownSrc gives an egress path of egressReplyCollection a source range.
func setDownSrc(t *testing.T, collection *ebpf.Collection, pathID uint32, first, last uint16) {
	t.Helper()
	client := mupClientKeyV1{AdvertisedIp: mustTestWord(t, ingressClient), InstanceNonce: 7}
	key := mupDownPathKeyV1{Client: client, PathId: pathID}
	var path mupDownPathV1
	if err := collection.Maps["server_down_paths"].Lookup(key, &path); err != nil {
		t.Fatalf("look up egress path %d: %v", pathID, err)
	}
	path.SrcFirst, path.SrcLast = first, last
	if err := collection.Maps["server_down_paths"].Update(key, path, ebpf.UpdateAny); err != nil {
		t.Fatalf("update egress path %d: %v", pathID, err)
	}
}

func TestServerRepliesOnAnEgressPathFromTheSourceRange(t *testing.T) {
	// Failover with only path 0 healthy takes the direct UDP path.
	collection := egressReplyCollection(t, 0, 0b01)
	defer collection.Close()
	setDownSrc(t, collection, 0, 41000, 41049)
	seen := map[uint16]bool{}
	for range srcPacketCount {
		result, output := targetReply(t, collection)
		assertReplyPasses(t, result)
		ip, udp := transportOf(output)
		if source := netip.AddrFrom4([4]byte(ip[12:16])); source != egressDirectServer {
			t.Fatalf("reply source = %s, want %s", source, egressDirectServer)
		}
		assertInRange(t, "UDP source port", binary.BigEndian.Uint16(udp[0:2]), 41000, 41049, seen)
		if destination := binary.BigEndian.Uint16(udp[2:4]); destination != 51821 {
			t.Fatalf("UDP destination port = %d, want 51821", destination)
		}
		if onesComplement(ip[:20], 0) != 0 || onesComplement(udp, pseudoHeaderSum(ip)) != 0 {
			t.Fatal("a checksum is invalid")
		}
	}
	assertSeveral(t, "the UDP source port", seen)

	// With only path 1 healthy, the ICMP path reflects through the pool.
	pool := egressReplyCollection(t, 0, 0b10)
	defer pool.Close()
	setDownSrc(t, pool, 1, 42000, 42049)
	seen = map[uint16]bool{}
	for range srcPacketCount {
		result, output := targetReply(t, pool)
		assertReplyPasses(t, result)
		ip, icmp := transportOf(output)
		if ip[9] != protocol.IPProtocolICMP || icmp[0] != 8 {
			t.Fatalf("protocol %d, ICMP type %d, want an Echo Request", ip[9], icmp[0])
		}
		assertInRange(t, "ICMP identifier", binary.BigEndian.Uint16(icmp[4:6]), 42000, 42049, seen)
		// The tag is the egress path ID plus one.
		if sequence := binary.BigEndian.Uint16(icmp[6:8]); sequence != 2<<12|9 {
			t.Fatalf("ICMP sequence = %#x, want the tag 2 and token 9", sequence)
		}
		if onesComplement(ip[:20], 0) != 0 || onesComplement(icmp, 0) != 0 {
			t.Fatal("a checksum is invalid")
		}
	}
	assertSeveral(t, "the ICMP identifier", seen)
}

func TestServerWrapsAnEgressBridgeReplyFromTheSourceRange(t *testing.T) {
	collection := egressBridgeCollection(t, 0, 0b01)
	defer collection.Close()
	setDownSrc(t, collection, 0, 43000, 43049)
	seen := map[uint16]bool{}
	for range srcPacketCount {
		result, output := targetReply(t, collection)
		assertReplyPasses(t, result)
		ip := output[14:]
		if destination := netip.AddrFrom4([4]byte(ip[16:20])); ip[9] != protocol.IPProtocolUDP || destination != bridgeAddress {
			t.Fatalf("outer header %x, want UDP to the bridge %s", ip[:20], bridgeAddress)
		}
		wrapperSource := binary.BigEndian.Uint16(ip[20:22])
		assertInRange(t, "wrapper source port", wrapperSource, 43000, 43049, seen)
		if destination := binary.BigEndian.Uint16(ip[22:24]); destination != 9300 {
			t.Fatalf("wrapper destination port = %d, want the path port 9300", destination)
		}
		inner, err := protocol.UnwrapBridge(ip[:binary.BigEndian.Uint16(ip[2:4])])
		if err != nil {
			t.Fatalf("UnwrapBridge: %v", err)
		}
		icmp := inner[20:]
		if identifier := binary.BigEndian.Uint16(icmp[4:6]); identifier != wrapperSource {
			t.Fatalf("inner identifier = %d, want the wrapper source port %d", identifier, wrapperSource)
		}
		if sequence := binary.BigEndian.Uint16(icmp[6:8]); sequence != 1<<12|9 {
			t.Fatalf("inner ICMP sequence = %#x, want the tag 1 and token 9", sequence)
		}
		if onesComplement(icmp, 0) != 0 {
			t.Fatal("the inner ICMP checksum is invalid")
		}
	}
	assertSeveral(t, "the wrapper source port", seen)
}

// srcEgressClientCollection is egressClientCollection with the source range
// 9700-9799 on the ingress path 0, 30000-30099 on the ICMP egress path 0, and
// 9500-9599 on the UDP egress path 1.
func srcEgressClientCollection(t *testing.T) *ebpf.Collection {
	t.Helper()
	collection := egressClientCollection(t, 0)
	for name, ranges := range map[string]map[uint32]mupPathSrcV1{
		"client_path_src": {0: {First: 9700, Last: 9799}},
		"client_down_src": {0: {First: 30000, Last: 30099}, 1: {First: 9500, Last: 9599}},
	} {
		for slot, src := range ranges {
			if err := collection.Maps[name].Update(slot, src, ebpf.UpdateAny); err != nil {
				t.Fatalf("update %s %d: %v", name, slot, err)
			}
		}
	}
	return collection
}

func TestClientAcceptsRepliesFromTheSourceRangeOfAPath(t *testing.T) {
	collection := srcEgressClientCollection(t)
	defer collection.Close()
	member := netip.MustParseAddr("198.51.100.36")
	for name, frame := range map[string][]byte{
		"ingress path range":        udpWireGuardFrame(t, egressIngressServer, egressClientAdvertised, 9750, 51820, 5),
		"egress path range":         udpWireGuardFrame(t, egressIngressServer, egressClientAdvertised, 9550, 51820, 5),
		"tagged ICMP in the range":  echoFrame(t, member, egressClientAdvertised, 0, 30050, 1<<12|5, 5),
		"untagged ICMP on the port": echoFrame(t, member, egressClientAdvertised, 0, 9300, 5, 5),
	} {
		result, output := runProgram(t, collection, "mup_client_ingress", frame)
		if result != tcActRedirect {
			t.Fatalf("%s: return value = %d, want the redirect", name, int32(result))
		}
		assertUDPHeader(t, output, egressClientAdvertised, egressPeer, 51820, 40000)
	}

	for name, frame := range map[string][]byte{
		"UDP below the range":      udpWireGuardFrame(t, egressIngressServer, egressClientAdvertised, 9499, 51820, 5),
		"UDP above the range":      udpWireGuardFrame(t, egressIngressServer, egressClientAdvertised, 9600, 51820, 5),
		"fixed port of a UDP path": udpWireGuardFrame(t, egressIngressServer, egressClientAdvertised, 9400, 51820, 5),
	} {
		before := dropCount(t, collection, protocol.DropEgressSource)
		result, _ := runProgram(t, collection, "mup_client_ingress", frame)
		if after := dropCount(t, collection, protocol.DropEgressSource); result != tcActShot || after != before+1 {
			t.Fatalf("%s: return value = %d, EGRESS_SOURCE drops %d to %d, want a drop", name, int32(result), before, after)
		}
	}

	// An Echo Reply that is not of a path goes on to the kernel.
	for name, frame := range map[string][]byte{
		"wrong tag":                 echoFrame(t, member, egressClientAdvertised, 0, 30050, 2<<12|5, 5),
		"identifier outside":        echoFrame(t, member, egressClientAdvertised, 0, 30100, 1<<12|5, 5),
		"tag of a slot without one": echoFrame(t, member, egressClientAdvertised, 0, 30050, 4<<12|5, 5),
	} {
		if result, _ := runProgram(t, collection, "mup_client_ingress", frame); result == tcActRedirect {
			t.Fatalf("%s: the client took the reply", name)
		}
	}
}

func TestClientRefusesATaggedICMPReplyOnAPathWithoutARange(t *testing.T) {
	collection := egressClientCollection(t, 0)
	defer collection.Close()
	member := netip.MustParseAddr("198.51.100.36")
	tagged := echoFrame(t, member, egressClientAdvertised, 0, 9300, 1<<12|5, 5)
	if result, _ := runProgram(t, collection, "mup_client_ingress", tagged); result == tcActRedirect {
		t.Fatal("a path without a range took a tagged reply")
	}
	plain := echoFrame(t, member, egressClientAdvertised, 0, 9300, 5, 5)
	if result, _ := runProgram(t, collection, "mup_client_ingress", plain); result != tcActRedirect {
		t.Fatalf("untagged reply: return value = %d, want the redirect", int32(result))
	}
}
