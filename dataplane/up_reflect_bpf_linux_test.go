//go:build linux

package dataplane

import (
	"encoding/binary"
	"math"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/xshecan/mup/protocol"
)

var (
	upAdvertised = netip.MustParseAddr("192.0.2.30")
	upServer     = netip.MustParseAddr("198.51.100.9")
	upPeer       = netip.MustParseAddr("203.0.113.7")
	upVia        = netip.MustParseAddr("203.0.113.9")
	upViaA       = netip.MustParseAddr("198.51.100.40")
	upViaB       = netip.MustParseAddr("198.51.100.41")
)

// upReflectClientCollection loads a client with one up reflect path in group
// 51820 on slot 0, through the given transport and reflect members. Token 5 is
// free, so a fresh peer takes it.
func upReflectClientCollection(t *testing.T, transport protocol.TransportID, members []netip.Addr, perPacket bool) *ebpf.Collection {
	t.Helper()
	collection := loadTestCollection(t)
	put := func(name string, key, value any) {
		t.Helper()
		if err := collection.Maps[name].Update(key, value, ebpf.UpdateAny); err != nil {
			t.Fatalf("update %s: %v", name, err)
		}
	}
	advertised := mustTestWord(t, upAdvertised)
	put("client_config", uint32(0), mupClientConfigV1{InstanceNonce: 7, AdvertisedIp: advertised})
	put("path_groups", uint16(51820), mupPathGroupV1{Mode: 0, PathMask: 1})
	put("path_config", uint32(0), mupPathConfigV1{
		DestinationIp: mustTestWord(t, upServer), SourceIp: advertised,
		Ifindex: 1, ServerPort: 9000, Transport: uint8(transport),
	})
	put("path_state", uint32(0), mupPathStateV1{HealthyMask: 1})
	reflect := mupUpReflectV1{Count: uint32(len(members))}
	if perPacket {
		reflect.Flags = protocol.ControlFlagBalancePerPacket
	}
	for index, member := range members {
		reflect.Members[index] = mustTestWord(t, member)
	}
	put("up_reflect_members", uint32(0), reflect)
	if err := collection.Maps["free_peer_tokens"].Update(nil, uint32(5), ebpf.UpdateAny); err != nil {
		t.Fatalf("push a peer token: %v", err)
	}
	return collection
}

// assertUpReflectICMP checks that a frame is an Echo Request from the server to
// one of the wanted members, with the server port as its identifier.
func assertUpReflectICMP(t *testing.T, frame []byte, wanted ...netip.Addr) {
	t.Helper()
	ip := frame[14:]
	l4 := ip[20:binary.BigEndian.Uint16(ip[2:4])]
	if ip[9] != protocol.IPProtocolICMP || l4[0] != 8 || l4[1] != 0 {
		t.Fatalf("protocol %d, ICMP type %d code %d, want an Echo Request", ip[9], l4[0], l4[1])
	}
	if identifier := binary.BigEndian.Uint16(l4[4:6]); identifier != 9000 {
		t.Fatalf("ICMP identifier = %d, want the server port 9000", identifier)
	}
	if source := netip.AddrFrom4([4]byte(ip[12:16])); source != upServer {
		t.Fatalf("source = %s, want the server %s", source, upServer)
	}
	destination := netip.AddrFrom4([4]byte(ip[16:20]))
	found := false
	for _, member := range wanted {
		if destination == member {
			found = true
		}
	}
	if !found {
		t.Fatalf("destination = %s, want one of %v", destination, wanted)
	}
	if onesComplement(ip[:20], 0) != 0 || onesComplement(l4, 0) != 0 {
		t.Fatal("a checksum is invalid")
	}
}

// A client egress reflects an ICMP upstream through the via host: it sends an
// Echo Request to the via with the server as the source.
func TestClientReflectsICMPUpstream(t *testing.T) {
	collection := upReflectClientCollection(t, protocol.TransportICMP, []netip.Addr{upVia}, false)
	defer collection.Close()
	frame := udpWireGuardFrame(t, upPeer, upAdvertised, 40000, 51820, 0)
	result, output, err := collection.Programs["mup_client_ingress"].Test(frame)
	if err != nil {
		t.Fatalf("program test: %v", err)
	}
	if result != tcActRedirect {
		t.Fatalf("return value = %d, want the redirect %d", int32(result), tcActRedirect)
	}
	assertUpReflectICMP(t, output, upVia)
}

// A client egress forges the source of a UDP upstream: it sends to the server
// with the via as the source.
func TestClientForgesUDPUpstream(t *testing.T) {
	collection := upReflectClientCollection(t, protocol.TransportUDP, []netip.Addr{upVia}, false)
	defer collection.Close()
	frame := udpWireGuardFrame(t, upPeer, upAdvertised, 40000, 51820, 0)
	result, output, err := collection.Programs["mup_client_ingress"].Test(frame)
	if err != nil {
		t.Fatalf("program test: %v", err)
	}
	if result != tcActRedirect {
		t.Fatalf("return value = %d, want the redirect %d", int32(result), tcActRedirect)
	}
	assertUDPHeader(t, output, upVia, upServer, 51820, 9000)
}

// A client egress spreads an ICMP upstream over the members of a reflect pool.
func TestClientReflectsThroughAPool(t *testing.T) {
	collection := upReflectClientCollection(t, protocol.TransportICMP, []netip.Addr{upViaA, upViaB}, false)
	defer collection.Close()
	frame := udpWireGuardFrame(t, upPeer, upAdvertised, 40000, 51820, 0)
	result, output, err := collection.Programs["mup_client_ingress"].Test(frame)
	if err != nil {
		t.Fatalf("program test: %v", err)
	}
	if result != tcActRedirect {
		t.Fatalf("return value = %d, want the redirect %d", int32(result), tcActRedirect)
	}
	assertUpReflectICMP(t, output, upViaA, upViaB)
}

// Without reflect members, an up path stays a direct path.
func TestClientWithoutMembersStaysDirect(t *testing.T) {
	collection := upReflectClientCollection(t, protocol.TransportUDP, nil, false)
	defer collection.Close()
	frame := udpWireGuardFrame(t, upPeer, upAdvertised, 40000, 51820, 0)
	result, output, err := collection.Programs["mup_client_ingress"].Test(frame)
	if err != nil {
		t.Fatalf("program test: %v", err)
	}
	if result != tcActRedirect {
		t.Fatalf("return value = %d, want the redirect %d", int32(result), tcActRedirect)
	}
	assertUDPHeader(t, output, upAdvertised, upServer, 51820, 9000)
}

// A server accepts a reflected upstream: an ICMP Echo Reply from the via of an
// up reflect registered path. The same reply on a path without the up reflect
// flag goes on to the kernel.
func TestServerAcceptsAReflectedUpstream(t *testing.T) {
	collection, client := targetIngressCollection(t)
	defer collection.Close()
	if err := collection.Maps["free_target_ports"].Update(nil, uint16(20000), ebpf.UpdateAny); err != nil {
		t.Fatalf("push a target port: %v", err)
	}
	pathKey := mupRegisteredPathKeyV1{
		SourceIp: mustTestWord(t, upVia), LocalIp: mustTestWord(t, ingressTarget),
		ServerPort: 5000, Transport: uint8(protocol.TransportICMP),
	}
	put := func(flags uint8) {
		t.Helper()
		value := mupRegisteredPathValueV1{Client: client, ExpiresAtNs: math.MaxUint64, Flags: flags}
		if err := collection.Maps["registered_paths"].Update(pathKey, value, ebpf.UpdateAny); err != nil {
			t.Fatalf("update registered path: %v", err)
		}
	}
	reply := icmpWireGuardFrame(t, upVia, ingressTarget, 0, 5000, 9)

	// With the up reflect flag, the Echo Reply is a reflected upstream.
	put(protocol.ControlFlagUpReflect)
	result, _, err := collection.Programs["mup_server_ingress"].Test(reply)
	if err != nil {
		t.Fatalf("program test: %v", err)
	}
	if result != tcActRedirect {
		t.Fatalf("with the flag: return value = %d, want the redirect %d", int32(result), tcActRedirect)
	}

	// Without the flag, the Echo Reply is a normal ping answer.
	put(0)
	result, output, err := collection.Programs["mup_server_ingress"].Test(reply)
	if err != nil {
		t.Fatalf("program test: %v", err)
	}
	if result != tcxNext || string(output) != string(reply) {
		t.Fatalf("without the flag: return value = %d, changed = %v, want TCX_NEXT and no change", int32(result), string(output) != string(reply))
	}
}
