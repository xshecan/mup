//go:build linux

package dataplane

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/xshecan/mup/protocol"
)

var (
	zeroUser       = netip.MustParseAddr("203.0.113.7")
	zeroAdvertised = netip.MustParseAddr("192.0.2.20")
	zeroServer     = netip.MustParseAddr("198.51.100.9")
)

// A sender can send a UDP checksum of zero for no checksum, and some NAT
// devices write zero for a computed checksum of zero, where RFC 768 says
// 0xffff. The client must give such a packet a valid checksum on each path.
func TestClientIngressCompletesAZeroUDPChecksum(t *testing.T) {
	for _, transport := range []protocol.TransportID{protocol.TransportUDP, protocol.TransportICMP} {
		// 48 bytes take only the short parts of the sum, and 1440 bytes
		// also take two full chunks.
		for _, length := range []int{48, 1440} {
			collection := zeroChecksumClientCollection(t, transport)
			packet := zeroChecksumFrame(t, zeroUser, zeroAdvertised, 40000, 51820, 0, length)
			result, output, err := collection.Programs["mup_client_ingress"].Test(packet)
			drops := dropCount(t, collection, protocol.DropChecksum)
			collection.Close()
			if err != nil {
				t.Fatalf("%v, length %d: program test: %v", transport, length, err)
			}
			if result != tcActRedirect || drops != 0 {
				t.Fatalf("%v, length %d: return value = %d, CHECKSUM drops = %d, want the redirect %d and no drop",
					transport, length, int32(result), drops, tcActRedirect)
			}
			ip := output[14:]
			l4 := ip[20:binary.BigEndian.Uint16(ip[2:4])]
			if len(l4) != 8+length {
				t.Fatalf("%v, length %d: transport length = %d, want %d", transport, length, len(l4), 8+length)
			}
			if onesComplement(ip[:20], 0) != 0 {
				t.Fatalf("%v, length %d: IPv4 header checksum is invalid", transport, length)
			}
			if transport == protocol.TransportUDP {
				assertUDPHeader(t, output, zeroAdvertised, zeroServer, 51820, 9000)
				if binary.BigEndian.Uint16(l4[6:8]) == 0 {
					t.Fatalf("length %d: UDP checksum is still zero", length)
				}
			} else {
				if ip[9] != protocol.IPProtocolICMP || l4[0] != 8 {
					t.Fatalf("length %d: protocol %d, ICMP type %d, want an Echo Request", length, ip[9], l4[0])
				}
				if onesComplement(l4, 0) != 0 {
					t.Fatalf("length %d: ICMP checksum is invalid", length)
				}
			}
			if token := l4[9:12]; token[0] != 0 || token[1] != 0 || token[2] != 5 {
				t.Fatalf("%v, length %d: peer token bytes = %x, want 000005", transport, length, token)
			}
		}
	}
}

// A NAT between the client and the server can write the same zero.
func TestServerIngressCompletesAZeroUDPChecksum(t *testing.T) {
	collection, _ := targetIngressCollection(t)
	defer collection.Close()
	if err := collection.Maps["free_target_ports"].Update(nil, uint16(20000), ebpf.UpdateAny); err != nil {
		t.Fatalf("push a target port: %v", err)
	}
	packet := zeroChecksumFrame(t, ingressClient, ingressTarget, 51821, 5000, 9, 1440)
	result, output, err := collection.Programs["mup_server_ingress"].Test(packet)
	if err != nil {
		t.Fatalf("program test: %v", err)
	}
	if drops := dropCount(t, collection, protocol.DropChecksum); result != tcActRedirect || drops != 0 {
		t.Fatalf("return value = %d, CHECKSUM drops = %d, want the redirect %d and no drop", int32(result), drops, tcActRedirect)
	}
	assertUDPHeader(t, output, ingressClient, ingressTarget, 20000, ingressTargetPort)
	if token := output[14+20+8+1 : 14+20+8+4]; token[0]|token[1]|token[2] != 0 {
		t.Fatalf("WireGuard reserved bytes = %x, want zero", token)
	}
}

// zeroChecksumClientCollection loads the programs with a client that has one
// healthy path of the given transport in group 51820, and one free token.
func zeroChecksumClientCollection(t *testing.T, transport protocol.TransportID) *ebpf.Collection {
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
	put("path_groups", uint16(51820), mupPathGroupV1{Mode: 0, PathMask: 1})
	put("path_config", uint32(0), mupPathConfigV1{
		DestinationIp: mustTestWord(t, zeroServer), SourceIp: advertised,
		Ifindex: 1, ServerPort: 9000, Transport: uint8(transport),
	})
	put("path_state", uint32(0), mupPathStateV1{HealthyMask: 1})
	if err := collection.Maps["free_peer_tokens"].Update(nil, uint32(5), ebpf.UpdateAny); err != nil {
		t.Fatalf("push a peer token: %v", err)
	}
	return collection
}

// zeroChecksumFrame builds the frame of a WireGuard data message with the
// given payload length, the peer token in the reserved bytes, and a UDP
// checksum field of zero.
func zeroChecksumFrame(t *testing.T, source, destination netip.Addr, sourcePort, destinationPort uint16, token uint32, length int) []byte {
	t.Helper()
	frame := udpPartialWireGuardFrame(t, source, destination, sourcePort, destinationPort, length)
	payload := frame[14+20+8:]
	payload[0] = 4
	payload[1], payload[2], payload[3] = byte(token>>16), byte(token>>8), byte(token)
	frame[14+20+6], frame[14+20+7] = 0, 0
	return frame
}
