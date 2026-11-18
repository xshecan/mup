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

const (
	tcActOK       = 0
	tcActShot     = 2
	tcActRedirect = 7
	tcxNext       = math.MaxUint32 // TCX_NEXT is -1.
)

var (
	ingressTarget     = netip.MustParseAddr("198.51.100.1")
	ingressClient     = netip.MustParseAddr("192.0.2.10")
	ingressMAC        = [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	ingressTargetPort = uint16(51820)
)

// targetIngressCollection loads the programs with a server that delivers to a
// target on this host through the ingress hook. A BPF test run uses the
// loopback device, so the delivery interface is ifindex 1.
func targetIngressCollection(t *testing.T) (*ebpf.Collection, mupClientKeyV1) {
	t.Helper()
	collection := loadTestCollection(t)
	put := func(name string, key, value any) {
		t.Helper()
		if err := collection.Maps[name].Update(key, value, ebpf.UpdateAny); err != nil {
			t.Fatalf("update %s: %v", name, err)
		}
	}
	target := mustTestWord(t, ingressTarget)
	put("server_config", uint32(0), mupServerConfigV1{
		TargetIp: target, SourceIp: target, Ifindex: 1,
		TargetPort: ingressTargetPort, ServerPort: 5000,
	})
	put("server_ports", uint32(0), mupServerPortsV1{First: 5000, Last: 5000})
	put("target_ingress", uint32(0), mupTargetIngressV1{Ifindex: 1, Mac: ingressMAC})
	client := mupClientKeyV1{AdvertisedIp: mustTestWord(t, ingressClient), InstanceNonce: 7}
	put("registration_by_key", client, mupRegistrationValueV1{ListenPort: 51821, ExpiresAtNs: math.MaxUint64})
	put("registered_paths", mupRegisteredPathKeyV1{
		SourceIp: client.AdvertisedIp, LocalIp: target, ServerPort: 5000,
		Transport: uint8(protocol.TransportUDP),
	}, mupRegisteredPathValueV1{Client: client, ExpiresAtNs: math.MaxUint64})
	return collection, client
}

func TestServerIngressInjectsIntoTheTargetInterface(t *testing.T) {
	collection, _ := targetIngressCollection(t)
	defer collection.Close()
	if err := collection.Maps["free_target_ports"].Update(nil, uint16(20000), ebpf.UpdateAny); err != nil {
		t.Fatalf("push a target port: %v", err)
	}
	packet := udpWireGuardFrame(t, ingressClient, ingressTarget, 51821, 5000, 9)
	result, output, err := collection.Programs["mup_server_ingress"].Test(packet)
	if err != nil {
		t.Fatalf("program test: %v", err)
	}
	if result != tcActRedirect {
		t.Fatalf("return value = %d, want the redirect %d", int32(result), tcActRedirect)
	}
	// The target sees the advertised IP of the client and the target port.
	if got := [6]byte(output[0:6]); got != ingressMAC {
		t.Fatalf("Ethernet destination = %x, want %x", got, ingressMAC)
	}
	assertUDPHeader(t, output, ingressClient, ingressTarget, 20000, ingressTargetPort)
	if token := output[14+20+8+1 : 14+20+8+4]; token[0]|token[1]|token[2] != 0 {
		t.Fatalf("WireGuard reserved bytes = %x, want zero", token)
	}
}

// A NAT can masquerade a flow to a pod with a port of the server range. The
// replies of the pod then reach the server program before conntrack restores
// their address. The program must leave them to the network stack.
func TestServerIngressPassesAPacketWithoutARegisteredPath(t *testing.T) {
	collection, _ := targetIngressCollection(t)
	defer collection.Close()
	program := collection.Programs["mup_server_ingress"]

	// A WireGuard reply of a pod has zero reserved bytes, so it has no token.
	pod := netip.MustParseAddr("10.1.0.55")
	nat := netip.MustParseAddr("10.1.0.1")
	reply := udpWireGuardFrame(t, pod, nat, 51820, 5000, 0)
	result, output, err := program.Test(reply)
	if err != nil {
		t.Fatalf("program test: %v", err)
	}
	if result != tcxNext || string(output) != string(reply) {
		t.Fatalf("pod reply: return value = %d, changed = %v, want TCX_NEXT and no change", int32(result), string(output) != string(reply))
	}
	if got := dropCount(t, collection, protocol.DropWireGuardReserved); got != 0 {
		t.Fatalf("WG_RESERVED drops after the pod reply = %d, want 0", got)
	}

	// A packet of a registered path without a token is still a MUP error.
	invalid := udpWireGuardFrame(t, ingressClient, ingressTarget, 51821, 5000, 0)
	result, _, err = program.Test(invalid)
	if err != nil {
		t.Fatalf("program test: %v", err)
	}
	if result != tcActShot {
		t.Fatalf("client packet without a token: return value = %d, want the drop %d", int32(result), tcActShot)
	}
	if got := dropCount(t, collection, protocol.DropWireGuardReserved); got != 1 {
		t.Fatalf("WG_RESERVED drops after the client packet = %d, want 1", got)
	}
}

func dropCount(t *testing.T, collection *ebpf.Collection, reason protocol.DropReason) uint64 {
	t.Helper()
	var values []uint64
	if err := collection.Maps["stats"].Lookup(uint32(reason), &values); err != nil {
		t.Fatalf("read drop count %d: %v", reason, err)
	}
	return aggregatePerCPU(values)
}

func TestServerEgressCatchesTheTargetReply(t *testing.T) {
	collection, client := targetIngressCollection(t)
	defer collection.Close()
	routeKey := mupServerRouteKeyV1{Client: client, PeerToken: 9}
	routeValue := mupServerRouteValueV1{
		TargetPort: 20000, ServerPort: 5000, Transport: uint8(protocol.TransportUDP),
		ClientSourceIp: client.AdvertisedIp, ServerLocalIp: mustTestWord(t, ingressTarget), Ifindex: 1,
	}
	if err := collection.Maps["server_route_by_key"].Update(routeKey, routeValue, ebpf.UpdateAny); err != nil {
		t.Fatalf("update forward route: %v", err)
	}
	reverse := mupServerReverseValueV1{RouteKey: routeKey, RouteValue: routeValue}
	if err := collection.Maps["server_route_by_port"].Update(uint16(20000), reverse, ebpf.UpdateAny); err != nil {
		t.Fatalf("update reverse route: %v", err)
	}
	program := collection.Programs["mup_server_egress"]

	reply := udpWireGuardFrame(t, ingressTarget, ingressClient, ingressTargetPort, 20000, 0)
	result, output, err := program.Test(reply)
	if err != nil {
		t.Fatalf("program test: %v", err)
	}
	if result != tcActOK && result != tcActRedirect {
		t.Fatalf("return value = %d, want pass or redirect", int32(result))
	}
	assertUDPHeader(t, output, ingressTarget, ingressClient, 5000, 51821)
	if token := output[14+20+8+1 : 14+20+8+4]; token[0] != 0 || token[1] != 0 || token[2] != 9 {
		t.Fatalf("peer token bytes = %x, want 000009", token)
	}

	// A packet that does not come from the target port goes on unchanged.
	other := udpWireGuardFrame(t, ingressTarget, ingressClient, ingressTargetPort+1, 20000, 0)
	result, output, err = program.Test(other)
	if err != nil {
		t.Fatalf("program test: %v", err)
	}
	if result != tcxNext || string(output) != string(other) {
		t.Fatalf("other packet: return value = %d, changed = %v, want TCX_NEXT and no change", int32(result), string(output) != string(other))
	}
}

// udpWireGuardFrame builds an Ethernet IPv4 UDP frame with a WireGuard data
// message, the peer token in the reserved bytes, and a full UDP checksum.
func udpWireGuardFrame(t *testing.T, source, destination netip.Addr, sourcePort, destinationPort uint16, token uint32) []byte {
	t.Helper()
	payload := make([]byte, 48)
	payload[0] = 4
	payload[1], payload[2], payload[3] = byte(token>>16), byte(token>>8), byte(token)
	for index := 16; index < len(payload); index++ {
		payload[index] = byte(index)
	}
	frame := make([]byte, 14+20+8+len(payload))
	frame[12], frame[13] = 0x08, 0x00
	ip := frame[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64
	ip[9] = protocol.IPProtocolUDP
	copy(ip[12:16], source.AsSlice())
	copy(ip[16:20], destination.AsSlice())
	binary.BigEndian.PutUint16(ip[10:12], onesComplement(ip[:20], 0))
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:2], sourcePort)
	binary.BigEndian.PutUint16(udp[2:4], destinationPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	binary.BigEndian.PutUint16(udp[6:8], onesComplement(udp, pseudoHeaderSum(ip)))
	return frame
}

// assertUDPHeader checks the addresses and ports of a frame, and that its IPv4
// and UDP checksums are valid.
func assertUDPHeader(t *testing.T, frame []byte, source, destination netip.Addr, sourcePort, destinationPort uint16) {
	t.Helper()
	ip := frame[14:]
	if got := netip.AddrFrom4([4]byte(ip[12:16])); got != source {
		t.Fatalf("IPv4 source = %s, want %s", got, source)
	}
	if got := netip.AddrFrom4([4]byte(ip[16:20])); got != destination {
		t.Fatalf("IPv4 destination = %s, want %s", got, destination)
	}
	if ip[9] != protocol.IPProtocolUDP {
		t.Fatalf("IPv4 protocol = %d, want UDP", ip[9])
	}
	udp := ip[20:binary.BigEndian.Uint16(ip[2:4])]
	if got := binary.BigEndian.Uint16(udp[0:2]); got != sourcePort {
		t.Fatalf("UDP source port = %d, want %d", got, sourcePort)
	}
	if got := binary.BigEndian.Uint16(udp[2:4]); got != destinationPort {
		t.Fatalf("UDP destination port = %d, want %d", got, destinationPort)
	}
	if onesComplement(ip[:20], 0) != 0 {
		t.Fatal("IPv4 header checksum is invalid")
	}
	if onesComplement(udp, pseudoHeaderSum(ip)) != 0 {
		t.Fatal("UDP checksum is invalid")
	}
}

func pseudoHeaderSum(ip []byte) uint32 {
	var sum uint32
	for index := 12; index < 20; index += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[index:]))
	}
	return sum + uint32(ip[9]) + uint32(binary.BigEndian.Uint16(ip[2:4])) - 20
}

// onesComplement returns the one's complement checksum of data with an initial
// sum. A valid checksummed block gives zero.
func onesComplement(data []byte, sum uint32) uint16 {
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func mustTestWord(t *testing.T, address netip.Addr) uint32 {
	t.Helper()
	word, err := requiredIPv4Word(address, "test address")
	if err != nil {
		t.Fatal(err)
	}
	return word
}
