package app

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/protocol"
)

func TestICMPEchoRoundTrip(t *testing.T) {
	t.Parallel()

	payload := bytes.Repeat([]byte{0x5a}, 48)
	packet := marshalICMPEcho(icmpEchoRequest, 5000, 7, payload)
	echo, err := parseICMPEcho(packet)
	if err != nil {
		t.Fatalf("parseICMPEcho: %v", err)
	}
	if echo.echoType != icmpEchoRequest || echo.identifier != 5000 || echo.sequence != 7 ||
		!bytes.Equal(echo.payload, payload) {
		t.Fatalf("echo = %#v", echo)
	}

	packet[2] ^= 0xff
	if _, err := parseICMPEcho(packet); err == nil {
		t.Fatal("corrupted checksum unexpectedly accepted")
	}
}

func TestRegistrationACKRejectsStaleSequence(t *testing.T) {
	t.Parallel()

	packet := make([]byte, protocol.ControlFrameLength)
	err := protocol.EncodeControlFrame(packet, protocol.ControlFrame{
		Type:          protocol.ControlRegisterACK,
		Transport:     protocol.TransportICMP,
		PathID:        2,
		Sequence:      7,
		ListenPort:    51820,
		ServerPort:    5000,
		LeaseSeconds:  30,
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		InstanceNonce: 99,
	})
	if err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
	}
	if err := validateRegistrationACK(packet, 99, 2, 7); err != nil {
		t.Fatalf("validateRegistrationACK: %v", err)
	}
	if err := validateRegistrationACK(packet, 99, 2, 8); err == nil {
		t.Fatal("stale ACK sequence unexpectedly accepted")
	}
}

func TestRegistrationACKResultReadsTheStatus(t *testing.T) {
	t.Parallel()

	ack := func(status protocol.ControlStatus) []byte {
		packet := make([]byte, protocol.ControlFrameLength)
		err := protocol.EncodeControlFrame(packet, protocol.ControlFrame{
			Type:          protocol.ControlRegisterACK,
			Transport:     protocol.TransportUDP,
			Status:        status,
			PathID:        4,
			Sequence:      3,
			ListenPort:    51821,
			ServerPort:    9002,
			LeaseSeconds:  30,
			AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
			InstanceNonce: 99,
		})
		if err != nil {
			t.Fatalf("EncodeControlFrame: %v", err)
		}
		return packet
	}
	if result, ok := registrationACKResult(ack(protocol.ControlStatusOK), 99, 4, 3); !ok || result != registerAcked {
		t.Fatalf("OK ACK = %v %v, want acked", result, ok)
	}
	if result, ok := registrationACKResult(ack(protocol.ControlStatusNoReflector), 99, 4, 3); !ok || result != registerNoReflector {
		t.Fatalf("no-reflector ACK = %v %v, want no reflector", result, ok)
	}
	if err := validateRegistrationACK(ack(protocol.ControlStatusNoReflector), 99, 4, 3); err == nil {
		t.Fatal("a no-reflector ACK validated as a healthy ACK")
	}
	// A status that the client does not act on is not an answer.
	if _, ok := registrationACKResult(ack(protocol.ControlStatusMalformed), 99, 4, 3); ok {
		t.Fatal("a malformed-status ACK was taken as an answer")
	}
	if _, ok := registrationACKResult(ack(protocol.ControlStatusNoReflector), 99, 4, 2); ok {
		t.Fatal("an ACK of another sequence was taken as an answer")
	}
}

func TestPickReflectMemberTakesTheHealthyMembersInTurn(t *testing.T) {
	t.Parallel()

	candidates := []netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2"), netip.MustParseAddr("203.0.113.3")}
	healthy := []netip.Addr{candidates[1], candidates[2]}
	for turn, want := range []netip.Addr{healthy[0], healthy[1], healthy[0]} {
		if member, ok := pickReflectMember(healthy, candidates, uint(turn)); !ok || member != want {
			t.Fatalf("turn %d member = %s, %v, want %s", turn, member, ok, want)
		}
	}
	for turn, want := range []netip.Addr{candidates[0], candidates[1], candidates[2], candidates[0]} {
		if member, ok := pickReflectMember(nil, candidates, uint(turn)); !ok || member != want {
			t.Fatalf("turn %d without healthy members = %s, %v, want %s", turn, member, ok, want)
		}
	}
	if _, ok := pickReflectMember(nil, nil, 0); ok {
		t.Fatal("a path without members picked a member")
	}
}

func TestReflectedControlPacketForgesTheMemberForUDP(t *testing.T) {
	t.Parallel()

	reg := reflectRegistration(protocol.TransportUDP)
	member := netip.MustParseAddr("203.0.113.2")
	frame := bytes.Repeat([]byte{0xab}, protocol.ControlFrameLength)
	packet, destination := reflectedControlPacket(reg, member, frame, 7)
	if destination != reg.path.Server {
		t.Fatalf("destination = %s, want the server %s", destination, reg.path.Server)
	}
	source, target, protocolNumber, payload := parseTestIPv4(t, packet)
	if source != member || target != reg.path.Server || protocolNumber != ipProtocolUDP {
		t.Fatalf("IPv4 header = %s to %s protocol %d", source, target, protocolNumber)
	}
	if sourcePort, destinationPort := binary.BigEndian.Uint16(payload[0:2]), binary.BigEndian.Uint16(payload[2:4]); sourcePort != reg.listenPort || destinationPort != reg.path.ServerPort {
		t.Fatalf("UDP ports = %d to %d, want %d to %d", sourcePort, destinationPort, reg.listenPort, reg.path.ServerPort)
	}
	if udpChecksum(source, target, zeroChecksum(payload)) != binary.BigEndian.Uint16(payload[6:8]) {
		t.Fatal("the UDP checksum is wrong")
	}
	if !bytes.Equal(payload[8:], frame) {
		t.Fatal("the UDP payload is not the frame")
	}
}

func TestReflectedControlPacketSendsAnEchoRequestFromTheServerForICMP(t *testing.T) {
	t.Parallel()

	reg := reflectRegistration(protocol.TransportICMP)
	member := netip.MustParseAddr("203.0.113.2")
	frame := bytes.Repeat([]byte{0xcd}, protocol.ControlFrameLength)
	packet, destination := reflectedControlPacket(reg, member, frame, 7)
	if destination != member {
		t.Fatalf("destination = %s, want the member %s", destination, member)
	}
	source, target, protocolNumber, payload := parseTestIPv4(t, packet)
	if source != reg.path.Server || target != member || protocolNumber != ipProtocolICMP {
		t.Fatalf("IPv4 header = %s to %s protocol %d", source, target, protocolNumber)
	}
	echo, err := parseICMPEcho(payload)
	if err != nil {
		t.Fatalf("parseICMPEcho: %v", err)
	}
	if echo.echoType != icmpEchoRequest || echo.identifier != reg.path.ServerPort || echo.sequence != 7 || !bytes.Equal(echo.payload, frame) {
		t.Fatalf("echo = %#v", echo)
	}
}

func reflectRegistration(transport protocol.TransportID) pathRegistration {
	return pathRegistration{
		advertisedIP: netip.MustParseAddr("192.0.2.10"),
		listenPort:   51820,
		path: config.Path{
			Server:     netip.MustParseAddr("198.51.100.1"),
			ServerPort: 9000,
			Transport:  transport,
		},
	}
}

// parseTestIPv4 checks the IPv4 header of a built packet and returns its
// addresses, its protocol, and its payload.
func parseTestIPv4(t *testing.T, packet []byte) (netip.Addr, netip.Addr, byte, []byte) {
	t.Helper()
	if len(packet) < 20 || packet[0] != 0x45 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
		t.Fatalf("bad IPv4 header % x", packet[:min(len(packet), 20)])
	}
	if internetChecksum(packet[:20]) != 0 {
		t.Fatal("the IPv4 header checksum is wrong")
	}
	return netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20])), packet[9], packet[20:]
}

func zeroChecksum(segment []byte) []byte {
	copied := bytes.Clone(segment)
	copied[6], copied[7] = 0, 0
	return copied
}
