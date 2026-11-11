package protocol

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func TestParseIPv4UDP(t *testing.T) {
	t.Parallel()

	payload := makeWireGuardPacket(MessageHandshakeInitiation, HandshakeInitiationLength)
	packet := ipv4Packet(17, 20+8+len(payload))
	binary.BigEndian.PutUint16(packet[20:22], 51820)
	binary.BigEndian.PutUint16(packet[22:24], 5000)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	copy(packet[28:], payload)

	parsed, err := ParseIPv4L4(packet)
	if err != nil {
		t.Fatalf("ParseIPv4L4: %v", err)
	}
	if parsed.Source != netip.MustParseAddr("192.0.2.10") || parsed.Destination != netip.MustParseAddr("198.51.100.1") {
		t.Fatalf("addresses = %v -> %v", parsed.Source, parsed.Destination)
	}
	if parsed.Protocol != IPProtocolUDP || parsed.SourcePort != 51820 || parsed.DestinationPort != 5000 {
		t.Fatalf("UDP tuple = %#v", parsed)
	}
	if len(parsed.Payload) != len(payload) || parsed.Payload[0] != MessageHandshakeInitiation {
		t.Fatalf("payload length/type = %d/%d", len(parsed.Payload), parsed.Payload[0])
	}
}

func TestParseIPv4ICMP(t *testing.T) {
	t.Parallel()

	payload := makeWireGuardPacket(MessageHandshakeResponse, HandshakeResponseLength)
	packet := ipv4Packet(1, 20+8+len(payload))
	packet[20] = 8
	binary.BigEndian.PutUint16(packet[24:26], 5000)
	binary.BigEndian.PutUint16(packet[26:28], 7)
	copy(packet[28:], payload)

	parsed, err := ParseIPv4L4(packet)
	if err != nil {
		t.Fatalf("ParseIPv4L4: %v", err)
	}
	if parsed.Protocol != IPProtocolICMP || parsed.ICMPType != 8 || parsed.ICMPIdentifier != 5000 || parsed.ICMPSequence != 7 {
		t.Fatalf("ICMP fields = %#v", parsed)
	}
}

func TestParseIPv4RejectsOptionsAndFragments(t *testing.T) {
	t.Parallel()

	options := ipv4Packet(17, 28)
	options[0] = 0x46
	if _, err := ParseIPv4L4(options); !errors.Is(err, ErrIPv4Options) {
		t.Fatalf("options error = %v, want %v", err, ErrIPv4Options)
	}
	fragment := ipv4Packet(17, 28)
	binary.BigEndian.PutUint16(fragment[6:8], 0x2000)
	if _, err := ParseIPv4L4(fragment); !errors.Is(err, ErrIPv4Fragment) {
		t.Fatalf("fragment error = %v, want %v", err, ErrIPv4Fragment)
	}
}

func ipv4Packet(protocol byte, length int) []byte {
	packet := make([]byte, length)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	packet[8] = 64
	packet[9] = protocol
	copy(packet[12:16], netip.MustParseAddr("192.0.2.10").AsSlice())
	copy(packet[16:20], netip.MustParseAddr("198.51.100.1").AsSlice())
	return packet
}
