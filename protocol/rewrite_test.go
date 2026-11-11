package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net/netip"
	"testing"
)

var (
	testClientIP = netip.MustParseAddr("203.0.113.10")
	testServerIP = netip.MustParseAddr("198.51.100.9")
)

func TestRewriteBetweenTransportsKeepsChecksumsValid(t *testing.T) {
	t.Parallel()

	messages := []struct {
		name   string
		typeID byte
		length int
	}{
		{name: "initiation", typeID: MessageHandshakeInitiation, length: HandshakeInitiationLength},
		{name: "response", typeID: MessageHandshakeResponse, length: HandshakeResponseLength},
		{name: "cookie", typeID: MessageCookieReply, length: CookieReplyLength},
		{name: "data", typeID: MessageTransportData, length: 1424},
	}
	for _, message := range messages {
		for _, input := range []uint8{IPProtocolUDP, IPProtocolICMP} {
			for _, output := range []uint8{IPProtocolUDP, IPProtocolICMP} {
				name := message.name + "/" + protocolName(input) + "-to-" + protocolName(output)
				t.Run(name, func(t *testing.T) {
					t.Parallel()

					random := rand.New(rand.NewPCG(uint64(message.length), uint64(input)<<8|uint64(output)))
					payload := randomWireGuardPayload(random, message.typeID, message.length)
					packet := buildPacket(t, input, payload)

					if err := RewritePeerToken(packet, 17); err != nil {
						t.Fatalf("RewritePeerToken: %v", err)
					}
					assertChecksumsValid(t, packet)
					rewriteTo(t, packet, output, 17)
					assertChecksumsValid(t, packet)

					parsed, err := ParseIPv4L4(packet)
					if err != nil {
						t.Fatalf("parse rewritten packet: %v", err)
					}
					if parsed.Protocol != output || parsed.Source != testClientIP || parsed.Destination != testServerIP {
						t.Fatalf("rewritten header = %#v", parsed)
					}
					want := bytes.Clone(payload)
					want[3] = 17
					if !bytes.Equal(parsed.Payload, want) {
						t.Fatal("rewrite changed WireGuard bytes other than the peer token")
					}
				})
			}
		}
	}
}

func TestRewriteChainKeepsChecksumsValid(t *testing.T) {
	t.Parallel()

	random := rand.New(rand.NewPCG(7, 11))
	for iteration := range 2000 {
		length := 32 + 16*random.IntN(90)
		input := []uint8{IPProtocolUDP, IPProtocolICMP}[random.IntN(2)]
		packet := buildPacket(t, input, randomWireGuardPayload(random, MessageTransportData, length))
		token := uint32(1 + random.IntN(int(MaxPeerToken)))
		if err := RewritePeerToken(packet, token); err != nil {
			t.Fatalf("iteration %d: RewritePeerToken: %v", iteration, err)
		}
		// Burst mode rewrites one packet once for every healthy path.
		for range 1 + random.IntN(8) {
			output := []uint8{IPProtocolUDP, IPProtocolICMP}[random.IntN(2)]
			rewriteTo(t, packet, output, token)
			assertChecksumsValid(t, packet)
		}
		if err := RewritePeerToken(packet, 0); err != nil {
			t.Fatalf("iteration %d: clear peer token: %v", iteration, err)
		}
		assertChecksumsValid(t, packet)
	}
}

func TestRewriteHandlesUDPChecksumSentAsAllOnes(t *testing.T) {
	t.Parallel()

	payload := makeWireGuardPacket(MessageTransportData, 64)
	packet := buildPacket(t, IPProtocolUDP, payload)
	// Adjust the last payload word so that the computed checksum is zero,
	// which UDP sends as 0xffff.
	binary.BigEndian.PutUint16(packet[26:28], 0)
	last := len(packet) - 2
	word := uint32(binary.BigEndian.Uint16(packet[last:]))
	binary.BigEndian.PutUint16(packet[last:], checksumFold(word+uint32(udpChecksum(packet))))
	binary.BigEndian.PutUint16(packet[26:28], udpChecksum(packet))
	if checksum := binary.BigEndian.Uint16(packet[26:28]); checksum != 0 {
		t.Fatalf("setup checksum = %#04x, want 0", checksum)
	}
	binary.BigEndian.PutUint16(packet[26:28], 0xffff)
	assertChecksumsValid(t, packet)

	rewriteTo(t, packet, IPProtocolICMP, 1)
	assertChecksumsValid(t, packet)
	rewriteTo(t, packet, IPProtocolUDP, 1)
	assertChecksumsValid(t, packet)
}

func TestRewriteRejectsUDPWithoutChecksum(t *testing.T) {
	t.Parallel()

	packet := buildPacket(t, IPProtocolUDP, makeWireGuardPacket(MessageCookieReply, CookieReplyLength))
	binary.BigEndian.PutUint16(packet[26:28], 0)
	if err := RewritePeerToken(packet, 5); err != nil {
		t.Fatalf("RewritePeerToken: %v", err)
	}
	if checksum := binary.BigEndian.Uint16(packet[26:28]); checksum != 0 {
		t.Fatalf("absent UDP checksum became %#04x", checksum)
	}
	err := RewriteICMP(packet, testClientIP, testServerIP, 8, 5000, 5)
	if !errors.Is(err, ErrRewriteChecksum) {
		t.Fatalf("RewriteICMP error = %v, want %v", err, ErrRewriteChecksum)
	}
}

func TestRewritePeerTokenRejectsOutOfRangeToken(t *testing.T) {
	t.Parallel()

	packet := buildPacket(t, IPProtocolICMP, makeWireGuardPacket(MessageCookieReply, CookieReplyLength))
	if err := RewritePeerToken(packet, MaxPeerToken+1); !errors.Is(err, ErrPeerTokenRange) {
		t.Fatalf("RewritePeerToken error = %v, want %v", err, ErrPeerTokenRange)
	}
}

func rewriteTo(t *testing.T, packet []byte, output uint8, token uint32) {
	t.Helper()
	var err error
	if output == IPProtocolUDP {
		err = RewriteUDP(packet, testClientIP, testServerIP, 51820, 5000)
	} else {
		err = RewriteICMP(packet, testClientIP, testServerIP, 8, 5000, uint16(token))
	}
	if err != nil {
		t.Fatalf("rewrite to %s: %v", protocolName(output), err)
	}
}

// buildPacket returns an IPv4 packet with valid IPv4 and transport checksums.
func buildPacket(t *testing.T, protocol uint8, payload []byte) []byte {
	t.Helper()
	packet := ipv4Packet(protocol, 20+8+len(payload))
	l4 := packet[20:]
	copy(l4[8:], payload)
	if protocol == IPProtocolUDP {
		binary.BigEndian.PutUint16(l4[0:2], 40000)
		binary.BigEndian.PutUint16(l4[2:4], 51820)
		binary.BigEndian.PutUint16(l4[4:6], uint16(len(l4)))
		checksum := udpChecksum(packet)
		if checksum == 0 {
			checksum = 0xffff
		}
		binary.BigEndian.PutUint16(l4[6:8], checksum)
	} else {
		l4[0] = 0
		binary.BigEndian.PutUint16(l4[4:6], 5000)
		binary.BigEndian.PutUint16(l4[6:8], 9)
		binary.BigEndian.PutUint16(l4[2:4], internetChecksum(l4))
	}
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[:20]))
	assertChecksumsValid(t, packet)
	return packet
}

// assertChecksumsValid recomputes both checksums over the whole packet.
func assertChecksumsValid(t *testing.T, packet []byte) {
	t.Helper()
	if internetChecksum(packet[:20]) != 0 {
		t.Fatal("IPv4 header checksum is invalid")
	}
	l4 := packet[20:]
	switch packet[9] {
	case IPProtocolUDP:
		if binary.BigEndian.Uint16(l4[6:8]) == 0 {
			t.Fatal("UDP checksum is absent")
		}
		if udpChecksum(packet) != 0 {
			t.Fatal("UDP checksum is invalid")
		}
	case IPProtocolICMP:
		if internetChecksum(l4) != 0 {
			t.Fatal("ICMP checksum is invalid")
		}
	default:
		t.Fatalf("unexpected protocol %d", packet[9])
	}
}

// udpChecksum returns the full UDP checksum over the pseudo-header and the
// UDP segment, including the current checksum field.
func udpChecksum(packet []byte) uint16 {
	l4 := packet[20:]
	sum := sumWords(packet[12:20], 0)
	sum += uint32(IPProtocolUDP) + uint32(len(l4))
	return ^checksumFold(sumWords(l4, sum))
}

func randomWireGuardPayload(random *rand.Rand, typeID byte, length int) []byte {
	payload := make([]byte, length)
	for index := range payload {
		payload[index] = byte(random.Uint32())
	}
	payload[0] = typeID
	payload[1], payload[2], payload[3] = 0, 0, 0
	return payload
}

func protocolName(protocol uint8) string {
	if protocol == IPProtocolUDP {
		return "udp"
	}
	return "icmp"
}
