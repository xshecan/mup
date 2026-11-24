package app

import (
	"encoding/binary"
	"net/netip"

	"github.com/xshecan/mup/protocol"
)

// egressWirePacket builds the IPv4 packet that the server sends for a frame on
// an egress path, as the server program sends a reply on it, and returns its
// destination. A direct path sends egressPacket. A bridge path wraps a packet
// for the bridge. Without bridgeVia, the wrapper leaves from localIP and holds
// the packet of the via. With bridgeVia, the wrapper leaves from the member and
// holds the direct packet from the bridge address, which the bridge sends.
func egressWirePacket(target egressTarget, frame []byte, sequence uint16) ([]byte, netip.Addr) {
	if !target.bridge {
		return egressPacket(target, frame, sequence)
	}
	if !target.bridgeVia {
		inner, _ := egressPacket(target, frame, sequence)
		return protocol.WrapForBridge(inner, target.localIP, target.server, target.port), target.server
	}
	outerSource := target.member
	if !outerSource.IsValid() {
		outerSource = target.localIP
	}
	direct := target
	direct.member = netip.Addr{}
	inner, _ := egressPacket(direct, frame, sequence)
	return protocol.WrapForBridge(inner, outerSource, target.server, target.port), target.server
}

// egressPacket builds the IPv4 packet of a frame on an egress path, and returns its
// destination. The source is the server address of a direct path, the reflector
// of a UDP path with a return IP or pool, and the client of an ICMP path that
// reflects.
func egressPacket(target egressTarget, frame []byte, sequence uint16) ([]byte, netip.Addr) {
	client := target.client.AdvertisedIP
	switch {
	case target.transport == protocol.TransportUDP:
		source := target.server
		if target.member.IsValid() {
			source = target.member
		}
		return buildIPv4UDP(source, client, target.port, target.listenPort, frame), client
	case target.member.IsValid():
		echo := marshalICMPEcho(icmpEchoRequest, target.port, sequence, frame)
		return buildIPv4ICMP(client, target.member, echo), target.member
	default:
		echo := marshalICMPEcho(icmpEchoReply, target.port, sequence, frame)
		return buildIPv4ICMP(target.server, client, echo), client
	}
}

// buildIPv4ICMP puts an ICMP message in an IPv4 packet.
func buildIPv4ICMP(source, destination netip.Addr, message []byte) []byte {
	totalLength := 20 + len(message)
	packet := make([]byte, totalLength)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLength))
	packet[8] = 64
	packet[9] = ipProtocolICMP
	sourceBytes := source.As4()
	destinationBytes := destination.As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], destinationBytes[:])
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[0:20]))
	copy(packet[20:], message)
	return packet
}

// buildIPv4UDP builds an IPv4 UDP packet with the given header fields. The UDP
// checksum is zero, which IPv4 allows.
func buildIPv4UDP(source, destination netip.Addr, sourcePort, destinationPort uint16, payload []byte) []byte {
	udpLength := 8 + len(payload)
	totalLength := 20 + udpLength
	packet := make([]byte, totalLength)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLength))
	packet[8] = 64
	packet[9] = ipProtocolUDP
	sourceBytes := source.As4()
	destinationBytes := destination.As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], destinationBytes[:])
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[0:20]))
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(udpLength))
	copy(packet[28:], payload)
	return packet
}
