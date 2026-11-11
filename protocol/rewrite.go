package protocol

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// This file mirrors the TCX rewrite in bpf/include/rewrite.h. MUP changes only
// the IPv4 addresses and protocol, the 8-byte UDP or ICMP header, and the peer
// token in WireGuard bytes 1 to 3. Each change updates the transport checksum
// incrementally (RFC 1624), so the cost does not depend on the payload length.

var (
	ErrRewriteAddress  = errors.New("rewrite requires IPv4 addresses")
	ErrRewriteChecksum = errors.New("UDP packet has no checksum to update")
)

// RewriteUDP rewrites a UDP or ICMP packet in place into a UDP packet.
func RewriteUDP(packet []byte, source, destination netip.Addr, sourcePort, destinationPort uint16) error {
	l4, payloadSum, err := beginRewrite(packet, source, destination)
	if err != nil {
		return err
	}
	packet[9] = IPProtocolUDP
	binary.BigEndian.PutUint16(l4[0:2], sourcePort)
	binary.BigEndian.PutUint16(l4[2:4], destinationPort)
	binary.BigEndian.PutUint16(l4[4:6], uint16(len(l4)))
	finishRewrite(packet, l4, payloadSum)
	return nil
}

// RewriteICMP rewrites a UDP or ICMP packet in place into an ICMP Echo packet.
func RewriteICMP(packet []byte, source, destination netip.Addr, icmpType uint8, identifier, sequence uint16) error {
	l4, payloadSum, err := beginRewrite(packet, source, destination)
	if err != nil {
		return err
	}
	packet[9] = IPProtocolICMP
	l4[0] = icmpType
	l4[1] = 0
	binary.BigEndian.PutUint16(l4[4:6], identifier)
	binary.BigEndian.PutUint16(l4[6:8], sequence)
	finishRewrite(packet, l4, payloadSum)
	return nil
}

// RewritePeerToken stores a peer token in the WireGuard reserved bytes of a
// UDP or ICMP packet, or clears them when token is zero, and updates the
// transport checksum. A UDP checksum of zero stays zero.
func RewritePeerToken(packet []byte, token uint32) error {
	parsed, err := ParseIPv4L4(packet)
	if err != nil {
		return err
	}
	if token > MaxPeerToken {
		return ErrPeerTokenRange
	}
	if len(parsed.Payload) < 4 {
		return ErrWireGuardLength
	}
	l4 := packet[20 : 28+len(parsed.Payload)]
	payload := parsed.Payload
	checksum := transportChecksum(parsed.Protocol, l4)
	sum := uint32(^checksum)
	sum += uint32(^checksumFold(wordAt(payload, 0) + wordAt(payload, 2)))
	payload[1] = byte(token >> 16)
	payload[2] = byte(token >> 8)
	payload[3] = byte(token)
	sum += wordAt(payload, 0) + wordAt(payload, 2)
	if parsed.Protocol == IPProtocolUDP && checksum == 0 {
		return nil
	}
	writeTransportChecksum(parsed.Protocol, l4, ^checksumFold(sum))
	return nil
}

// beginRewrite derives the payload sum from the current transport checksum
// and writes the new IPv4 addresses. It returns the transport segment.
func beginRewrite(packet []byte, source, destination netip.Addr) ([]byte, uint32, error) {
	if !source.Is4() || !destination.Is4() {
		return nil, 0, ErrRewriteAddress
	}
	parsed, err := ParseIPv4L4(packet)
	if err != nil {
		return nil, 0, err
	}
	l4 := packet[20 : 28+len(parsed.Payload)]
	checksum := transportChecksum(parsed.Protocol, l4)
	if parsed.Protocol == IPProtocolUDP && checksum == 0 {
		return nil, 0, ErrRewriteChecksum
	}
	payloadSum := uint32(^checksum)
	payloadSum += uint32(^checksumFold(transportHeaderSum(packet, l4)))
	sourceBytes := source.As4()
	destinationBytes := destination.As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], destinationBytes[:])
	return l4, payloadSum, nil
}

func finishRewrite(packet, l4 []byte, payloadSum uint32) {
	checksum := ^checksumFold(payloadSum + transportHeaderSum(packet, l4))
	writeTransportChecksum(packet[9], l4, checksum)
	packet[10] = 0
	packet[11] = 0
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[:20]))
}

// transportHeaderSum sums the words that the transport checksum covers,
// except the payload and the checksum field: the UDP pseudo-header and UDP
// header, or the ICMP header.
func transportHeaderSum(packet, l4 []byte) uint32 {
	if packet[9] == IPProtocolUDP {
		return wordAt(packet, 12) + wordAt(packet, 14) +
			wordAt(packet, 16) + wordAt(packet, 18) +
			uint32(IPProtocolUDP) + wordAt(l4, 4) +
			wordAt(l4, 0) + wordAt(l4, 2) + wordAt(l4, 4)
	}
	return wordAt(l4, 0) + wordAt(l4, 4) + wordAt(l4, 6)
}

func transportChecksum(protocol uint8, l4 []byte) uint16 {
	if protocol == IPProtocolUDP {
		return binary.BigEndian.Uint16(l4[6:8])
	}
	return binary.BigEndian.Uint16(l4[2:4])
}

// writeTransportChecksum sends a computed UDP checksum of zero as 0xffff
// (RFC 768).
func writeTransportChecksum(protocol uint8, l4 []byte, checksum uint16) {
	if protocol == IPProtocolUDP {
		if checksum == 0 {
			checksum = 0xffff
		}
		binary.BigEndian.PutUint16(l4[6:8], checksum)
		return
	}
	binary.BigEndian.PutUint16(l4[2:4], checksum)
}

func wordAt(data []byte, offset int) uint32 {
	return uint32(binary.BigEndian.Uint16(data[offset : offset+2]))
}

func internetChecksum(data []byte) uint16 {
	return ^checksumFold(sumWords(data, 0))
}

func sumWords(data []byte, sum uint32) uint32 {
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	return sum
}

func checksumFold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}
