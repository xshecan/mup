package protocol

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	IPProtocolICMP uint8 = 1
	IPProtocolUDP  uint8 = 17
)

var (
	ErrMalformedIPv4 = errors.New("malformed IPv4 packet")
	ErrIPv4Options   = errors.New("IPv4 options are not supported")
	ErrIPv4Fragment  = errors.New("IPv4 fragments are not supported")
	ErrUnsupportedL4 = errors.New("unsupported IPv4 transport protocol")
	ErrMalformedL4   = errors.New("malformed IPv4 transport header")
)

type IPv4L4Packet struct {
	Source          netip.Addr
	Destination     netip.Addr
	Protocol        uint8
	SourcePort      uint16
	DestinationPort uint16
	Payload         []byte
	ICMPType        uint8
	ICMPCode        uint8
	ICMPIdentifier  uint16
	ICMPSequence    uint16
}

func ParseIPv4L4(packet []byte) (IPv4L4Packet, error) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return IPv4L4Packet{}, ErrMalformedIPv4
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 {
		return IPv4L4Packet{}, ErrMalformedIPv4
	}
	if ihl != 20 {
		return IPv4L4Packet{}, ErrIPv4Options
	}
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLength < ihl || totalLength > len(packet) {
		return IPv4L4Packet{}, ErrMalformedIPv4
	}
	if binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return IPv4L4Packet{}, ErrIPv4Fragment
	}
	packet = packet[:totalLength]
	parsed := IPv4L4Packet{
		Source:      netip.AddrFrom4([4]byte(packet[12:16])),
		Destination: netip.AddrFrom4([4]byte(packet[16:20])),
		Protocol:    packet[9],
	}
	l4 := packet[ihl:]
	switch parsed.Protocol {
	case IPProtocolUDP:
		if len(l4) < 8 {
			return IPv4L4Packet{}, ErrMalformedL4
		}
		udpLength := int(binary.BigEndian.Uint16(l4[4:6]))
		if udpLength != len(l4) || udpLength < 8 {
			return IPv4L4Packet{}, ErrMalformedL4
		}
		parsed.SourcePort = binary.BigEndian.Uint16(l4[0:2])
		parsed.DestinationPort = binary.BigEndian.Uint16(l4[2:4])
		parsed.Payload = l4[8:]
	case IPProtocolICMP:
		if len(l4) < 8 {
			return IPv4L4Packet{}, ErrMalformedL4
		}
		parsed.ICMPType = l4[0]
		parsed.ICMPCode = l4[1]
		parsed.ICMPIdentifier = binary.BigEndian.Uint16(l4[4:6])
		parsed.ICMPSequence = binary.BigEndian.Uint16(l4[6:8])
		parsed.Payload = l4[8:]
	default:
		return IPv4L4Packet{}, ErrUnsupportedL4
	}
	return parsed, nil
}
