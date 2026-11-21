package protocol

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// The bridge wrapper is a UDP header and a 12-byte bridge header between the
// IPv4 header and the transport header of a packet. bpf/mup.c builds and
// removes it in the dataplane, and these functions build it for the control
// frames and the tests.
const (
	BridgeMagic         uint16 = 0x4d42
	BridgeVersion       uint8  = 1
	BridgeHeaderLength         = 12
	BridgeOverhead             = 8 + BridgeHeaderLength
	ipv4HeaderLength           = 20
	ipv4ProtocolUDPWord        = 17
)

// WrapForBridge puts an IPv4 packet without options in the bridge wrapper. The
// result is a UDP packet from source to bridge, on port at both ends. The UDP
// checksum is zero, and the inner transport header and payload do not change.
func WrapForBridge(inner []byte, source, bridge netip.Addr, port uint16) []byte {
	totalLength := len(inner) + BridgeOverhead
	packet := make([]byte, totalLength)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLength))
	packet[8] = 64
	packet[9] = ipv4ProtocolUDPWord
	sourceBytes, bridgeBytes := source.As4(), bridge.As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], bridgeBytes[:])
	binary.BigEndian.PutUint16(packet[10:12], ipv4HeaderChecksum(packet[:ipv4HeaderLength]))
	wrapper := packet[ipv4HeaderLength:]
	binary.BigEndian.PutUint16(wrapper[0:2], port)
	binary.BigEndian.PutUint16(wrapper[2:4], port)
	binary.BigEndian.PutUint16(wrapper[4:6], uint16(len(inner)))
	binary.BigEndian.PutUint16(wrapper[8:10], BridgeMagic)
	wrapper[10] = BridgeVersion
	wrapper[11] = inner[9]
	copy(wrapper[12:20], inner[12:20])
	copy(wrapper[BridgeOverhead:], inner[ipv4HeaderLength:])
	return packet
}

// ErrBridgeWrapper reports a packet that is not a valid bridge wrapper.
var ErrBridgeWrapper = errors.New("invalid bridge wrapper")

// UnwrapBridge removes the bridge wrapper of an IPv4 packet without options,
// and returns the inner packet with a new IPv4 header.
func UnwrapBridge(packet []byte) ([]byte, error) {
	if len(packet) < ipv4HeaderLength+BridgeOverhead || packet[0] != 0x45 || packet[9] != ipv4ProtocolUDPWord {
		return nil, ErrBridgeWrapper
	}
	wrapper := packet[ipv4HeaderLength:]
	if binary.BigEndian.Uint16(wrapper[8:10]) != BridgeMagic || wrapper[10] != BridgeVersion {
		return nil, ErrBridgeWrapper
	}
	inner := make([]byte, len(packet)-BridgeOverhead)
	copy(inner[:ipv4HeaderLength], packet[:ipv4HeaderLength])
	binary.BigEndian.PutUint16(inner[2:4], uint16(len(inner)))
	inner[9] = wrapper[11]
	copy(inner[12:20], wrapper[12:20])
	inner[10], inner[11] = 0, 0
	binary.BigEndian.PutUint16(inner[10:12], ipv4HeaderChecksum(inner[:ipv4HeaderLength]))
	copy(inner[ipv4HeaderLength:], wrapper[BridgeOverhead:])
	return inner, nil
}

func ipv4HeaderChecksum(header []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(header); index += 2 {
		if index == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(header[index:]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
