package app

import (
	"encoding/binary"
	"errors"

	"github.com/xshecan/mup/protocol"
)

const (
	icmpEchoReply   uint8 = 0
	icmpEchoRequest uint8 = 8
)

type icmpEcho struct {
	echoType   uint8
	identifier uint16
	sequence   uint16
	payload    []byte
}

func marshalICMPEcho(echoType uint8, identifier, sequence uint16, payload []byte) []byte {
	packet := make([]byte, 8+len(payload))
	packet[0] = echoType
	binary.BigEndian.PutUint16(packet[4:6], identifier)
	binary.BigEndian.PutUint16(packet[6:8], sequence)
	copy(packet[8:], payload)
	binary.BigEndian.PutUint16(packet[2:4], internetChecksum(packet))
	return packet
}

func parseICMPEcho(packet []byte) (icmpEcho, error) {
	if len(packet) < 8 || packet[1] != 0 {
		return icmpEcho{}, errors.New("invalid ICMP Echo header")
	}
	if internetChecksum(packet) != 0 {
		return icmpEcho{}, errors.New("invalid ICMP checksum")
	}
	return icmpEcho{
		echoType:   packet[0],
		identifier: binary.BigEndian.Uint16(packet[4:6]),
		sequence:   binary.BigEndian.Uint16(packet[6:8]),
		payload:    packet[8:],
	}, nil
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func validateRegistrationACK(packet []byte, nonce uint64, pathID uint16, sequence uint32) error {
	frame, err := protocol.DecodeControlFrame(packet)
	if err != nil {
		return err
	}
	if frame.Type != protocol.ControlRegisterACK || frame.Status != protocol.ControlStatusOK ||
		frame.InstanceNonce != nonce || frame.PathID != pathID || frame.Sequence != sequence {
		return errors.New("registration ACK does not match request")
	}
	return nil
}
