package app

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/xshecan/mup/config"
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

// registerResult is the result of one REGISTER.
type registerResult uint8

const (
	// registerMissed means that no answer came before the timeout.
	registerMissed registerResult = iota
	// registerAcked means that the server accepted the path.
	registerAcked
	// registerNoReflector means that the server has no healthy reflector in
	// the return pool of the path, so it cannot return replies on it.
	registerNoReflector
)

// registrationACKResult reads the REGISTER_ACK that answers this request. ok
// is false for a frame that does not answer it, or that has a status the
// client does not act on.
func registrationACKResult(packet []byte, nonce uint64, pathID uint16, sequence uint32) (registerResult, bool) {
	frame, err := protocol.DecodeControlFrame(packet)
	if err != nil {
		return registerMissed, false
	}
	if frame.Type != protocol.ControlRegisterACK ||
		frame.InstanceNonce != nonce || frame.PathID != pathID || frame.Sequence != sequence {
		return registerMissed, false
	}
	switch frame.Status {
	case protocol.ControlStatusOK:
		return registerAcked, true
	case protocol.ControlStatusNoReflector:
		return registerNoReflector, true
	default:
		return registerMissed, false
	}
}

func validateRegistrationACK(packet []byte, nonce uint64, pathID uint16, sequence uint32) error {
	if result, ok := registrationACKResult(packet, nonce, pathID, sequence); !ok || result != registerAcked {
		return errors.New("registration ACK does not match request")
	}
	return nil
}

// probeReplyFrame answers a reflector probe. It names the reflector that
// reached the client in its return IP, because the reply comes from the client,
// not from the spoofed source.
func probeReplyFrame(registration pathRegistration, reflector netip.Addr, sequence uint32) ([]byte, error) {
	frame := protocol.ControlFrame{
		Type:          protocol.ControlProbeReply,
		Transport:     protocol.TransportUDP,
		Flags:         protocol.ControlFlagReturnIP,
		PathID:        registration.pathID,
		Sequence:      sequence,
		ListenPort:    registration.listenPort,
		ServerPort:    registration.path.ServerPort,
		InstanceNonce: registration.nonce,
		AdvertisedIP:  registration.advertisedIP,
		ReturnIP:      reflector,
	}
	packet := make([]byte, protocol.ControlFrameLength)
	if err := protocol.EncodeControlFrame(packet, frame); err != nil {
		return nil, err
	}
	return packet, nil
}

func registrationFrame(registration pathRegistration, sequence uint32) ([]byte, error) {
	frame := protocol.ControlFrame{
		Type:          protocol.ControlRegister,
		Transport:     registration.path.Transport,
		PathID:        registration.pathID,
		Sequence:      sequence,
		ListenPort:    registration.listenPort,
		ServerPort:    registration.path.ServerPort,
		LeaseSeconds:  registrationLeaseSeconds,
		InstanceNonce: registration.nonce,
		AdvertisedIP:  registration.advertisedIP,
		ReturnIP:      registration.returnIP,
	}
	switch {
	case registration.path.IsPool():
		frame.ReturnPrefix = registration.path.ReturnPrefix
		frame.Flags = protocol.ControlFlagReturnPool
		if registration.path.Balance == config.BalancePerPacket {
			frame.Flags |= protocol.ControlFlagBalancePerPacket
		}
	case registration.returnIP.IsValid():
		frame.Flags = protocol.ControlFlagReturnIP
	}
	packet := make([]byte, protocol.ControlFrameLength)
	if err := protocol.EncodeControlFrame(packet, frame); err != nil {
		return nil, err
	}
	return packet, nil
}
