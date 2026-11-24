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

// The IPv4 protocol numbers of the packets that the client builds itself.
const (
	ipProtocolICMP byte = 1
	ipProtocolUDP  byte = 17
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
	setSourceRange(&frame, registration.path)
	packet := make([]byte, protocol.ControlFrameLength)
	if err := protocol.EncodeControlFrame(packet, frame); err != nil {
		return nil, err
	}
	return packet, nil
}

// ingressReflectFrame builds the REGISTER of one member. Each member registers as a
// single ingress reflect path, so a pool is a set of one-member registrations on the
// server.
func ingressReflectFrame(reg pathRegistration, member netip.Addr, sequence uint32) ([]byte, error) {
	frame := protocol.ControlFrame{
		Type:          protocol.ControlRegister,
		Transport:     reg.path.Transport,
		Flags:         protocol.ControlFlagIngressReflect | protocol.ControlFlagReturnIP,
		PathID:        reg.pathID,
		Sequence:      sequence,
		ListenPort:    reg.listenPort,
		ServerPort:    reg.path.ServerPort,
		LeaseSeconds:  registrationLeaseSeconds,
		InstanceNonce: reg.nonce,
		AdvertisedIP:  reg.advertisedIP,
		ReturnIP:      member,
	}
	setSourceRange(&frame, reg.path)
	packet := make([]byte, protocol.ControlFrameLength)
	if err := protocol.EncodeControlFrame(packet, frame); err != nil {
		return nil, err
	}
	return packet, nil
}

// setSourceRange puts the source range of a path in a REGISTER or an
// EGRESS_REGISTER. The frame itself keeps the fixed port of the path, and only
// the data packets take their source from the range.
func setSourceRange(frame *protocol.ControlFrame, path config.Path) {
	if !path.HasSrc() {
		return
	}
	frame.Flags |= protocol.ControlFlagSourceRange
	frame.SrcFirst = path.SrcFirst
	frame.SrcLast = path.SrcLast
}

// buildIPv4Packet builds an IPv4 packet with the given source, so a raw socket
// with the header included sends it with a spoofed source.
func buildIPv4Packet(source, destination netip.Addr, protocolNumber byte, payload []byte, id uint16) []byte {
	total := 20 + len(payload)
	packet := make([]byte, total)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(total))
	binary.BigEndian.PutUint16(packet[4:6], id)
	packet[8] = 64
	packet[9] = protocolNumber
	source4 := source.As4()
	destination4 := destination.As4()
	copy(packet[12:16], source4[:])
	copy(packet[16:20], destination4[:])
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[:20]))
	copy(packet[20:], payload)
	return packet
}

func buildUDPSegment(source, destination netip.Addr, sourcePort, destinationPort uint16, payload []byte) []byte {
	segment := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(segment[0:2], sourcePort)
	binary.BigEndian.PutUint16(segment[2:4], destinationPort)
	binary.BigEndian.PutUint16(segment[4:6], uint16(len(segment)))
	copy(segment[8:], payload)
	binary.BigEndian.PutUint16(segment[6:8], udpChecksum(source, destination, segment))
	return segment
}

// udpChecksum computes the UDP checksum over the IPv4 pseudo header and the
// segment. A computed checksum of zero becomes 0xffff, as RFC 768 requires.
func udpChecksum(source, destination netip.Addr, segment []byte) uint16 {
	source4 := source.As4()
	destination4 := destination.As4()
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(source4[0:2])) + uint32(binary.BigEndian.Uint16(source4[2:4]))
	sum += uint32(binary.BigEndian.Uint16(destination4[0:2])) + uint32(binary.BigEndian.Uint16(destination4[2:4]))
	sum += uint32(ipProtocolUDP) + uint32(len(segment))
	for index := 0; index+1 < len(segment); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(segment[index:]))
	}
	if len(segment)%2 == 1 {
		sum += uint32(segment[len(segment)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	folded := ^uint16(sum)
	if folded == 0 {
		return 0xffff
	}
	return folded
}

// reflectedControlPacket builds a control frame of an ingress reflect path as
// the IPv4 packet that goes through member, and returns the address to send it
// to. A UDP frame carries the member as its source, so the server sees it from
// the member. An ICMP frame is an Echo Request to the member with the server as
// its source, so the member answers the server with an Echo Reply.
func reflectedControlPacket(reg pathRegistration, member netip.Addr, frame []byte, id uint32) ([]byte, netip.Addr) {
	if reg.path.Transport == protocol.TransportICMP {
		echo := marshalICMPEcho(icmpEchoRequest, reg.path.ServerPort, uint16(id), frame)
		return buildIPv4Packet(reg.path.Server, member, ipProtocolICMP, echo, uint16(id)), member
	}
	segment := buildUDPSegment(member, reg.path.Server, reg.listenPort, reg.path.ServerPort, frame)
	return buildIPv4Packet(member, reg.path.Server, ipProtocolUDP, segment, uint16(id)), reg.path.Server
}
