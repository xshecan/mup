//go:build linux

package app

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"

	"github.com/xshecan/mup/protocol"
)

// upReflectPathConn registers an up reflect path. Each cycle it sends a REGISTER
// reflected through every candidate member, collects the ACKs that come back on
// the down paths, and publishes the members that answered to the dataplane. The
// path is healthy while at least one member answers. The socket includes the
// IPv4 header, so the reflected packets carry a spoofed source.
type upReflectPathConn struct {
	fd           int
	registration pathRegistration
	router       *ackRouter
	routed       *ackWaiter
}

func openUpReflectPathConn(registration pathRegistration, router *ackRouter) (*upReflectPathConn, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("open raw socket of up reflect path %d: %w", registration.pathID, err)
	}
	if registration.path.Interface != "" {
		if err := unix.BindToDevice(fd, registration.path.Interface); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("bind up reflect path %d to %s: %w", registration.pathID, registration.path.Interface, err)
		}
	}
	return &upReflectPathConn{
		fd:           fd,
		registration: registration,
		router:       router,
		routed:       router.subscribe(registration.pathID),
	}, nil
}

func (s *upReflectPathConn) Close() error {
	if s.routed != nil {
		s.router.unsubscribe(s.routed)
	}
	return unix.Close(s.fd)
}

func (s *upReflectPathConn) Run(ctx context.Context, report probeReporter) error {
	defer s.Close()
	var sequence uint32
	for {
		sequence++
		sentAt := time.Now()
		result := s.registerMembers(sequence, sentAt)
		if err := report(ctx, sequence, sentAt, result); err != nil {
			return err
		}
		if err := sleepContext(ctx, registrationDelay(result == registerAcked)); err != nil {
			return err
		}
	}
}

// registerMembers sends the down registrations to the server, a REGISTER
// reflected through each member, and returns whether any member answered. It
// publishes the members that answered.
func (s *upReflectPathConn) registerMembers(sequence uint32, sentAt time.Time) registerResult {
	reg := s.registration
	if reg.downs != nil {
		for _, down := range reg.downFrames(sequence) {
			s.sendDownRegister(reg, down, sequence)
		}
	}
	drainRouted(s.routed)
	for _, member := range reg.members {
		frame, err := upReflectFrame(reg, member, sequence)
		if err != nil {
			continue
		}
		if reg.path.BridgeReflect() {
			// The client cannot send the spoofed packet, so it wraps the
			// reflected REGISTER for the bridge, and the bridge emits it.
			_ = s.sendViaBridge(reg, member, frame, sequence)
		} else if reg.path.Transport == protocol.TransportICMP {
			// The member answers the server with an Echo Reply, so the request
			// carries the server as its source.
			_ = s.sendICMP(reg.path.Server, member, reg.path.ServerPort, uint16(sequence), frame, sequence)
		} else {
			// The server sees the forged member source.
			_ = s.sendUDP(member, reg.path.Server, reg.listenPort, reg.path.ServerPort, frame, sequence)
		}
	}
	healthy := s.collectHealthy(sequence, sentAt)
	if reg.writeMembers != nil {
		_ = reg.writeMembers(healthy)
	}
	if len(healthy) == 0 {
		return registerMissed
	}
	return registerAcked
}

// collectHealthy reads the REGISTER_ACK frames that arrive on the down paths
// until the reply window ends. Each ACK names the member that answered in its
// return IP, because the member reflected the REGISTER to the server.
func (s *upReflectPathConn) collectHealthy(sequence uint32, sentAt time.Time) []netip.Addr {
	seen := make(map[netip.Addr]bool)
	var healthy []netip.Addr
	timer := time.NewTimer(time.Until(sentAt.Add(controlReplyTimeout)))
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			return healthy
		case reply := <-s.routed.replies:
			frame, err := protocol.DecodeControlFrame(reply)
			if err != nil {
				continue
			}
			if frame.Type != protocol.ControlRegisterACK || frame.InstanceNonce != s.registration.nonce ||
				frame.PathID != s.registration.pathID || frame.Sequence != sequence ||
				frame.Status != protocol.ControlStatusOK {
				continue
			}
			if frame.ReturnIP.IsValid() && !seen[frame.ReturnIP] {
				seen[frame.ReturnIP] = true
				healthy = append(healthy, frame.ReturnIP)
			}
		}
	}
}

func (s *upReflectPathConn) sendICMP(source, destination netip.Addr, identifier, echoSequence uint16, payload []byte, id uint32) error {
	echo := marshalICMPEcho(icmpEchoRequest, identifier, echoSequence, payload)
	packet := buildIPv4Packet(source, destination, unix.IPPROTO_ICMP, echo, uint16(id))
	return unix.Sendto(s.fd, packet, 0, &unix.SockaddrInet4{Addr: destination.As4()})
}

func (s *upReflectPathConn) sendUDP(source, destination netip.Addr, sourcePort, destinationPort uint16, payload []byte, id uint32) error {
	segment := buildUDPSegment(source, destination, sourcePort, destinationPort, payload)
	packet := buildIPv4Packet(source, destination, unix.IPPROTO_UDP, segment, uint16(id))
	return unix.Sendto(s.fd, packet, 0, &unix.SockaddrInet4{Addr: destination.As4()})
}

// The MUP bridge wrapper, mirrored from bpf/include/mup_abi.h. The wrapper is a
// UDP header and the bridge header, inserted after the IPv4 header.
const (
	bridgeWrapOverhead = 20
	bridgeWrapMagic0   = 0x4d
	bridgeWrapMagic1   = 0x42
	bridgeWrapVersion  = 1
)

// sendViaBridge wraps the reflected REGISTER for the bridge and sends the
// wrapper to the bridge over the socket. The client cannot send the spoofed
// packet, so the bridge removes the wrapper and emits the inner packet to the
// member. The outer packet carries the advertised source, so it needs no
// spoofing.
func (s *upReflectPathConn) sendViaBridge(reg pathRegistration, member netip.Addr, frame []byte, id uint32) error {
	var innerSource, innerDestination netip.Addr
	var innerProtocol byte
	var inner []byte
	if reg.path.Transport == protocol.TransportICMP {
		echo := marshalICMPEcho(icmpEchoRequest, reg.path.ServerPort, uint16(id), frame)
		innerSource, innerDestination, innerProtocol = reg.path.Server, member, unix.IPPROTO_ICMP
		inner = buildIPv4Packet(innerSource, innerDestination, unix.IPPROTO_ICMP, echo, uint16(id))
	} else {
		segment := buildUDPSegment(member, reg.path.Server, reg.listenPort, reg.path.ServerPort, frame)
		innerSource, innerDestination, innerProtocol = member, reg.path.Server, unix.IPPROTO_UDP
		inner = buildIPv4Packet(innerSource, innerDestination, unix.IPPROTO_UDP, segment, uint16(id))
	}
	packet := wrapForBridge(reg.advertisedIP, reg.path.ProxyBridge, reg.path.ServerPort, innerProtocol, innerSource, innerDestination, inner, uint16(id))
	return unix.Sendto(s.fd, packet, 0, &unix.SockaddrInet4{Addr: reg.path.ProxyBridge.As4()})
}

// sendDownRegister sends one DOWN_REGISTER to the server. The server keeps a
// down path only when the frame reaches it from the advertised IP, so a direct
// reflect path sends it from that address itself. A bridge path cannot reach
// the server directly, which is the reason it reflects at all, so it routes the
// frame through the bridge, and the bridge emits it with the advertised source.
func (s *upReflectPathConn) sendDownRegister(reg pathRegistration, frame []byte, id uint32) {
	if reg.path.BridgeReflect() {
		_ = s.sendDownViaBridge(reg, frame, id)
		return
	}
	_ = s.sendICMP(reg.advertisedIP, reg.path.Server, reg.path.ServerPort, uint16(id), frame, id)
}

// sendDownViaBridge wraps a DOWN_REGISTER for the bridge with the advertised IP
// as its inner source, so the bridge emits it to the server from that address.
// The frame travels on the transport of the up path, because the server reads
// the control frames of the path on the port of the up path.
func (s *upReflectPathConn) sendDownViaBridge(reg pathRegistration, frame []byte, id uint32) error {
	var innerProtocol byte
	var inner []byte
	if reg.path.Transport == protocol.TransportICMP {
		echo := marshalICMPEcho(icmpEchoRequest, reg.path.ServerPort, uint16(id), frame)
		innerProtocol = unix.IPPROTO_ICMP
		inner = buildIPv4Packet(reg.advertisedIP, reg.path.Server, unix.IPPROTO_ICMP, echo, uint16(id))
	} else {
		segment := buildUDPSegment(reg.advertisedIP, reg.path.Server, reg.listenPort, reg.path.ServerPort, frame)
		innerProtocol = unix.IPPROTO_UDP
		inner = buildIPv4Packet(reg.advertisedIP, reg.path.Server, unix.IPPROTO_UDP, segment, uint16(id))
	}
	packet := wrapForBridge(reg.advertisedIP, reg.path.ProxyBridge, reg.path.ServerPort, innerProtocol, reg.advertisedIP, reg.path.Server, inner, uint16(id))
	return unix.Sendto(s.fd, packet, 0, &unix.SockaddrInet4{Addr: reg.path.ProxyBridge.As4()})
}

// wrapForBridge wraps an inner IPv4 packet in the MUP bridge wrapper, from
// source to the bridge. It mirrors mup_bridge_wrap in bpf/mup.c: it turns the
// outer IPv4 header into a UDP packet to the bridge and inserts the UDP header
// and the bridge header, which carry the inner protocol and addresses.
func wrapForBridge(source, bridge netip.Addr, port uint16, innerProtocol byte, innerSource, innerDestination netip.Addr, inner []byte, id uint16) []byte {
	payload := inner[20:]
	innerTotal := len(inner)
	total := innerTotal + bridgeWrapOverhead
	packet := make([]byte, total)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(total))
	binary.BigEndian.PutUint16(packet[4:6], id)
	packet[8] = 64
	packet[9] = unix.IPPROTO_UDP
	source4 := source.As4()
	bridge4 := bridge.As4()
	copy(packet[12:16], source4[:])
	copy(packet[16:20], bridge4[:])
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[20:22], port)
	binary.BigEndian.PutUint16(packet[22:24], port)
	binary.BigEndian.PutUint16(packet[24:26], uint16(innerTotal))
	// packet[26:28] stays zero: the bridge does not check the outer UDP checksum.
	packet[28] = bridgeWrapMagic0
	packet[29] = bridgeWrapMagic1
	packet[30] = bridgeWrapVersion
	packet[31] = innerProtocol
	innerSource4 := innerSource.As4()
	innerDestination4 := innerDestination.As4()
	copy(packet[32:36], innerSource4[:])
	copy(packet[36:40], innerDestination4[:])
	copy(packet[40:], payload)
	return packet
}

// upReflectFrame builds the REGISTER of one member. Each member registers as a
// single up reflect path, so a pool is a set of one-member registrations on the
// server.
func upReflectFrame(reg pathRegistration, member netip.Addr, sequence uint32) ([]byte, error) {
	frame := protocol.ControlFrame{
		Type:          protocol.ControlRegister,
		Transport:     reg.path.Transport,
		Flags:         protocol.ControlFlagUpReflect | protocol.ControlFlagReturnIP,
		PathID:        reg.pathID,
		Sequence:      sequence,
		ListenPort:    reg.listenPort,
		ServerPort:    reg.path.ServerPort,
		LeaseSeconds:  registrationLeaseSeconds,
		InstanceNonce: reg.nonce,
		AdvertisedIP:  reg.advertisedIP,
		ReturnIP:      member,
	}
	packet := make([]byte, protocol.ControlFrameLength)
	if err := protocol.EncodeControlFrame(packet, frame); err != nil {
		return nil, err
	}
	return packet, nil
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
	sum += uint32(unix.IPPROTO_UDP) + uint32(len(segment))
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
