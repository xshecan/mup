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

// ingressReflectPathConn registers an ingress reflect path. Each cycle it sends a REGISTER
// reflected through every candidate member, collects the ACKs that come back on
// the egress paths, and publishes the members that answered to the dataplane. The
// path is healthy while at least one member answers. The socket includes the
// IPv4 header, so the reflected packets carry a spoofed source.
type ingressReflectPathConn struct {
	fd           int
	registration pathRegistration
	router       *ackRouter
	routed       *ackWaiter
	// healthy holds the members that answered in the latest cycle.
	healthy []netip.Addr
}

func openIngressReflectPathConn(registration pathRegistration, router *ackRouter) (*ingressReflectPathConn, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("open raw socket of ingress reflect path %d: %w", registration.pathID, err)
	}
	if registration.path.Interface != "" {
		if err := unix.BindToDevice(fd, registration.path.Interface); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("bind ingress reflect path %d to %s: %w", registration.pathID, registration.path.Interface, err)
		}
	}
	return &ingressReflectPathConn{
		fd:           fd,
		registration: registration,
		router:       router,
		routed:       router.subscribe(registration.pathID),
	}, nil
}

func (s *ingressReflectPathConn) Close() error {
	if s.routed != nil {
		s.router.unsubscribe(s.routed)
	}
	return unix.Close(s.fd)
}

func (s *ingressReflectPathConn) Run(ctx context.Context, report probeReporter) error {
	defer s.Close()
	var sequence uint32
	for {
		sequence++
		sentAt := time.Now()
		result, repliedAt := s.registerMembers(sequence, sentAt)
		if err := report(ctx, sequence, sentAt, repliedAt, result); err != nil {
			return err
		}
		if err := sleepContext(ctx, registrationDelay(result == registerAcked)); err != nil {
			return err
		}
	}
}

// registerMembers sends the egress registrations to the server, a REGISTER
// reflected through each member, and returns whether any member answered, with
// the time of the first answer. It publishes the members that answered.
func (s *ingressReflectPathConn) registerMembers(sequence uint32, sentAt time.Time) (registerResult, time.Time) {
	reg := s.registration
	if reg.egresses != nil {
		for _, egress := range reg.egressFrames(sequence) {
			s.sendEgressRegister(reg, egress, sequence)
		}
	}
	drainRouted(s.routed)
	for _, member := range reg.members {
		frame, err := ingressReflectFrame(reg, member, sequence)
		if err != nil {
			continue
		}
		if reg.path.BridgeReflect() {
			// The client cannot send the spoofed packet, so it wraps the
			// reflected REGISTER for the bridge, and the bridge emits it.
			_ = s.sendViaBridge(reg, member, frame, sequence)
		} else {
			_ = s.sendReflected(reg, member, frame, sequence)
		}
	}
	healthy, repliedAt := s.collectHealthy(sequence, sentAt)
	s.healthy = healthy
	if reg.writeMembers != nil {
		_ = reg.writeMembers(healthy)
	}
	if len(healthy) == 0 {
		return registerMissed, time.Time{}
	}
	return registerAcked, repliedAt
}

// collectHealthy reads the REGISTER_ACK frames that arrive on the egress paths
// until the reply window ends. Each ACK names the member that answered in its
// return IP, because the member reflected the REGISTER to the server. The
// function also returns the time of the first ACK, which gives the round-trip
// time of the path. The wait for the other members is not part of it.
func (s *ingressReflectPathConn) collectHealthy(sequence uint32, sentAt time.Time) ([]netip.Addr, time.Time) {
	seen := make(map[netip.Addr]bool)
	var healthy []netip.Addr
	var repliedAt time.Time
	timer := time.NewTimer(time.Until(sentAt.Add(controlReplyTimeout)))
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			return healthy, repliedAt
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
				if repliedAt.IsZero() {
					repliedAt = time.Now()
				}
				seen[frame.ReturnIP] = true
				healthy = append(healthy, frame.ReturnIP)
			}
		}
	}
}

// sendReflected sends a control frame of the path through member. The UDP
// frame carries the forged member source. The ICMP frame is an Echo Request to
// the member with the server as its source, so the member answers the server.
func (s *ingressReflectPathConn) sendReflected(reg pathRegistration, member netip.Addr, frame []byte, id uint32) error {
	packet, destination := reflectedControlPacket(reg, member, frame, id)
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
func (s *ingressReflectPathConn) sendViaBridge(reg pathRegistration, member netip.Addr, frame []byte, id uint32) error {
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

// sendEgressRegister sends one EGRESS_REGISTER to the server. The client of a
// reflect path does not reach the server directly, which is the reason it
// reflects at all. So a bridge path routes the frame through the bridge, and
// the bridge emits it with the advertised source. A path without a bridge
// reflects the frame like its REGISTER, through every member that answered in
// the latest cycle, or through every candidate while none answered. The server
// takes it because it arrives on a reflect path of the client.
func (s *ingressReflectPathConn) sendEgressRegister(reg pathRegistration, frame []byte, id uint32) {
	if reg.path.BridgeReflect() {
		_ = s.sendEgressViaBridge(reg, frame, id)
		return
	}
	members := s.healthy
	if len(members) == 0 {
		members = reg.members
	}
	for _, member := range members {
		_ = s.sendReflected(reg, member, frame, id)
	}
}

// sendEgressViaBridge wraps a EGRESS_REGISTER for the bridge with the advertised IP
// as its inner source, so the bridge emits it to the server from that address.
// The frame travels on the transport of the ingress path, because the server reads
// the control frames of the path on the port of the ingress path.
func (s *ingressReflectPathConn) sendEgressViaBridge(reg pathRegistration, frame []byte, id uint32) error {
	return unix.Sendto(s.fd, bridgeControlPacket(reg, frame, id), 0, &unix.SockaddrInet4{Addr: reg.path.ProxyBridge.As4()})
}

// bridgeControlPacket wraps a control frame of the client itself for the
// bridge of an ingress path. The inner packet goes from the advertised IP to the
// server of the path, on the transport of the path, so the server sees the
// frame from the client address, as it requires for a EGRESS_REGISTER and for
// the PROBE_REPLY of an egress path.
func bridgeControlPacket(reg pathRegistration, frame []byte, id uint32) []byte {
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
	return wrapForBridge(reg.advertisedIP, reg.path.ProxyBridge, reg.path.ServerPort, innerProtocol, reg.advertisedIP, reg.path.Server, inner, uint16(id))
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
	packet := make([]byte, protocol.ControlFrameLength)
	if err := protocol.EncodeControlFrame(packet, frame); err != nil {
		return nil, err
	}
	return packet, nil
}
