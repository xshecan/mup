//go:build linux

package app

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"

	"github.com/xshecan/mup/protocol"
)

// rawDownSender sends control frames on down paths from a raw socket. The
// source is the server address of a direct path, the reflector of a UDP path
// with a return IP or pool, and the client of an ICMP path that reflects.
type rawDownSender struct {
	fd int
}

func openDownSender() (*rawDownSender, error) {
	fd, err := openSpoofSocket()
	if err != nil {
		return nil, err
	}
	return &rawDownSender{fd: fd}, nil
}

func (s *rawDownSender) Close() error {
	return unix.Close(s.fd)
}

func (s *rawDownSender) send(target downTarget, frame []byte, sequence uint16) error {
	packet, destination := downPacket(target, frame, sequence)
	// A down path through a bridge sends the packet in the bridge wrapper,
	// as the server program does.
	if target.bridge {
		packet = protocol.WrapForBridge(packet, target.localIP, target.server, target.port)
		destination = target.server
	}
	var address unix.SockaddrInet4
	address.Addr = destination.As4()
	return unix.Sendto(s.fd, packet, 0, &address)
}

// downPacket builds the IPv4 packet of a frame on a down path, and returns its
// destination.
func downPacket(target downTarget, frame []byte, sequence uint16) ([]byte, netip.Addr) {
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
	packet[9] = unix.IPPROTO_ICMP
	sourceBytes := source.As4()
	destinationBytes := destination.As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], destinationBytes[:])
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[0:20]))
	copy(packet[20:], message)
	return packet
}

// locateDownInterface finds the interface of a down path: the interface that
// holds its server address. An address on a loopback or a tunnel interface
// sends through the route to the destination.
func locateDownInterface(server, destination netip.Addr) (int, error) {
	networkInterface, err := interfaceForAddress(server)
	if err != nil {
		return 0, fmt.Errorf("%w: %s", errDownNotLocal, server)
	}
	if networkInterface.Flags&net.FlagLoopback == 0 && hasEthernetHeader(networkInterface.Name) {
		return networkInterface.Index, nil
	}
	_, ifindex, err := systemResolver{}.Resolve(destination, "")
	return ifindex, err
}
