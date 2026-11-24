//go:build linux

package app

import (
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

// rawEgressSender sends control frames on egress paths from a raw socket.
// egressWirePacket builds each packet.
type rawEgressSender struct {
	fd int
}

func openEgressSender() (*rawEgressSender, error) {
	fd, err := openSpoofSocket()
	if err != nil {
		return nil, err
	}
	return &rawEgressSender{fd: fd}, nil
}

func (s *rawEgressSender) Close() error {
	return unix.Close(s.fd)
}

func (s *rawEgressSender) send(target egressTarget, frame []byte, sequence uint16) error {
	packet, destination := egressWirePacket(target, frame, sequence)
	var address unix.SockaddrInet4
	address.Addr = destination.As4()
	return unix.Sendto(s.fd, packet, 0, &address)
}

// locateEgressInterface finds the interface of an egress path: the interface that
// holds its server address. An address on a loopback or a tunnel interface
// sends through the route to the destination.
func locateEgressInterface(server, destination netip.Addr) (int, error) {
	networkInterface, err := interfaceForAddress(server)
	if err != nil {
		return 0, fmt.Errorf("%w: %s", errEgressNotLocal, server)
	}
	if networkInterface.Flags&net.FlagLoopback == 0 && hasEthernetHeader(networkInterface.Name) {
		return networkInterface.Index, nil
	}
	_, ifindex, err := systemResolver{}.Resolve(destination, "")
	return ifindex, err
}
