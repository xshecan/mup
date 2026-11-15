//go:build linux

package app

import (
	"context"
	"encoding/binary"
	"log"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"

	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/protocol"
)

const reflectorEmitInterval = 2 * time.Second

// reflectorEmitter sends a control probe to each UDP pool client, spoofed from
// each pool member, so the client can confirm which members reach it. It uses a
// raw socket, because the probe source is the reflector, not the server.
type reflectorEmitter struct {
	members memberSource
	targets *reflectorTargets
	seq     uint32
}

// memberSource reads the current members of a pool.
type memberSource interface {
	PoolMembers(key dataplane.PoolKey) []netip.Addr
}

func newReflectorEmitLoop(runtime *dataplane.Runtime, targets *reflectorTargets) loop {
	emitter := &reflectorEmitter{members: runtime, targets: targets}
	return emitter.run
}

func (e *reflectorEmitter) run(ctx context.Context) error {
	fd, err := openSpoofSocket()
	if err != nil {
		// The emitter needs a raw socket. Without it the server still runs,
		// but it cannot measure UDP reflector health, so it logs and idles.
		log.Printf("mup reflector probe emitter disabled: %v", err)
		<-ctx.Done()
		return ctx.Err()
	}
	defer unix.Close(fd)
	ticker := time.NewTicker(reflectorEmitInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			e.emitAll(fd)
		}
	}
}

func (e *reflectorEmitter) emitAll(fd int) {
	for _, target := range e.targets.active(time.Now()) {
		members := e.members.PoolMembers(dataplane.PoolKey{Base: target.base, Transport: protocol.TransportUDP})
		for _, member := range members {
			e.seq++
			frame, err := probeFrame(target, e.seq)
			if err != nil {
				continue
			}
			packet := buildIPv4UDP(member, target.advertisedIP, target.serverPort, target.listenPort, frame)
			var destination unix.SockaddrInet4
			destination.Addr = target.advertisedIP.As4()
			_ = unix.Sendto(fd, packet, 0, &destination)
		}
	}
}

// probeFrame builds the control probe. The reflector is the spoofed IP source
// of the packet, so the frame itself carries only the client identity.
func probeFrame(target reflectorTarget, sequence uint32) ([]byte, error) {
	frame := protocol.ControlFrame{
		Type:          protocol.ControlProbe,
		Transport:     protocol.TransportUDP,
		PathID:        target.pathID,
		Sequence:      sequence,
		ListenPort:    target.listenPort,
		ServerPort:    target.serverPort,
		InstanceNonce: target.nonce,
		AdvertisedIP:  target.advertisedIP,
	}
	packet := make([]byte, protocol.ControlFrameLength)
	if err := protocol.EncodeControlFrame(packet, frame); err != nil {
		return nil, err
	}
	return packet, nil
}

// openSpoofSocket opens a raw IPv4 socket that sends packets with a header the
// caller builds, so the source address can be a reflector.
func openSpoofSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return -1, err
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// buildIPv4UDP builds an IPv4 UDP packet with the given header fields. The UDP
// checksum is zero, which IPv4 allows.
func buildIPv4UDP(source, destination netip.Addr, sourcePort, destinationPort uint16, payload []byte) []byte {
	udpLength := 8 + len(payload)
	totalLength := 20 + udpLength
	packet := make([]byte, totalLength)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLength))
	packet[8] = 64
	packet[9] = unix.IPPROTO_UDP
	sourceBytes := source.As4()
	destinationBytes := destination.As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], destinationBytes[:])
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[0:20]))
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(udpLength))
	copy(packet[28:], payload)
	return packet
}
