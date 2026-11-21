package app

import (
	"context"
	"log"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/protocol"
)

// downFrameSender sends one control frame on one down path, in the same way
// as the server program sends a reply on it.
type downFrameSender interface {
	send(target downTarget, frame []byte, sequence uint16) error
}

// downService runs the down paths of the server: it keeps the DOWN_REGISTER
// frames, sends a probe on each down path and pool member every 2 seconds,
// sends each REGISTER_ACK on the down paths of the client, and writes the
// health to the dataplane.
type downService struct {
	registry *downRegistry
	sender   downFrameSender
	logger   *log.Logger
	sequence atomic.Uint32
}

// handle answers a DOWN_REGISTER or a PROBE_REPLY of a down path. It reports
// false for any other frame.
func (d *downService) handle(frame protocol.ControlFrame, source netip.Addr) bool {
	if d == nil {
		return false
	}
	switch {
	case frame.Type == protocol.ControlDownRegister:
		if err := d.registry.register(frame, source, time.Now()); err != nil {
			d.logger.Printf("mup down path %d of %s: %v", frame.PathID, frame.AdvertisedIP, err)
		}
		return true
	case frame.Type == protocol.ControlProbeReply && frame.Flags&protocol.ControlFlagDownPath != 0:
		if source == frame.AdvertisedIP {
			d.registry.confirm(frame, time.Now())
		}
		return true
	}
	return false
}

// ack sends a REGISTER_ACK on each down path of its client, so an up path is
// healthy when its REGISTER reaches the server, even if the up flow carries
// nothing back.
func (d *downService) ack(frame protocol.ControlFrame, packet []byte) {
	if d == nil || d.sender == nil {
		return
	}
	client := dataplane.ClientKey{AdvertisedIP: frame.AdvertisedIP, InstanceNonce: frame.InstanceNonce}
	for _, target := range d.registry.ackTargets(client, time.Now()) {
		_ = d.sender.send(target, packet, uint16(frame.Sequence))
	}
}

// revoke forgets the down paths of a client that restarted.
func (d *downService) revoke(client dataplane.ClientKey) {
	if d != nil {
		d.registry.revoke(client, time.Now())
	}
}

func (d *downService) run(ctx context.Context) error {
	ticker := time.NewTicker(downProbeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now := <-ticker.C:
			d.probe(now)
			d.registry.sync(now)
		}
	}
}

func (d *downService) probe(now time.Time) {
	if d.sender == nil {
		return
	}
	for _, target := range d.registry.probeTargets(now) {
		sequence := d.sequence.Add(1)
		frame := protocol.ControlFrame{
			Type:          protocol.ControlProbe,
			Transport:     target.transport,
			Flags:         protocol.ControlFlagDownPath,
			PathID:        target.pathID,
			Sequence:      sequence,
			ListenPort:    target.listenPort,
			ServerPort:    target.port,
			InstanceNonce: target.client.InstanceNonce,
			AdvertisedIP:  target.client.AdvertisedIP,
		}
		packet := make([]byte, protocol.ControlFrameLength)
		if err := protocol.EncodeControlFrame(packet, frame); err != nil {
			continue
		}
		_ = d.sender.send(target, packet, uint16(sequence))
	}
}
