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

// egressFrameSender sends one control frame on one egress path, in the same way
// as the server program sends a reply on it.
type egressFrameSender interface {
	send(target egressTarget, frame []byte, sequence uint16) error
}

// egressService runs the egress paths of the server: it keeps the EGRESS_REGISTER
// frames, sends a probe on each egress path and pool member every 2 seconds,
// sends each REGISTER_ACK on the egress paths of the client, and writes the
// health to the dataplane.
type egressService struct {
	registry *egressRegistry
	sender   egressFrameSender
	logger   *log.Logger
	sequence atomic.Uint32
}

// handle answers a EGRESS_REGISTER or a PROBE_REPLY of an egress path. It reports
// false for any other frame.
func (d *egressService) handle(frame protocol.ControlFrame, source netip.Addr) bool {
	if d == nil {
		return false
	}
	switch {
	case frame.Type == protocol.ControlEgressRegister:
		if err := d.registry.register(frame, source, time.Now()); err != nil {
			d.logger.Printf("mup egress path %d of %s: %v", frame.PathID, frame.AdvertisedIP, err)
		}
		return true
	case frame.Type == protocol.ControlProbeReply && frame.Flags&protocol.ControlFlagEgressPath != 0:
		if source == frame.AdvertisedIP {
			d.registry.confirm(frame, time.Now())
		}
		return true
	}
	return false
}

// ack sends a REGISTER_ACK on each egress path of its client, so an ingress path is
// healthy when its REGISTER reaches the server, even if the ingress flow carries
// nothing back.
func (d *egressService) ack(frame protocol.ControlFrame, packet []byte) {
	if d == nil || d.sender == nil {
		return
	}
	client := dataplane.ClientKey{AdvertisedIP: frame.AdvertisedIP, InstanceNonce: frame.InstanceNonce}
	for _, target := range d.registry.ackTargets(client, time.Now()) {
		_ = d.sender.send(target, packet, uint16(frame.Sequence))
	}
}

// revoke forgets the egress paths of a client that restarted.
func (d *egressService) revoke(client dataplane.ClientKey) {
	if d != nil {
		d.registry.revoke(client, time.Now())
	}
}

func (d *egressService) run(ctx context.Context) error {
	ticker := time.NewTicker(egressProbeInterval)
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

func (d *egressService) probe(now time.Time) {
	if d.sender == nil {
		return
	}
	for _, target := range d.registry.probeTargets(now) {
		sequence := d.sequence.Add(1)
		frame := protocol.ControlFrame{
			Type:          protocol.ControlProbe,
			Transport:     target.transport,
			Flags:         protocol.ControlFlagEgressPath,
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
