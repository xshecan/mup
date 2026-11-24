package app

import (
	"context"
	"log"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/xshecan/mup/control"
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

// handle answers a EGRESS_REGISTER or a PROBE_REPLY of an egress path. The
// server takes such a frame from the advertised IP, or from a via host when
// reflected reports that the frame arrived on an ingress reflect path of its
// client. It reports false for any other frame.
func (d *egressService) handle(frame protocol.ControlFrame, source netip.Addr, reflected bool) bool {
	if d == nil {
		return false
	}
	trusted := source == frame.AdvertisedIP || reflected
	switch {
	case frame.Type == protocol.ControlEgressRegister:
		if !trusted {
			d.logger.Printf("mup egress path %d of %s: EGRESS_REGISTER from %s is not from the client", frame.PathID, frame.AdvertisedIP, source)
			return true
		}
		if err := d.registry.register(frame, time.Now()); err != nil {
			d.logger.Printf("mup egress path %d of %s: %v", frame.PathID, frame.AdvertisedIP, err)
		}
		return true
	case frame.Type == protocol.ControlProbeReply && frame.Flags&protocol.ControlFlagEgressPath != 0:
		if trusted {
			d.registry.confirm(frame, time.Now())
		}
		return true
	}
	return false
}

// arrivedOnReflectPath reports whether a frame arrived on a live ingress reflect
// path of its client. Such a frame comes from a via host of the client, because
// the client reflects it like the REGISTER of the path.
func arrivedOnReflectPath(registry *control.Registry, frame protocol.ControlFrame, path control.PathKey, now time.Time) bool {
	if registry == nil {
		return false
	}
	client := control.ClientKey{AdvertisedIP: frame.AdvertisedIP, InstanceNonce: frame.InstanceNonce}
	return registry.IsReflectPathOf(now, path, client)
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
