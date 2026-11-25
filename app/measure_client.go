package app

import (
	"net/netip"
	"time"

	"github.com/xshecan/mup/api"
	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/measure"
	"github.com/xshecan/mup/protocol"
)

// measureInterval is the time between two MEASURE rounds of the client.
const measureInterval = 2 * time.Second

// ingressMeasure measures one ingress path of the client. The probes are the
// MEASURE frames, and the loss pairs the count of the client in a MEASURE with
// the count of the server in its reply. An ingress reflect path also tracks
// the MEASURE through each member.
type ingressMeasure struct {
	sequence uint32
	// round is the latest MEASURE round, which gives the egress RTT samples.
	round   ingressRound
	probes  measure.Probes
	loss    measure.Loss
	rate    measure.Rate
	members map[netip.Addr]*measure.Probes
	// gate and memberGates hold the loss gates of the path and of its
	// members in a group with a loss limit.
	gate        measure.LossGate
	memberGates map[netip.Addr]*measure.LossGate
}

func newIngressMeasure() *ingressMeasure {
	return &ingressMeasure{members: make(map[netip.Addr]*measure.Probes), memberGates: make(map[netip.Addr]*measure.LossGate)}
}

// clientEgressMeasure measures one egress path of the client. The loss pairs
// the count of the server in a PROBE with the count of the client when the
// probe arrived. The RTT samples come from the ACKs and the MEASURE replies
// that arrive on the path.
type clientEgressMeasure struct {
	loss measure.Loss
	rate measure.Rate
	rtts measure.RTTs
}

// measureSend is one MEASURE that a round sends. A frame of an ingress reflect
// path goes through member.
type measureSend struct {
	registration pathRegistration
	member       netip.Addr
	frame        []byte
}

func (c *clientController) ingressMeasureLocked(slot int) *ingressMeasure {
	if c.ingressMeasures[slot] == nil {
		c.ingressMeasures[slot] = newIngressMeasure()
	}
	return c.ingressMeasures[slot]
}

func (c *clientController) egressMeasureLocked(slot int) *clientEgressMeasure {
	if c.egressMeasures[slot] == nil {
		c.egressMeasures[slot] = &clientEgressMeasure{}
	}
	return c.egressMeasures[slot]
}

// measureRound samples the counters of every path and sends one MEASURE on
// every ingress path, healthy or not. An ingress reflect path sends one
// through each candidate member. A MEASURE without an answer changes nothing
// but the measurement.
func (c *clientController) measureRound(now time.Time) {
	ingress, egress, countErr := c.dataplane.ClientPathCounters()
	counted := countErr == nil
	c.mu.Lock()
	var sends []measureSend
	for slot, current := range c.slots {
		if current == nil {
			continue
		}
		m := c.ingressMeasureLocked(slot)
		var code uint32
		if counted {
			m.rate.Sample(ingress[slot].Packets, ingress[slot].Bytes, now)
			code = measure.EncodeCount(ingress[slot].Packets)
		}
		m.sequence++
		m.probes.Sent(m.sequence, now)
		m.round = ingressRound{known: true, sequence: m.sequence, sentAt: now}
		registration := c.registrationLocked(current.group, current.runtimePath(), slot)
		if !registration.ingressReflect {
			if frame, err := measureFrame(registration, netip.Addr{}, m.sequence, code); err == nil {
				sends = append(sends, measureSend{registration: registration, frame: frame})
			}
			continue
		}
		for member := range m.members {
			if !containsAddr(registration.members, member) {
				delete(m.members, member)
			}
		}
		for _, member := range registration.members {
			frame, err := measureFrame(registration, member, m.sequence, code)
			if err != nil {
				continue
			}
			tracker := m.members[member]
			if tracker == nil {
				tracker = &measure.Probes{}
				m.members[member] = tracker
			}
			tracker.Sent(m.sequence, now)
			sends = append(sends, measureSend{registration: registration, member: member, frame: frame})
		}
	}
	if counted {
		for slot, current := range c.egressSlots {
			if current != nil {
				c.egressMeasureLocked(slot).rate.Sample(egress[slot].Packets, egress[slot].Bytes, now)
			}
		}
	}
	// The data sets follow the loss and the RTT that this round measured
	// up to now. A new answer counts in the next round.
	if err := c.evaluateDataLocked(now); err != nil {
		c.logger.Printf("client: cannot write the path state: %v", err)
	}
	c.mu.Unlock()
	for _, send := range sends {
		if send.member.IsValid() {
			_ = c.controls.sendIngressMember(send.registration, send.member, send.frame)
		} else {
			_ = c.controls.sendIngress(send.registration, send.frame)
		}
	}
}

// measureFrame builds the MEASURE of an ingress path. It has the fields of a
// REGISTER of the path, or of the REGISTER of one member, with its own
// sequence and the count code of the client in the lease field.
func measureFrame(registration pathRegistration, member netip.Addr, sequence, code uint32) ([]byte, error) {
	frame := protocol.ControlFrame{
		Type:          protocol.ControlMeasure,
		Transport:     registration.path.Transport,
		PathID:        registration.pathID,
		Sequence:      sequence,
		ListenPort:    registration.listenPort,
		ServerPort:    registration.path.ServerPort,
		LeaseSeconds:  code,
		InstanceNonce: registration.nonce,
		AdvertisedIP:  registration.advertisedIP,
	}
	if member.IsValid() {
		frame.Flags = protocol.ControlFlagIngressReflect | protocol.ControlFlagReturnIP
		frame.ReturnIP = member
	}
	packet := make([]byte, protocol.ControlFrameLength)
	if err := protocol.EncodeControlFrame(packet, frame); err != nil {
		return nil, err
	}
	return packet, nil
}

// handleMeasureReply takes a MEASURE_REPLY that arrived on the socket of a
// path or on an egress path. The first answer of a round gives the RTT and a
// loss marker of the ingress path. Each egress path that the reply arrived on
// gets an RTT sample, as from a REGISTER_ACK.
func (c *clientController) handleMeasureReply(reply egressProbe) {
	frame := reply.frame
	if frame.Type != protocol.ControlMeasureReply || int(frame.PathID) >= config.MaxPaths {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if frame.AdvertisedIP != c.client.AdvertisedIP || frame.InstanceNonce != c.nonce {
		return
	}
	slot := int(frame.PathID)
	current := c.slots[slot]
	if current == nil || frame.ListenPort != current.group.settings.ListenPort {
		return
	}
	m := c.ingressMeasureLocked(slot)
	if frame.Flags&protocol.ControlFlagIngressReflect != 0 {
		if tracker := m.members[frame.ReturnIP]; tracker != nil {
			tracker.Answered(frame.Sequence, reply.received)
		}
	}
	// Only the first answer of a round gives a marker, so the copies on the
	// other egress paths and the answers of the other members do not.
	if _, first := m.probes.Answered(frame.Sequence, reply.received); first {
		tx, txOK := measure.DecodeCount(frame.LeaseSeconds)
		rx, rxOK := measure.DecodeCount(frame.PeerCount)
		if txOK && rxOK {
			m.loss.Mark(tx, rx, reply.received)
		}
	}
	if current.group.egresses == nil || !m.round.known || m.round.sequence != frame.Sequence {
		return
	}
	for index, egress := range c.egressSlots {
		if egress == nil || egress.group != current.group ||
			!egressSourceMatches(egress.path, reply.source, reply.transport, reply.port) {
			continue
		}
		// The earliest arrival of a round on each egress path counts.
		arrival := &c.measureArrivals[index][slot]
		if arrival.known && arrival.sequence == frame.Sequence {
			return
		}
		*arrival = egressArrival{known: true, sequence: frame.Sequence, at: reply.received}
		rtt := reply.received.Sub(m.round.sentAt)
		if rtt >= 0 && rtt <= egressRTTLimit {
			c.addEgressSampleLocked(index, slot, egressSample{known: true, rtt: rtt, at: reply.received})
		}
		return
	}
}

// addEgressSampleLocked keeps an RTT sample of an egress path for an ingress
// path, and adds it to the RTT window of the egress path.
func (c *clientController) addEgressSampleLocked(egress, ingress int, sample egressSample) {
	c.samples[egress][ingress] = sample
	c.egressMeasureLocked(egress).rtts.Add(sample.rtt, sample.at)
}

// markEgressProbeLocked adds the loss marker of a PROBE of an egress path:
// the count of the server in the probe, and the count of the client when the
// probe arrived.
func (c *clientController) markEgressProbeLocked(slot int, txCode, rxCode uint32, at time.Time) {
	tx, txOK := measure.DecodeCount(txCode)
	rx, rxOK := measure.DecodeCount(rxCode)
	if txOK && rxOK {
		c.egressMeasureLocked(slot).loss.Mark(tx, rx, at)
	}
}

// ingressMeasurementLocked is the measurement of an ingress path.
func (c *clientController) ingressMeasurementLocked(slot int, now time.Time) api.Measurement {
	m := c.ingressMeasures[slot]
	if m == nil {
		return api.Measurement{}
	}
	view := probesMeasurement(&m.probes, now)
	view.LossPercent, view.LossLongPercent = lossMeasurement(&m.loss, now)
	view.RatePacketsPerSecond, view.RateBitsPerSecond = m.rate.Rate(now)
	return view
}

// egressMeasurementLocked is the measurement of an egress path. It has no
// probe loss, because the client does not probe its egress paths.
func (c *clientController) egressMeasurementLocked(slot int, now time.Time) api.Measurement {
	m := c.egressMeasures[slot]
	if m == nil {
		return api.Measurement{}
	}
	var view api.Measurement
	view.LossPercent, view.LossLongPercent = lossMeasurement(&m.loss, now)
	if rtt, ok := m.rtts.Avg(now); ok {
		view.RTTAvgSeconds = rtt.Seconds()
	}
	if jitter, ok := m.rtts.Jitter(now); ok {
		view.RTTJitterSeconds = jitter.Seconds()
	}
	view.RatePacketsPerSecond, view.RateBitsPerSecond = m.rate.Rate(now)
	return view
}

// Members lists each member of each ingress reflect path. A member is healthy
// while it answers, and degraded while its probe loss is above the loss limit
// of its group. A degraded member leaves the list of the dataplane, unless
// every healthy member of the path is degraded.
func (c *clientController) Members() (api.MemberList, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	members := []api.Member{}
	for slot, current := range c.slots {
		if current == nil || !current.path.IngressReflect(current.group.egresses != nil) {
			continue
		}
		c.reflectMu.Lock()
		published := c.reflectHealthy[slot]
		degraded := c.reflectDegraded[slot]
		c.reflectMu.Unlock()
		m := c.ingressMeasures[slot]
		for _, member := range candidateMembers(current.runtimePath()) {
			entry := api.Member{
				Direction:  directionIngress,
				PathID:     slot,
				ListenPort: current.group.settings.ListenPort,
				Address:    member.String(),
				Healthy:    containsAddr(published, member),
				Degraded:   containsAddr(degraded, member),
			}
			if m != nil {
				if tracker := m.members[member]; tracker != nil {
					entry.Measurement = probesMeasurement(tracker, now)
				}
			}
			members = append(members, entry)
		}
	}
	return api.MemberList{Members: members}, nil
}

// clearIngressMeasureLocked starts the measurement of an ingress path again.
func (c *clientController) clearIngressMeasureLocked(slot int) {
	c.ingressMeasures[slot] = nil
	c.reflectMu.Lock()
	c.reflectDegraded[slot] = nil
	c.reflectMu.Unlock()
	for index := range c.measureArrivals {
		c.measureArrivals[index][slot] = egressArrival{}
	}
}

// clearEgressMeasureLocked starts the measurement of an egress path again.
func (c *clientController) clearEgressMeasureLocked(slot int) {
	c.egressMeasures[slot] = nil
	c.measureArrivals[slot] = [config.MaxPaths]egressArrival{}
}

// egressCounts reads the counts of the data packets that the client accepted
// on its egress paths. ok is false when the dataplane cannot read them.
func egressCounts(plane clientDataplane) (counts [dataplane.MaxEgressPaths]dataplane.PathCounter, ok bool) {
	_, counts, err := plane.ClientPathCounters()
	return counts, err == nil
}
