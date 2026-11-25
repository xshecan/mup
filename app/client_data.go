package app

import (
	"math/bits"
	"net/netip"
	"slices"
	"time"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/measure"
)

// evaluateDataLocked runs the loss gates of the ingress paths and of the
// members of the ingress reflect paths in the groups with a loss limit, on a
// MEASURE round. It then updates the data set of each group and writes the
// path state and the member lists that changed.
func (c *clientController) evaluateDataLocked(now time.Time) error {
	c.lastMeasure = now
	for slot, current := range c.slots {
		if current == nil {
			continue
		}
		limit := current.group.policy.maxLoss.Percent()
		if limit == 0 {
			continue
		}
		m := c.ingressMeasureLocked(slot)
		data, _ := lossMeasurement(&m.loss, now)
		var probe *float64
		if loss, ok := m.probes.LossPercent(now); ok {
			probe = &loss
		}
		m.gate.Evaluate(limit, data, probe, now)
		if !current.path.IngressReflect(current.group.egresses != nil) {
			continue
		}
		var degraded []netip.Addr
		for _, member := range candidateMembers(current.runtimePath()) {
			tracker := m.members[member]
			if tracker == nil {
				continue
			}
			gate := m.memberGates[member]
			if gate == nil {
				gate = &measure.LossGate{}
				m.memberGates[member] = gate
			}
			var memberLoss *float64
			if loss, ok := tracker.LossPercent(now); ok {
				memberLoss = &loss
			}
			if gate.Evaluate(limit, nil, memberLoss, now) {
				degraded = append(degraded, member)
			}
		}
		for member := range m.memberGates {
			if m.members[member] == nil {
				delete(m.memberGates, member)
			}
		}
		perPacket := current.path.Balance == config.BalancePerPacket
		c.reflectMu.Lock()
		if !slices.Equal(c.reflectDegraded[slot], degraded) {
			c.reflectDegraded[slot] = degraded
			if err := c.writeReflectMembersLocked(slot, perPacket); err != nil {
				c.logger.Printf("client path %d: cannot publish the members: %v", slot, err)
			}
		}
		c.reflectMu.Unlock()
	}
	c.dataMasksLocked(true)
	return c.writePathStateLocked(false)
}

// dataMasksLocked computes the data set of each group from the health, the
// loss gates and the latency choice. On a health change, tick is false, and a
// group that prefers latency keeps its path while that path stays usable, so
// only a MEASURE round moves it to a faster path.
func (c *clientController) dataMasksLocked(tick bool) {
	for _, group := range c.groups {
		var candidates []dataCandidate
		for slot, current := range c.slots {
			if current == nil || current.group != group {
				continue
			}
			health, _ := c.health.Path(slot)
			candidate := dataCandidate{id: slot, priority: int(current.priority), healthy: health.Healthy}
			if m := c.ingressMeasures[slot]; m != nil {
				candidate.degraded = group.policy.maxLoss != 0 && m.gate.Degraded()
				candidate.rtt = choiceRTT(&m.probes, c.lastMeasure)
			}
			candidates = append(candidates, candidate)
		}
		var chooser *measure.LatencyChooser
		if group.chooser != nil && group.settings.Mode == config.ModeFailover {
			chooser = group.chooser
		}
		if chooser != nil && !tick && group.hasChosen {
			if mask := dataSet(candidates, nil, c.lastMeasure); mask&(1<<group.chosen) != 0 {
				group.dataMask = 1 << group.chosen
				continue
			}
		}
		group.dataMask = dataSet(candidates, chooser, c.lastMeasure)
		group.hasChosen = false
		if chooser != nil && group.dataMask != 0 {
			group.chosen, group.hasChosen = bits.TrailingZeros8(group.dataMask), true
		}
	}
}

// writeReflectMembersLocked writes the member list of an ingress reflect path:
// its healthy members without the degraded ones, or all its healthy members
// when every one of them is degraded. An empty list never reaches the
// dataplane, because the data path sends a packet unreflected when the list
// is empty, and the server drops it. The dataplane keeps its last list. By
// then the path missed its rounds and has left the path mask, or is about to.
// The caller holds reflectMu.
func (c *clientController) writeReflectMembersLocked(slot int, perPacket bool) error {
	members := publishedMembers(c.reflectHealthy[slot], c.reflectDegraded[slot])
	if len(members) == 0 {
		return nil
	}
	return c.dataplane.SetIngressReflect(slot, members, perPacket)
}
