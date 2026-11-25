package app

import (
	"net/netip"
	"slices"
	"time"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
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
	if err := c.syncPathSettingsLocked(); err != nil {
		return err
	}
	return c.writePathStateLocked(false)
}

// dataMasksLocked computes the data set of each group from the health, the
// loss gates and the latency choice. On a health change, tick is false, and a
// group that prefers latency keeps its path while that path stays usable, so
// only a MEASURE round moves it to a faster path. The data set is the usable
// set, and the chosen path of a latency choice becomes the head of the order
// that syncPathSettingsLocked writes.
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
		if chooser == nil {
			group.hasHead = false
		}
		if chooser != nil && !tick && group.hasChosen {
			if mask, _, _ := dataSet(candidates, nil, c.lastMeasure); mask&(1<<group.chosen) != 0 {
				group.dataMask = mask
				continue
			}
		}
		mask, chosen, ok := dataSet(candidates, chooser, c.lastMeasure)
		group.dataMask = mask
		group.hasChosen = false
		if chooser != nil && ok && mask&(1<<chosen) != 0 {
			group.chosen, group.hasChosen = chosen, true
			group.head, group.hasHead = chosen, true
		}
	}
}

// groupPathsLocked returns the paths of a group by slot, with current in its
// slot. A path that is about to join the group is not in c.slots yet.
func (c *clientController) groupPathsLocked(group *pathGroup, slot int, current *clientPath) [config.MaxPaths]*clientPath {
	var paths [config.MaxPaths]*clientPath
	for index, path := range c.slots {
		if path != nil && path.group == group {
			paths[index] = path
		}
	}
	paths[slot] = current
	return paths
}

// pathSettingsLocked is the dataplane setting of a path in slot: the path on
// its server port with its rate limit, the priority of the order of its group,
// and its balancer weight.
func (c *clientController) pathSettingsLocked(slot int, current *clientPath) dataplane.PathSettings {
	paths := c.groupPathsLocked(current.group, slot, current)
	settings := clientPathSettings(current.runtimePath(), c.client.AdvertisedIP, current.ifindex, dataPriority(current.group, paths, slot))
	shares := make([]rateShare, 0, len(paths))
	for index, path := range paths {
		if path != nil {
			shares = append(shares, rateShare{id: index, limit: rateLimitOf(path.path), members: len(candidateMembers(path.path))})
		}
	}
	settings.Weight = balancerWeights(current.group.settings.Mode, shares)[slot]
	return settings
}

// dataPriority is the priority that the dataplane gets for the path in slot.
// Without a latency choice it is the configured priority. With one, the
// chosen path gets zero, and the other paths of the group get 1, 2 and so on
// in their configured order, so the failover mode tries the chosen path first
// and then the others as before.
func dataPriority(group *pathGroup, paths [config.MaxPaths]*clientPath, slot int) uint8 {
	current := paths[slot]
	if !group.hasHead || group.head < 0 || group.head >= len(paths) || paths[group.head] == nil {
		return current.priority
	}
	if slot == group.head {
		return 0
	}
	rank := uint8(1)
	for index, other := range paths {
		if other == nil || index == slot || index == group.head {
			continue
		}
		if other.priority < current.priority || other.priority == current.priority && index < slot {
			rank++
		}
	}
	return rank
}

// syncPathSettingsLocked writes the setting of each path whose priority or
// weight changed. Without a latency choice and without rate limits, nothing
// changes, and nothing is written. The dataplane clears the member list of a
// slot when it writes the path, so an ingress reflect path gets its list again.
func (c *clientController) syncPathSettingsLocked() error {
	for slot, current := range c.slots {
		if current == nil {
			continue
		}
		settings := c.pathSettingsLocked(slot, current)
		if settings == current.written {
			continue
		}
		if err := c.dataplane.SetPath(slot, settings); err != nil {
			return err
		}
		current.written = settings
		if !current.path.IngressReflect(current.group.egresses != nil) {
			continue
		}
		c.reflectMu.Lock()
		err := c.writeReflectMembersLocked(slot, current.path.Balance == config.BalancePerPacket)
		c.reflectMu.Unlock()
		if err != nil {
			return err
		}
	}
	return nil
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
