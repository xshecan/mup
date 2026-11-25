package app

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/measure"
	"github.com/xshecan/mup/protocol"
)

// egressDriver runs the probe rounds of a server for the egress paths of one
// client. Each path loses a share of its data, and its probes come back after
// a round trip time. A member in silent answers only on even rounds.
type egressDriver struct {
	plane    *fakeEgressPlane
	registry *egressRegistry
	sender   *recordingEgressSender
	service  *egressService
	frames   []protocol.ControlFrame
	start    time.Time
	round    int
	sent     map[uint16]uint64
	got      map[uint16]uint64
	loss     map[uint16]float64
	rtt      map[uint16]time.Duration
	silent   map[netip.Addr]bool
}

func newEgressDriver(frames ...protocol.ControlFrame) *egressDriver {
	plane := newFakeEgressPlane()
	plane.members[dataplane.PoolKey{Base: egressPool, Transport: protocol.TransportICMP}] = egressMembers
	registry := newTestEgressRegistry(plane)
	sender := &recordingEgressSender{}
	return &egressDriver{
		plane:    plane,
		registry: registry,
		sender:   sender,
		service:  &egressService{registry: registry, sender: sender, logger: discardLogger},
		frames:   frames,
		start:    time.Now().Add(-20 * time.Minute),
		sent:     map[uint16]uint64{},
		got:      map[uint16]uint64{},
		loss:     map[uint16]float64{},
		rtt:      map[uint16]time.Duration{},
		silent:   map[netip.Addr]bool{},
	}
}

func (d *egressDriver) now() time.Time {
	return d.start.Add(time.Duration(d.round) * egressProbeInterval)
}

// run registers the paths, sends one probe round, answers it, and syncs, as
// the client and the egress service do every round.
func (d *egressDriver) run(t *testing.T, rounds int) {
	t.Helper()
	for range rounds {
		d.round++
		now := d.now()
		for _, frame := range d.frames {
			if err := d.registry.register(frame, now); err != nil {
				t.Fatalf("register: %v", err)
			}
			id := frame.PathID
			d.sent[id] += 100
			d.got[id] += uint64(100 * (1 - d.loss[id]))
			d.plane.setCounter(egressKeyOf, id, dataplane.PathCounterEgress, d.sent[id])
		}
		d.sender.frames, d.sender.sent = nil, nil
		d.service.probe(now)
		for index, probe := range d.sender.frames {
			target := d.sender.sent[index]
			member := target.member
			if !member.IsValid() {
				member = egressServer
			}
			if d.silent[member] && d.round%2 == 1 {
				continue
			}
			rtt := d.rtt[probe.PathID]
			if rtt == 0 {
				rtt = 20 * time.Millisecond
			}
			reply := probeReply(probe.PathID, probe.Transport, member)
			reply.Sequence = probe.Sequence
			reply.LeaseSeconds = measure.EncodeCount(d.got[probe.PathID])
			d.registry.confirm(reply, now.Add(rtt))
		}
		d.registry.sync(now.Add(100 * time.Millisecond))
	}
}

func (d *egressDriver) healthyMask() uint8 {
	return d.plane.groups[egressGroupOf].HealthyMask
}

// first is the path that the failover mode of the group tries first: the
// preferred path, or else the path of the data set with the lowest ID. It is
// -1 when the data set is empty.
func (d *egressDriver) first() int {
	group := d.plane.groups[egressGroupOf]
	if group.HasPreferred && group.HealthyMask&(1<<group.Preferred) != 0 {
		return int(group.Preferred)
	}
	for id := range dataplane.MaxEgressPaths {
		if group.HealthyMask&(1<<id) != 0 {
			return id
		}
	}
	return -1
}

// runUntilFirst runs rounds until the failover mode tries path want first,
// and fails after limit rounds.
func (d *egressDriver) runUntilFirst(t *testing.T, want int, limit int) {
	t.Helper()
	for range limit {
		if d.first() == want {
			return
		}
		d.run(t, 1)
	}
	t.Fatalf("first egress path = %d after %d rounds, want %d", d.first(), limit, want)
}

// runUntil runs rounds until the group mask is want, and fails after limit
// rounds.
func (d *egressDriver) runUntil(t *testing.T, want uint8, limit int) {
	t.Helper()
	for range limit {
		if d.healthyMask() == want {
			return
		}
		d.run(t, 1)
	}
	t.Fatalf("egress mask = %#b after %d rounds, want %#b", d.healthyMask(), limit, want)
}

func (d *egressDriver) egressPath(t *testing.T, id uint16) egressView {
	t.Helper()
	groups := d.registry.clients(d.now().Add(100 * time.Millisecond))[egressKeyOf]
	if len(groups) != 1 {
		t.Fatalf("groups = %#v", groups)
	}
	for _, path := range groups[0].Paths {
		if path.ID == id {
			return egressView{group: groups[0].TolerancePercent, prefer: groups[0].Prefer, active: path.Active, degraded: path.Degraded, healthy: path.Healthy, reason: path.Reason}
		}
	}
	t.Fatalf("egress path %d is missing", id)
	return egressView{}
}

type egressView struct {
	group                     float64
	prefer                    string
	active, degraded, healthy bool
	reason                    string
}

func settingsFrame(id, port uint16, mode config.Mode, settings protocol.EgressSettings) protocol.ControlFrame {
	frame := egressFrame(id, port, protocol.TransportUDP, mode)
	frame.LeaseSeconds = protocol.PackEgressLease(registrationLeaseSeconds, settings)
	return frame
}

func TestTheServerMovesTheRepliesOffALossyEgressPath(t *testing.T) {
	t.Parallel()

	settings := protocol.EgressSettings{ToleranceTenths: 50}
	driver := newEgressDriver(settingsFrame(0, 9300, config.ModeFailover, settings), settingsFrame(1, 9301, config.ModeFailover, settings))
	driver.run(t, 2)
	if mask := driver.healthyMask(); mask != 0b11 {
		t.Fatalf("first mask = %#b, want both paths", mask)
	}
	driver.loss[0] = 0.2
	driver.runUntil(t, 0b10, 10)
	degradedAt := driver.now()
	if view := driver.egressPath(t, 0); !view.healthy || !view.degraded || view.active || !strings.HasPrefix(view.reason, "loss ") || !strings.HasSuffix(view.reason, "% above 5%") || view.group != 5 {
		t.Fatalf("lossy egress path = %#v", view)
	}
	if view := driver.egressPath(t, 1); !view.active || view.degraded {
		t.Fatalf("other egress path = %#v, want active", view)
	}
	driver.loss[0] = 0
	for driver.now().Sub(degradedAt) < measure.LossHoldFirst-egressProbeInterval {
		driver.run(t, 1)
		if mask := driver.healthyMask(); mask != 0b10 {
			t.Fatalf("mask = %#b during the hold, want %#b", mask, 0b10)
		}
	}
	driver.runUntil(t, 0b11, 3)
	if view := driver.egressPath(t, 0); view.degraded || !view.active {
		t.Fatalf("recovered egress path = %#v", view)
	}
}

func TestTheServerKeepsAllLossyEgressPaths(t *testing.T) {
	t.Parallel()

	settings := protocol.EgressSettings{ToleranceTenths: 50}
	driver := newEgressDriver(settingsFrame(0, 9300, config.ModeBalancer, settings), settingsFrame(1, 9301, config.ModeBalancer, settings))
	driver.loss[0], driver.loss[1] = 0.2, 0.2
	driver.run(t, 10)
	if mask := driver.healthyMask(); mask != 0b11 {
		t.Fatalf("mask = %#b, want both lossy paths", mask)
	}
	if view := driver.egressPath(t, 1); !view.degraded || !view.active {
		t.Fatalf("lossy egress path = %#v, want degraded and active", view)
	}
}

func TestTheServerPicksTheFasterEgressPath(t *testing.T) {
	t.Parallel()

	settings := protocol.EgressSettings{PreferLatency: true}
	driver := newEgressDriver(settingsFrame(0, 9300, config.ModeFailover, settings), settingsFrame(1, 9301, config.ModeFailover, settings))
	driver.rtt[0], driver.rtt[1] = 60*time.Millisecond, 15*time.Millisecond
	driver.run(t, 1)
	// The data set keeps both paths, so a full path can spill, and the
	// choice is the path that the failover mode tries first.
	if mask, first := driver.healthyMask(), driver.first(); mask != 0b11 || first != 0 {
		t.Fatalf("first mask = %#b with path %d first, want both with path 0 by its order", mask, first)
	}
	driver.runUntilFirst(t, 1, 12)
	if mask := driver.healthyMask(); mask != 0b11 {
		t.Fatalf("mask = %#b, want both paths", mask)
	}
	if view := driver.egressPath(t, 1); !view.active || view.prefer != "latency" {
		t.Fatalf("fast egress path = %#v", view)
	}
	if view := driver.egressPath(t, 0); view.active {
		t.Fatalf("slow egress path = %#v, want not active", view)
	}
	driver.rtt[0] = 14 * time.Millisecond
	for range 30 {
		driver.run(t, 1)
		if mask, first := driver.healthyMask(), driver.first(); mask != 0b11 || first != 1 {
			t.Fatalf("mask = %#b with path %d first after a small change, want path 1 first", mask, first)
		}
	}
	// The latency choice counts only in the failover mode.
	repeater := newEgressDriver(settingsFrame(0, 9300, config.ModeRepeater, settings), settingsFrame(1, 9301, config.ModeRepeater, settings))
	repeater.rtt[0] = 60 * time.Millisecond
	repeater.run(t, 12)
	if mask := repeater.healthyMask(); mask != 0b11 || repeater.plane.groups[egressGroupOf].HasPreferred {
		t.Fatalf("repeater group = %#v, want both paths and no preferred path", repeater.plane.groups[egressGroupOf])
	}
}

func TestADegradedEgressMemberLeavesThePath(t *testing.T) {
	t.Parallel()

	pool := poolFrame(0, 9200)
	pool.LeaseSeconds = protocol.PackEgressLease(registrationLeaseSeconds, protocol.EgressSettings{ToleranceTenths: 50})
	driver := newEgressDriver(pool)
	driver.silent[egressMembers[1]] = true
	driver.run(t, 10)
	key := egressKey{client: egressKeyOf, id: 0}
	want := []netip.Addr{egressMembers[0], egressMembers[2]}
	if got := driver.plane.paths[key].Members; !slices.Equal(got, want) {
		t.Fatalf("members = %v, want %v", got, want)
	}
	for _, member := range driver.registry.members(driver.now()) {
		degraded := member.Address == egressMembers[1].String()
		if !member.Healthy || member.Degraded != degraded {
			t.Fatalf("member = %#v, want healthy and degraded %v", member, degraded)
		}
	}
	// When every healthy member degrades, they all stay.
	driver.silent[egressMembers[0]], driver.silent[egressMembers[2]] = true, true
	driver.run(t, 6)
	if got := driver.plane.paths[key].Members; !slices.Equal(got, egressMembers) {
		t.Fatalf("members = %v, want all healthy members", got)
	}
}

func TestAnOldStyleEgressRegisterGivesNoSettings(t *testing.T) {
	t.Parallel()

	settings := protocol.EgressSettings{ToleranceTenths: 50, PreferLatency: true}
	driver := newEgressDriver(settingsFrame(0, 9300, config.ModeFailover, settings), settingsFrame(1, 9301, config.ModeFailover, settings))
	driver.run(t, 1)
	if view := driver.egressPath(t, 0); view.group != 5 || view.prefer != "latency" {
		t.Fatalf("group settings = %#v", view)
	}
	// The latest frame sets the settings of the group, and a lease of 30
	// carries none.
	driver.frames = []protocol.ControlFrame{
		egressFrame(0, 9300, protocol.TransportUDP, config.ModeFailover),
		egressFrame(1, 9301, protocol.TransportUDP, config.ModeFailover),
	}
	driver.loss[0] = 0.5
	driver.run(t, 10)
	if view := driver.egressPath(t, 0); view.group != 0 || view.prefer != "" || view.degraded {
		t.Fatalf("group after an old frame = %#v, want no settings", view)
	}
	if mask := driver.healthyMask(); mask != 0b11 {
		t.Fatalf("mask = %#b, want the healthy paths", mask)
	}
}

func TestWithoutSettingsTheEgressMasksAreTheHealth(t *testing.T) {
	t.Parallel()

	driver := newEgressDriver(poolFrame(0, 9200), egressFrame(1, 9300, protocol.TransportUDP, config.ModeRepeater))
	driver.silent[egressMembers[1]] = true
	driver.loss[1] = 0.5
	driver.rtt[1] = 80 * time.Millisecond
	key := egressKey{client: egressKeyOf, id: 0}
	for range 20 {
		driver.run(t, 1)
		now := driver.now().Add(100 * time.Millisecond)
		driver.registry.mu.Lock()
		var healthy uint8
		var members []netip.Addr
		for pathKey, path := range driver.registry.paths {
			list := driver.registry.healthyLocked(path, now)
			if len(list) > 0 {
				healthy |= 1 << pathKey.id
			}
			if pathKey == key {
				members = list
			}
		}
		driver.registry.mu.Unlock()
		if mask := driver.healthyMask(); mask != healthy {
			t.Fatalf("mask = %#b, want the healthy mask %#b", mask, healthy)
		}
		if got := driver.plane.paths[key].Members; !slices.Equal(got, members) {
			t.Fatalf("members = %v, want the healthy members %v", got, members)
		}
	}
}

func TestTheActiveEgressPathsFollowTheMode(t *testing.T) {
	t.Parallel()

	settings := protocol.EgressSettings{ToleranceTenths: 50}
	active := func(t *testing.T, driver *egressDriver) [2]bool {
		t.Helper()
		return [2]bool{driver.egressPath(t, 0).active, driver.egressPath(t, 1).active}
	}
	// Failover sends on the first path of the data set only.
	failover := newEgressDriver(settingsFrame(0, 9300, config.ModeFailover, settings), settingsFrame(1, 9301, config.ModeFailover, settings))
	failover.run(t, 3)
	if got := active(t, failover); got != [2]bool{true, false} {
		t.Fatalf("failover active = %v, want only path 0", got)
	}
	// A degraded first path makes the second active.
	failover.loss[0] = 0.2
	failover.runUntil(t, 0b10, 10)
	if got := active(t, failover); got != [2]bool{false, true} {
		t.Fatalf("failover active with path 0 degraded = %v, want only path 1", got)
	}
	// When both are degraded, the fallback uses both, and failover sends on
	// the first.
	failover.loss[1] = 0.2
	failover.runUntil(t, 0b11, 10)
	if got := active(t, failover); got != [2]bool{true, false} {
		t.Fatalf("failover active with both degraded = %v, want only path 0", got)
	}
	if view := failover.egressPath(t, 1); !view.degraded {
		t.Fatalf("path 1 = %#v, want degraded", view)
	}

	balancer := newEgressDriver(settingsFrame(0, 9300, config.ModeBalancer, settings), settingsFrame(1, 9301, config.ModeBalancer, settings))
	balancer.run(t, 3)
	if got := active(t, balancer); got != [2]bool{true, true} {
		t.Fatalf("balancer active = %v, want both paths", got)
	}
	// Without a healthy path no path is active.
	later := balancer.now().Add(egressHealthWindow + time.Second)
	balancer.registry.sync(later)
	groups := balancer.registry.clients(later)[egressKeyOf]
	if len(groups) != 1 || len(groups[0].Paths) != 2 {
		t.Fatalf("groups = %#v, want both paths", groups)
	}
	for _, path := range groups[0].Paths {
		if path.Healthy || path.Active {
			t.Fatalf("path %d = %#v, want unhealthy and not active", path.ID, path)
		}
	}
}
