package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"math/bits"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/xshecan/mup/api"
	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/control"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/protocol"
)

const (
	controlReplyTimeout = 900 * time.Millisecond
	missLimit           = 3
	registrationRefresh = 10 * time.Second
	registrationRetry   = time.Second

	// portMoveMisses is the number of REGISTER frames in a row without an
	// answer that moves a path with a port range to another server port.
	portMoveMisses = 10
	// portMoveMaxDoublings limits the wait between two moves without an
	// answer to 16 times the first wait.
	portMoveMaxDoublings = 4
)

// probeReporter passes the result of one REGISTER to the controller. repliedAt
// is the time of the first answer. It is zero when the path reports right
// after the answer, and the controller then takes the time of the report.
type probeReporter func(ctx context.Context, sequence uint32, sentAt, repliedAt time.Time, result registerResult) error

// pathConn owns the control socket of one path.
type pathConn interface {
	// Run sends REGISTER frames until ctx ends, and then closes the socket.
	Run(ctx context.Context, report probeReporter) error
	Close() error
}

// pathRegistration holds the values that a path sends in its REGISTER frames.
// An ingress path of a group with separate egress paths has egresses, and it sends the
// EGRESS_REGISTER frames of the group before each REGISTER. Its ACK can then
// arrive on any egress path.
type pathRegistration struct {
	advertisedIP netip.Addr
	listenPort   uint16
	returnIP     netip.Addr
	path         config.Path
	nonce        uint64
	pathID       uint16
	egresses     *egressSet
	// ingressReflect marks a path that reflects the ingress through its members.
	// The control loop sends a REGISTER through each member and keeps the
	// healthy ones. writeMembers publishes the healthy members to the
	// dataplane, and perPacket picks the per-packet balance mode.
	ingressReflect bool
	members        []netip.Addr
	perPacket      bool
	writeMembers   func(members []netip.Addr) error
	// healthyMembers holds the members that answered in the latest cycle of
	// the path, so a control frame of the client can go through them.
	healthyMembers []netip.Addr
}

// egressFrames returns the EGRESS_REGISTER frames to send before the REGISTER
// with this sequence.
func (r pathRegistration) egressFrames(sequence uint32) [][]byte {
	return r.egresses.frames(r, sequence, time.Now())
}

// pathOpener opens the control socket of a path. A path that cannot open its
// socket fails before it goes live.
type pathOpener func(pathRegistration) (pathConn, error)

type clientDataplane interface {
	UpdatePathState(healthyMask uint8, generation uint32) error
	SetPath(slot int, path dataplane.PathSettings) error
	SetIngressReflect(slot int, members []netip.Addr, perPacket bool) error
	ClearPath(slot int) error
	SetEgressPath(slot int, path *dataplane.EgressPathSettings) error
	EgressPathsSeen() ([dataplane.MaxEgressPaths]time.Duration, error)
	SetGroup(group dataplane.GroupSettings) error
	AttachClient(ifindexes []int) error
	Snapshot() (dataplane.StatsSnapshot, error)
	ClientRoutes() ([]dataplane.ClientRoute, error)
}

type pathProbeResult struct {
	slot     int
	epoch    uint64
	sequence uint32
	sentAt   time.Time
	// repliedAt is the time of the first answer, or zero for the time of
	// the report.
	repliedAt time.Time
	result    registerResult
}

type clientPath struct {
	// path is the configured path. Its port range can have more than one
	// server port.
	path     config.Path
	group    *pathGroup
	ifindex  int
	priority uint8
	// port is the server port that the path uses now.
	port   uint16
	epoch  uint64
	cancel context.CancelFunc
	// last is the result of the latest REGISTER of the path.
	last registerResult
	// missed counts the REGISTER frames in a row without an answer.
	missed int
	// moves counts the port moves since the last answer.
	moves int
}

// runtimePath is the path on the server port that it uses now.
func (p *clientPath) runtimePath() config.Path {
	return p.path.AtPort(p.port)
}

// pathGroup is the runtime state of one configured group. A group with
// separate egress paths has egresses.
type pathGroup struct {
	settings dataplane.GroupSettings
	egresses *egressSet
}

// clientEgressPath is one egress path of a group. It is healthy while the probes
// of the servers arrive on it.
type clientEgressPath struct {
	path      config.Path
	group     *pathGroup
	lastProbe time.Time
}

// egressInUse is how long an egress path counts as in use after its latest reply.
const egressInUse = 10 * time.Second

// clientController runs the paths of a client. A slot is a path ID, a bit in
// the healthy mask, and an entry in the BPF path_config map. Paths can join
// and leave while the client runs, but the groups stay fixed.
type clientController struct {
	mu            sync.Mutex
	client        config.Client
	nonce         uint64
	groups        []*pathGroup
	initial       []dataplane.PathSettings
	dataplane     clientDataplane
	resolver      routeResolver
	controls      clientControls
	interfaceName func(int) string
	// pickPort chooses the next server port of a path in its range.
	pickPort     func(ports config.PortRange, current uint16) uint16
	logger       *log.Logger
	health       *control.HealthEngine
	slots        [config.MaxPaths]*clientPath
	egressSlots  [dataplane.MaxEgressPaths]*clientEgressPath
	stopEgress   func()
	nextPriority int
	nextEpoch    uint64
	probes       chan pathProbeResult
	failures     chan error
	ctx          context.Context
	startedAt    time.Time
	// reflectMu guards reflectHealthy. The control loop of a path writes it
	// without c.mu, so the controller takes reflectMu after c.mu and never
	// the other way.
	reflectMu      sync.Mutex
	reflectHealthy [config.MaxPaths][]netip.Addr
}

func newClientController(
	client config.Client,
	settings dataplane.ClientSettings,
	plane clientDataplane,
	resolver routeResolver,
	controls clientControls,
	startedAt time.Time,
	logger *log.Logger,
) *clientController {
	groups := make([]*pathGroup, 0, len(settings.Groups))
	for _, group := range settings.Groups {
		current := &pathGroup{settings: group}
		if group.DownMask != 0 {
			current.egresses = newEgressSet(group.EgressMode)
		}
		groups = append(groups, current)
	}
	return &clientController{
		client:        client,
		nonce:         settings.InstanceNonce,
		groups:        groups,
		initial:       settings.Paths,
		dataplane:     plane,
		resolver:      resolver,
		controls:      controls,
		interfaceName: interfaceName,
		pickPort:      randomOtherPort,
		logger:        logger,
		health:        control.NewHealthEngine(config.MaxPaths, controlReplyTimeout, missLimit),
		probes:        make(chan pathProbeResult, 2*config.MaxPaths),
		failures:      make(chan error, config.MaxPaths),
		startedAt:     startedAt,
	}
}

func (c *clientController) run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := c.start(ctx); err != nil {
		return err
	}
	defer func() {
		c.mu.Lock()
		stop := c.stopEgress
		c.mu.Unlock()
		if stop != nil {
			stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-c.failures:
			return err
		case probe := <-c.probes:
			if err := c.handleProbe(probe); err != nil {
				return err
			}
		}
	}
}

// start opens the paths from the configuration. They start healthy.
func (c *clientController) start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ctx = ctx
	egressSlot := 0
	var splitPorts []uint16
	for index, group := range c.groups {
		if group.egresses == nil {
			continue
		}
		splitPorts = append(splitPorts, group.settings.ListenPort)
		for _, path := range c.client.Groups[index].EgressPaths {
			c.egressSlots[egressSlot] = &clientEgressPath{path: path, group: group}
			group.egresses.set(uint16(egressSlot), path)
			egressSlot++
		}
	}
	if len(splitPorts) > 0 {
		stop, err := c.controls.listenEgress(egressListen{
			advertisedIP: c.client.AdvertisedIP,
			nonce:        c.nonce,
			listenPorts:  splitPorts,
		}, c.handleEgressProbe)
		if err != nil {
			return err
		}
		c.stopEgress = stop
	}
	slot := 0
	for index, group := range c.groups {
		for _, path := range c.client.Groups[index].Paths {
			settings := c.initial[slot]
			current := &clientPath{path: path, group: group, ifindex: settings.Ifindex, priority: settings.Priority, port: path.ServerPort}
			conn, err := c.controls.open(c.registrationLocked(group, current.runtimePath(), slot))
			if err != nil {
				return err
			}
			if err := c.startHealthLocked(slot, path.IngressReflect(group.egresses != nil)); err != nil {
				_ = conn.Close()
				return err
			}
			c.launchLocked(slot, current, conn)
			slot++
		}
	}
	c.nextPriority = len(c.initial)
	return c.publishHealthLocked()
}

// startHealthLocked starts to track a path of the configuration. An ingress reflect
// path starts unhealthy, because the dataplane has no member list for it until its
// first round finds a member, and the data path would send its packets unreflected.
func (c *clientController) startHealthLocked(slot int, ingressReflect bool) error {
	if ingressReflect {
		return c.health.StartUnhealthy(slot)
	}
	_, err := c.health.StartHealthy(slot)
	return err
}

// registrationLocked takes the path on the server port that it uses now.
func (c *clientController) registrationLocked(group *pathGroup, path config.Path, slot int) pathRegistration {
	registration := pathRegistration{
		advertisedIP: c.client.AdvertisedIP,
		listenPort:   group.settings.ListenPort,
		returnIP:     path.ReturnIP,
		path:         path,
		nonce:        c.nonce,
		pathID:       uint16(slot),
		egresses:     group.egresses,
	}
	if path.IngressReflect(group.egresses != nil) {
		registration.ingressReflect = true
		registration.members = candidateMembers(path)
		registration.perPacket = path.Balance == config.BalancePerPacket
		registration.writeMembers = func(members []netip.Addr) error {
			c.reflectMu.Lock()
			c.reflectHealthy[slot] = slices.Clone(members)
			c.reflectMu.Unlock()
			// An empty list never reaches the dataplane, because the data path
			// sends a packet unreflected when the list is empty, and the
			// server drops it. The dataplane keeps its last list. By then the
			// path missed its rounds and has left the path mask, or is about to.
			if len(members) == 0 {
				return nil
			}
			return c.dataplane.SetIngressReflect(slot, members, registration.perPacket)
		}
		// An older path in the slot can leave members of another pool, so
		// the registration keeps only its own candidates.
		c.reflectMu.Lock()
		for _, member := range c.reflectHealthy[slot] {
			if slices.Contains(registration.members, member) {
				registration.healthyMembers = append(registration.healthyMembers, member)
			}
		}
		c.reflectMu.Unlock()
	}
	return registration
}

// pickReflectMember returns the member that a control frame of an ingress
// reflect path goes through on this turn: the healthy members in turn, or the
// candidates in turn while no member is healthy.
func pickReflectMember(healthy, candidates []netip.Addr, turn uint) (netip.Addr, bool) {
	members := healthy
	if len(members) == 0 {
		members = candidates
	}
	if len(members) == 0 {
		return netip.Addr{}, false
	}
	return members[turn%uint(len(members))], true
}

// candidateMembers returns the via hosts of an ingress reflect path: the single
// return IP, or the first addresses of the return pool. The cap matches the
// pool size MUP_MAX_POOL in bpf/include/mup_abi.h.
func candidateMembers(path config.Path) []netip.Addr {
	if !path.ReturnIP.IsValid() {
		return nil
	}
	if !path.IsPool() {
		return []netip.Addr{path.ReturnIP}
	}
	prefix := netip.PrefixFrom(path.ReturnIP, int(path.ReturnPrefix)).Masked()
	members := make([]netip.Addr, 0, maxIngressReflectMembers)
	for address := prefix.Addr(); prefix.Contains(address) && len(members) < maxIngressReflectMembers; address = address.Next() {
		members = append(members, address)
	}
	return members
}

// maxIngressReflectMembers matches MUP_MAX_POOL in bpf/include/mup_abi.h.
const maxIngressReflectMembers = 16

func (c *clientController) launchLocked(slot int, current *clientPath, conn pathConn) {
	c.nextEpoch++
	epoch := c.nextEpoch
	pathContext, cancel := context.WithCancel(c.ctx)
	current.epoch = epoch
	current.cancel = cancel
	c.slots[slot] = current
	report := func(ctx context.Context, sequence uint32, sentAt, repliedAt time.Time, result registerResult) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case c.probes <- pathProbeResult{slot: slot, epoch: epoch, sequence: sequence, sentAt: sentAt, repliedAt: repliedAt, result: result}:
			return nil
		}
	}
	go func() {
		err := conn.Run(pathContext, report)
		if pathContext.Err() != nil {
			return
		}
		if err == nil {
			err = errors.New("control loop stopped")
		}
		select {
		case c.failures <- fmt.Errorf("client path %d: %w", slot, err):
		default:
		}
	}()
}

// handleProbe ignores results from a path that left, or from an older path
// in the same slot.
func (c *clientController) handleProbe(probe pathProbeResult) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	current := c.slots[probe.slot]
	if current == nil || current.epoch != probe.epoch {
		return nil
	}
	if err := c.health.Sent(probe.slot, probe.sequence, probe.sentAt); err != nil {
		return err
	}
	current.last = probe.result
	if probe.result == registerMissed {
		current.missed++
	} else {
		current.missed = 0
		current.moves = 0
	}
	changed := false
	// A path without a healthy reflector counts as missed, because the
	// server cannot return replies on it.
	if probe.result == registerAcked {
		// An ingress reflect path collects the answers of its members for a whole
		// reply window before it reports, so it names the time of the first
		// answer. Without it, the round-trip time would be the window.
		repliedAt := probe.repliedAt
		if repliedAt.IsZero() {
			repliedAt = time.Now()
		}
		transition, _, err := c.health.Reply(probe.slot, probe.sequence, repliedAt)
		if err != nil {
			return err
		}
		changed = transition.Changed
	} else {
		for _, transition := range c.health.ExpireProbes(probe.sentAt.Add(controlReplyTimeout)) {
			changed = changed || transition.Changed
		}
	}
	if changed {
		if err := c.publishHealthLocked(); err != nil {
			return err
		}
	}
	if current.path.HasPortRange() && current.missed >= portMoveThreshold(current.moves) {
		return c.movePortLocked(probe.slot)
	}
	return nil
}

// portMoveThreshold is the number of REGISTER frames in a row without an
// answer that moves a path. It doubles with each move without an answer.
func portMoveThreshold(moves int) int {
	return portMoveMisses << min(moves, portMoveMaxDoublings)
}

// movePortLocked moves a path that the server stopped answering to another
// server port of its range. A filter on the way can drop the packets of one
// flow and pass the others, so a new server port can get through. The new
// control loop starts before the old one stops, so that the two loops of a
// UDP path share the control socket of the group.
func (c *clientController) movePortLocked(slot int) error {
	current := c.slots[slot]
	port := c.pickPort(current.path.Ports(), current.port)
	moved := &clientPath{
		path:     current.path,
		group:    current.group,
		ifindex:  current.ifindex,
		priority: current.priority,
		port:     port,
		last:     current.last,
		moves:    current.moves + 1,
	}
	conn, err := c.controls.open(c.registrationLocked(current.group, moved.runtimePath(), slot))
	if err != nil {
		// The path stays on its port, and the next misses try again.
		c.logger.Printf("client path %d: cannot move to server port %d: %v", slot, port, err)
		current.missed = 0
		return nil
	}
	settings := clientPathSettings(moved.runtimePath(), c.client.AdvertisedIP, current.ifindex, current.priority)
	if err := c.dataplane.SetPath(slot, settings); err != nil {
		_ = conn.Close()
		return err
	}
	c.logger.Printf("client path %d: no answer to %d registrations on server port %d, so it moved to port %d",
		slot, current.missed, current.port, port)
	current.cancel()
	c.launchLocked(slot, moved, conn)
	return nil
}

// randomOtherPort chooses a port of the range other than the current port. The
// range has at least two ports.
func randomOtherPort(ports config.PortRange, current uint16) uint16 {
	port := ports.First + uint16(rand.IntN(ports.Len()-1))
	if port >= current {
		port++
	}
	return port
}

func (c *clientController) publishHealthLocked() error {
	mask, generation := c.health.Snapshot()
	return c.dataplane.UpdatePathState(mask, generation)
}

// groupLocked finds a group by listen port. A zero port selects the only group
// of a client that has one group.
func (c *clientController) groupLocked(listenPort uint16) (*pathGroup, error) {
	if listenPort == 0 {
		if len(c.groups) != 1 {
			return nil, badRequest(fmt.Errorf("the client has %d groups, so choose one with its listen port", len(c.groups)))
		}
		return c.groups[0], nil
	}
	for _, group := range c.groups {
		if group.settings.ListenPort == listenPort {
			return group, nil
		}
	}
	return nil, notFound("no group has listen port %d", listenPort)
}

// AddPath adds a path to a free slot in a group. The new path stays unhealthy
// until the server answers its first REGISTER.
func (c *clientController) AddPath(raw string, listenPort uint16) (api.Path, error) {
	return c.addPath(raw, listenPort, false)
}

// AddBridge adds an ingress path through a MUP bridge to a group with egress paths.
func (c *clientController) AddBridge(raw string, listenPort uint16) (api.Path, error) {
	return c.addPath(raw, listenPort, true)
}

func (c *clientController) addPath(raw string, listenPort uint16, bridge bool) (api.Path, error) {
	path, err := config.ParsePath(raw)
	if err != nil {
		return api.Path{}, badRequest(err)
	}
	path.Bridge = bridge
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx == nil {
		return api.Path{}, unavailable("the client is still starting")
	}
	group, err := c.groupLocked(listenPort)
	if err != nil {
		return api.Path{}, err
	}
	if bridge && path.ReturnIP.IsValid() {
		return api.Path{}, badRequest(errors.New("an ingress bridge has no via, because it passes the client packets on to the server"))
	}
	if bridge && group.egresses == nil {
		return api.Path{}, conflict("the group of listen port %d has no egress paths, and a bridge needs a group with ingress and egress", group.settings.ListenPort)
	}
	slot := -1
	for index, current := range c.slots {
		if current == nil {
			if slot < 0 {
				slot = index
			}
			continue
		}
		if current.path.SameRoute(path) {
			return api.Path{}, conflict("path %s shares a server port with path %d", path, index)
		}
		if current.group != group && current.path.SharesServerPort(path) {
			return api.Path{}, conflict("server %s:%s is in the group of listen port %d, and a server port can serve one group", path.Server, path.Ports(), current.group.settings.ListenPort)
		}
	}
	if slot < 0 {
		return api.Path{}, conflict("the client already has %d paths", config.MaxPaths)
	}
	if c.nextPriority > math.MaxUint8 {
		return api.Path{}, conflict("no path priority is left, restart the daemon")
	}
	_, ifindex, err := c.resolver.Resolve(path.Server, path.Interface)
	if err != nil {
		return api.Path{}, badRequest(fmt.Errorf("resolve path: %w", err))
	}
	if ifindex <= 0 {
		return api.Path{}, badRequest(fmt.Errorf("resolve path: invalid interface index %d", ifindex))
	}
	conn, err := c.controls.open(c.registrationLocked(group, path.AtPort(path.ServerPort), slot))
	if err != nil {
		return api.Path{}, err
	}
	if err := c.dataplane.AttachClient([]int{ifindex}); err != nil {
		_ = conn.Close()
		return api.Path{}, err
	}
	priority := uint8(c.nextPriority)
	settings := clientPathSettings(path.AtPort(path.ServerPort), c.client.AdvertisedIP, ifindex, priority)
	if err := c.dataplane.SetPath(slot, settings); err != nil {
		_ = conn.Close()
		return api.Path{}, err
	}
	if err := c.setPathMaskLocked(group, group.settings.PathMask|1<<slot); err != nil {
		_ = conn.Close()
		_ = c.dataplane.ClearPath(slot)
		return api.Path{}, err
	}
	if err := c.health.StartUnhealthy(slot); err != nil {
		_ = conn.Close()
		_ = c.setPathMaskLocked(group, group.settings.PathMask&^(1<<slot))
		_ = c.dataplane.ClearPath(slot)
		return api.Path{}, err
	}
	c.nextPriority++
	c.launchLocked(slot, &clientPath{path: path, group: group, ifindex: ifindex, priority: priority, port: path.ServerPort}, conn)
	return c.pathLocked(slot, c.inUseSlotsLocked()), nil
}

// AddEgressPath adds an egress path to a group with separate egress paths. The ingress
// paths send it to the servers with their next REGISTER, and it stays
// unhealthy until the first probe arrives on it.
func (c *clientController) AddEgressPath(raw string, listenPort uint16) (api.Path, error) {
	return c.addEgressPath(raw, listenPort, false)
}

// AddEgressBridge adds an egress path through a MUP bridge.
func (c *clientController) AddEgressBridge(raw string, listenPort uint16) (api.Path, error) {
	return c.addEgressPath(raw, listenPort, true)
}

func (c *clientController) addEgressPath(raw string, listenPort uint16, bridge bool) (api.Path, error) {
	path, err := config.ParsePath(raw)
	if err != nil {
		return api.Path{}, badRequest(err)
	}
	path.Bridge = bridge
	if err := path.ValidateEgress(); err != nil {
		return api.Path{}, badRequest(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx == nil {
		return api.Path{}, unavailable("the client is still starting")
	}
	group, err := c.groupLocked(listenPort)
	if err != nil {
		return api.Path{}, err
	}
	if group.egresses == nil {
		return api.Path{}, conflict("the group of listen port %d has no egress paths, because its paths carry both directions", group.settings.ListenPort)
	}
	slot := -1
	for index, current := range c.egressSlots {
		if current == nil {
			if slot < 0 {
				slot = index
			}
			continue
		}
		if current.path.SameEgressPath(path) {
			return api.Path{}, conflict("egress path %s is already egress path %d", path, index)
		}
	}
	if slot < 0 {
		return api.Path{}, conflict("the client already has %d egress paths", dataplane.MaxEgressPaths)
	}
	settings := dataplane.EgressPathFromConfig(path)
	if err := c.dataplane.SetEgressPath(slot, &settings); err != nil {
		return api.Path{}, err
	}
	if err := c.setEgressMaskLocked(group, group.settings.DownMask|1<<slot); err != nil {
		_ = c.dataplane.SetEgressPath(slot, nil)
		return api.Path{}, err
	}
	c.egressSlots[slot] = &clientEgressPath{path: path, group: group}
	group.egresses.set(uint16(slot), path)
	seen, _ := c.dataplane.EgressPathsSeen()
	return c.egressPathLocked(slot, seen, time.Now()), nil
}

// RemoveEgressPath removes an egress path. The ingress paths tell the servers with a
// lease of zero, so they stop to use it with the next REGISTER.
func (c *clientController) RemoveEgressPath(id int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id < 0 || id >= dataplane.MaxEgressPaths || c.egressSlots[id] == nil {
		return notFound("egress path %d does not exist", id)
	}
	group := c.egressSlots[id].group
	if bits.OnesCount8(group.settings.DownMask) == 1 {
		return conflict("egress path %d is the last egress path of the group of listen port %d, add another egress path first", id, group.settings.ListenPort)
	}
	if err := c.setEgressMaskLocked(group, group.settings.DownMask&^(1<<id)); err != nil {
		return err
	}
	if err := c.dataplane.SetEgressPath(id, nil); err != nil {
		return err
	}
	group.egresses.remove(uint16(id), time.Now())
	c.egressSlots[id] = nil
	return nil
}

// SetEgressMode changes the egress mode of a group with separate egress
// paths. The servers take it with the next REGISTER of an ingress path.
func (c *clientController) SetEgressMode(raw string, listenPort uint16) error {
	mode, err := config.ParseMode(raw)
	if err != nil {
		return badRequest(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	group, err := c.groupLocked(listenPort)
	if err != nil {
		return err
	}
	if group.egresses == nil {
		return conflict("the group of listen port %d has no egress paths, because its paths carry both directions", group.settings.ListenPort)
	}
	updated := group.settings
	updated.EgressMode = mode
	if err := c.dataplane.SetGroup(updated); err != nil {
		return err
	}
	group.settings = updated
	group.egresses.setMode(mode)
	return nil
}

func (c *clientController) setEgressMaskLocked(group *pathGroup, mask uint8) error {
	updated := group.settings
	updated.DownMask = mask
	if err := c.dataplane.SetGroup(updated); err != nil {
		return err
	}
	group.settings = updated
	return nil
}

// handleEgressProbe answers the probe of an egress path on an ingress path of its
// group: the healthy ingress path with the lowest priority, or every ingress path when
// none is healthy, so that a probe can bring the group back.
func (c *clientController) handleEgressProbe(probe egressProbe) {
	frame := probe.frame
	c.mu.Lock()
	if frame.AdvertisedIP != c.client.AdvertisedIP || frame.InstanceNonce != c.nonce ||
		int(frame.PathID) >= len(c.egressSlots) {
		c.mu.Unlock()
		return
	}
	egress := c.egressSlots[frame.PathID]
	if egress == nil || !egressSourceMatches(egress.path, probe.source, probe.transport, probe.port) {
		c.mu.Unlock()
		return
	}
	egress.lastProbe = probe.received
	path := egress.path
	targets := c.ingressTargetsLocked(egress.group)
	c.mu.Unlock()
	for _, registration := range targets {
		reply, err := egressProbeReplyFrame(registration, probe, path)
		if err != nil {
			return
		}
		_ = c.controls.sendIngress(registration, reply)
	}
}

func (c *clientController) ingressTargetsLocked(group *pathGroup) []pathRegistration {
	var all []pathRegistration
	var best pathRegistration
	selected := -1
	for slot, current := range c.slots {
		if current == nil || current.group != group {
			continue
		}
		registration := c.registrationLocked(group, current.runtimePath(), slot)
		all = append(all, registration)
		health, _ := c.health.Path(slot)
		if health.Healthy && (selected < 0 || current.priority < c.slots[selected].priority) {
			selected = slot
			best = registration
		}
	}
	if selected >= 0 {
		return []pathRegistration{best}
	}
	return all
}

func (c *clientController) setPathMaskLocked(group *pathGroup, mask uint8) error {
	updated := group.settings
	updated.PathMask = mask
	if err := c.dataplane.SetGroup(updated); err != nil {
		return err
	}
	group.settings = updated
	return nil
}

// RemovePath clears the healthy bit of a path before its configuration, so
// that the client program never picks a half-removed path.
func (c *clientController) RemovePath(id int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id < 0 || id >= config.MaxPaths || c.slots[id] == nil {
		return notFound("path %d does not exist", id)
	}
	group := c.slots[id].group
	if bits.OnesCount8(group.settings.PathMask) == 1 {
		return conflict("path %d is the last path of the group of listen port %d, add another path first", id, group.settings.ListenPort)
	}
	c.slots[id].cancel()
	c.slots[id] = nil
	if _, err := c.health.Forget(id); err != nil {
		return err
	}
	if err := c.publishHealthLocked(); err != nil {
		return err
	}
	if err := c.setPathMaskLocked(group, group.settings.PathMask&^(1<<id)); err != nil {
		return err
	}
	return c.dataplane.ClearPath(id)
}

func (c *clientController) SetMode(raw string, listenPort uint16) error {
	mode, err := config.ParseMode(raw)
	if err != nil {
		return badRequest(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	group, err := c.groupLocked(listenPort)
	if err != nil {
		return err
	}
	updated := group.settings
	updated.Mode = mode
	if err := c.dataplane.SetGroup(updated); err != nil {
		return err
	}
	group.settings = updated
	return nil
}

func (c *clientController) Status() (api.Status, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	snapshot, err := c.dataplane.Snapshot()
	if err != nil {
		return api.Status{}, err
	}
	routes, err := c.dataplane.ClientRoutes()
	if err != nil {
		return api.Status{}, err
	}
	paths := c.pathsLocked()
	status := &api.ClientStatus{
		AdvertisedIP:      c.client.AdvertisedIP.String(),
		Generation:        snapshot.PathGeneration,
		Groups:            c.groupsLocked(paths, routes),
		Paths:             paths,
		Peers:             snapshot.ClientRoutes,
		TokensFree:        snapshot.PeerTokensAvailable,
		TokensQuarantined: snapshot.PeerQuarantined,
		TokensQuota:       uint64(protocol.MaxPeerToken),
	}
	return api.Status{Role: api.RoleClient, StartedAt: c.startedAt, Client: status, Drops: apiDrops(snapshot)}, nil
}

func (c *clientController) groupsLocked(paths []api.Path, routes []dataplane.ClientRoute) []api.Group {
	groups := make([]api.Group, 0, len(c.groups))
	for _, group := range c.groups {
		converted := api.Group{ListenPort: group.settings.ListenPort, Mode: group.settings.Mode.String()}
		if group.egresses != nil {
			converted.EgressMode = group.settings.EgressMode.String()
		}
		for _, path := range paths {
			if path.ListenPort != converted.ListenPort {
				continue
			}
			if path.Direction == directionEgress {
				converted.EgressPaths++
				if path.Healthy {
					converted.HealthyEgressPaths++
				}
				continue
			}
			converted.Paths++
			if path.Healthy {
				converted.HealthyPaths++
			}
		}
		for _, route := range routes {
			if route.Local.Port() == converted.ListenPort {
				converted.Peers++
			}
		}
		groups = append(groups, converted)
	}
	return groups
}

func (c *clientController) Paths() ([]api.Path, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pathsLocked(), nil
}

func (c *clientController) Peers() (api.PeerList, error) {
	routes, err := c.dataplane.ClientRoutes()
	if err != nil {
		return api.PeerList{}, err
	}
	peers := make([]api.Peer, 0, len(routes))
	for _, route := range routes {
		peers = append(peers, api.Peer{
			Token:       route.Token,
			Address:     route.Peer.String(),
			Local:       route.Local.String(),
			Interface:   c.interfaceName(route.Ifindex),
			IdleSeconds: route.Idle.Seconds(),
		})
	}
	return api.PeerList{Peers: peers}, nil
}

const (
	directionIngress = "ingress"
	directionEgress  = "egress"
)

func (c *clientController) pathsLocked() []api.Path {
	inUse := c.inUseSlotsLocked()
	paths := make([]api.Path, 0, config.MaxPaths)
	for slot, current := range c.slots {
		if current != nil {
			paths = append(paths, c.pathLocked(slot, inUse))
		}
	}
	seen, err := c.dataplane.EgressPathsSeen()
	if err != nil {
		for slot := range seen {
			seen[slot] = -1
		}
	}
	now := time.Now()
	for slot, egress := range c.egressSlots {
		if egress != nil {
			paths = append(paths, c.egressPathLocked(slot, seen, now))
		}
	}
	return paths
}

// egressPathLocked describes an egress path. It is healthy while the probes of
// the servers arrive, and in use while the program accepts replies on it.
func (c *clientController) egressPathLocked(slot int, seen [dataplane.MaxEgressPaths]time.Duration, now time.Time) api.Path {
	egress := c.egressSlots[slot]
	var returnIP string
	switch {
	case egress.path.IsPool():
		returnIP = netip.PrefixFrom(egress.path.ReturnIP, int(egress.path.ReturnPrefix)).String()
	case egress.path.ReturnIP.IsValid():
		returnIP = egress.path.ReturnIP.String()
	}
	return api.Path{
		ID:         slot,
		Direction:  directionEgress,
		Bridge:     egress.path.Bridge,
		ListenPort: egress.group.settings.ListenPort,
		Server:     egress.path.Server.String(),
		Port:       egress.path.ServerPort,
		Transport:  egress.path.Transport.String(),
		ReturnIP:   returnIP,
		Healthy:    !egress.lastProbe.IsZero() && now.Sub(egress.lastProbe) < egressHealthWindow,
		InUse:      seen[slot] >= 0 && seen[slot] < egressInUse,
		LastProbe:  egress.lastProbe,
	}
}

func (c *clientController) pathLocked(slot int, inUse [config.MaxPaths]bool) api.Path {
	current := c.slots[slot]
	health, _ := c.health.Path(slot)
	name := current.path.Interface
	if name == "" {
		name = c.interfaceName(current.ifindex)
	}
	var reason string
	if !health.Healthy && current.last == registerNoReflector {
		reason = "no reflector"
	}
	var returnIP string
	switch {
	case current.path.IsPool():
		returnIP = netip.PrefixFrom(current.path.ReturnIP, int(current.path.ReturnPrefix)).String()
	case current.path.ReturnIP.IsValid():
		returnIP = current.path.ReturnIP.String()
	}
	var firstPort, lastPort uint16
	if current.path.HasPortRange() {
		firstPort, lastPort = current.path.ServerPort, current.path.LastPort
	}
	var direction string
	if current.group.egresses != nil {
		direction = directionIngress
	}
	return api.Path{
		ID:         slot,
		Direction:  direction,
		Bridge:     current.path.Bridge,
		ListenPort: current.group.settings.ListenPort,
		Server:     current.path.Server.String(),
		Port:       current.port,
		FirstPort:  firstPort,
		LastPort:   lastPort,
		Transport:  current.path.Transport.String(),
		ReturnIP:   returnIP,
		Interface:  name,
		Priority:   current.priority,
		Healthy:    health.Healthy,
		Reason:     reason,
		InUse:      inUse[slot],
		Misses:     health.Misses,
		LastACK:    health.LastReply,
		RTTSeconds: health.RTT.Seconds(),
	}
}

// inUseSlotsLocked mirrors the path choice of the client program in each group.
// Failover uses the healthy path with the lowest priority. The other modes use
// every healthy path.
func (c *clientController) inUseSlotsLocked() [config.MaxPaths]bool {
	var inUse [config.MaxPaths]bool
	for _, group := range c.groups {
		selected := -1
		for slot, current := range c.slots {
			if current == nil || current.group != group {
				continue
			}
			health, _ := c.health.Path(slot)
			if !health.Healthy {
				continue
			}
			if group.settings.Mode != config.ModeFailover {
				inUse[slot] = true
				continue
			}
			if selected < 0 || current.priority < c.slots[selected].priority {
				selected = slot
			}
		}
		if selected >= 0 {
			inUse[selected] = true
		}
	}
	return inUse
}

func registrationDelay(success bool) time.Duration {
	if success {
		return registrationRefresh
	}
	return registrationRetry
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func interfaceName(ifindex int) string {
	if ifindex <= 0 {
		return ""
	}
	networkInterface, err := net.InterfaceByIndex(ifindex)
	if err != nil {
		return strconv.Itoa(ifindex)
	}
	return networkInterface.Name
}
