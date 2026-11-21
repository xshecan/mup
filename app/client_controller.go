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

// probeReporter passes the result of one REGISTER to the controller.
type probeReporter func(ctx context.Context, sequence uint32, sentAt time.Time, result registerResult) error

// pathConn owns the control socket of one path.
type pathConn interface {
	// Run sends REGISTER frames until ctx ends, and then closes the socket.
	Run(ctx context.Context, report probeReporter) error
	Close() error
}

// pathRegistration holds the values that a path sends in its REGISTER frames.
// An up path of a group with separate down paths has downs, and it sends the
// DOWN_REGISTER frames of the group before each REGISTER. Its ACK can then
// arrive on any down path.
type pathRegistration struct {
	advertisedIP netip.Addr
	listenPort   uint16
	returnIP     netip.Addr
	path         config.Path
	nonce        uint64
	pathID       uint16
	downs        *downSet
}

// downFrames returns the DOWN_REGISTER frames to send before the REGISTER
// with this sequence.
func (r pathRegistration) downFrames(sequence uint32) [][]byte {
	return r.downs.frames(r, sequence, time.Now())
}

// pathOpener opens the control socket of a path. A path that cannot open its
// socket fails before it goes live.
type pathOpener func(pathRegistration) (pathConn, error)

type clientDataplane interface {
	UpdatePathState(healthyMask uint8, generation uint32) error
	SetPath(slot int, path dataplane.PathSettings) error
	ClearPath(slot int) error
	SetDownPath(slot int, path *dataplane.DownPathSettings) error
	DownPathsSeen() ([dataplane.MaxDownPaths]time.Duration, error)
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
	result   registerResult
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
// separate down paths has downs.
type pathGroup struct {
	settings dataplane.GroupSettings
	downs    *downSet
}

// clientDownPath is one down path of a group. It is healthy while the probes
// of the servers arrive on it.
type clientDownPath struct {
	path      config.Path
	group     *pathGroup
	lastProbe time.Time
}

// downInUse is how long a down path counts as in use after its latest reply.
const downInUse = 10 * time.Second

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
	downSlots    [dataplane.MaxDownPaths]*clientDownPath
	stopDown     func()
	nextPriority int
	nextEpoch    uint64
	probes       chan pathProbeResult
	failures     chan error
	ctx          context.Context
	startedAt    time.Time
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
			current.downs = newDownSet(group.DownMode)
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
		stop := c.stopDown
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
	downSlot := 0
	var splitPorts []uint16
	for index, group := range c.groups {
		if group.downs == nil {
			continue
		}
		splitPorts = append(splitPorts, group.settings.ListenPort)
		for _, path := range c.client.Groups[index].DownPaths {
			c.downSlots[downSlot] = &clientDownPath{path: path, group: group}
			group.downs.set(uint16(downSlot), path)
			downSlot++
		}
	}
	if len(splitPorts) > 0 {
		stop, err := c.controls.listenDown(downListen{
			advertisedIP: c.client.AdvertisedIP,
			nonce:        c.nonce,
			listenPorts:  splitPorts,
		}, c.handleDownProbe)
		if err != nil {
			return err
		}
		c.stopDown = stop
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
			if _, err := c.health.StartHealthy(slot); err != nil {
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

// registrationLocked takes the path on the server port that it uses now.
func (c *clientController) registrationLocked(group *pathGroup, path config.Path, slot int) pathRegistration {
	return pathRegistration{
		advertisedIP: c.client.AdvertisedIP,
		listenPort:   group.settings.ListenPort,
		returnIP:     path.ReturnIP,
		path:         path,
		nonce:        c.nonce,
		pathID:       uint16(slot),
		downs:        group.downs,
	}
}

func (c *clientController) launchLocked(slot int, current *clientPath, conn pathConn) {
	c.nextEpoch++
	epoch := c.nextEpoch
	pathContext, cancel := context.WithCancel(c.ctx)
	current.epoch = epoch
	current.cancel = cancel
	c.slots[slot] = current
	report := func(ctx context.Context, sequence uint32, sentAt time.Time, result registerResult) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case c.probes <- pathProbeResult{slot: slot, epoch: epoch, sequence: sequence, sentAt: sentAt, result: result}:
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
		transition, _, err := c.health.Reply(probe.slot, probe.sequence, time.Now())
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

// AddBridge adds an up path through a MUP bridge to a group with down paths.
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
	if group.downs != nil && path.ReturnIP.IsValid() {
		return api.Path{}, badRequest(errors.New("an up path of a group with down paths has no via, because the down paths carry the replies"))
	}
	if bridge && group.downs == nil {
		return api.Path{}, conflict("the group of listen port %d has no down paths, and a bridge needs a group with upstream and downstream", group.settings.ListenPort)
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

// AddDownPath adds a down path to a group with separate down paths. The up
// paths send it to the servers with their next REGISTER, and it stays
// unhealthy until the first probe arrives on it.
func (c *clientController) AddDownPath(raw string, listenPort uint16) (api.Path, error) {
	return c.addDownPath(raw, listenPort, false)
}

// AddDownBridge adds a down path through a MUP bridge.
func (c *clientController) AddDownBridge(raw string, listenPort uint16) (api.Path, error) {
	return c.addDownPath(raw, listenPort, true)
}

func (c *clientController) addDownPath(raw string, listenPort uint16, bridge bool) (api.Path, error) {
	path, err := config.ParsePath(raw)
	if err != nil {
		return api.Path{}, badRequest(err)
	}
	path.Bridge = bridge
	if err := path.ValidateDown(); err != nil {
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
	if group.downs == nil {
		return api.Path{}, conflict("the group of listen port %d has no down paths, because its paths carry both directions", group.settings.ListenPort)
	}
	slot := -1
	for index, current := range c.downSlots {
		if current == nil {
			if slot < 0 {
				slot = index
			}
			continue
		}
		if current.path.SameDownPath(path) {
			return api.Path{}, conflict("down path %s is already down path %d", path, index)
		}
	}
	if slot < 0 {
		return api.Path{}, conflict("the client already has %d down paths", dataplane.MaxDownPaths)
	}
	settings := dataplane.DownPathFromConfig(path)
	if err := c.dataplane.SetDownPath(slot, &settings); err != nil {
		return api.Path{}, err
	}
	if err := c.setDownMaskLocked(group, group.settings.DownMask|1<<slot); err != nil {
		_ = c.dataplane.SetDownPath(slot, nil)
		return api.Path{}, err
	}
	c.downSlots[slot] = &clientDownPath{path: path, group: group}
	group.downs.set(uint16(slot), path)
	seen, _ := c.dataplane.DownPathsSeen()
	return c.downPathLocked(slot, seen, time.Now()), nil
}

// RemoveDownPath removes a down path. The up paths tell the servers with a
// lease of zero, so they stop to use it with the next REGISTER.
func (c *clientController) RemoveDownPath(id int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id < 0 || id >= dataplane.MaxDownPaths || c.downSlots[id] == nil {
		return notFound("down path %d does not exist", id)
	}
	group := c.downSlots[id].group
	if bits.OnesCount8(group.settings.DownMask) == 1 {
		return conflict("down path %d is the last down path of the group of listen port %d, add another down path first", id, group.settings.ListenPort)
	}
	if err := c.setDownMaskLocked(group, group.settings.DownMask&^(1<<id)); err != nil {
		return err
	}
	if err := c.dataplane.SetDownPath(id, nil); err != nil {
		return err
	}
	group.downs.remove(uint16(id), time.Now())
	c.downSlots[id] = nil
	return nil
}

// SetDownMode changes the downstream mode of a group with separate down
// paths. The servers take it with the next REGISTER of an up path.
func (c *clientController) SetDownMode(raw string, listenPort uint16) error {
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
	if group.downs == nil {
		return conflict("the group of listen port %d has no down paths, because its paths carry both directions", group.settings.ListenPort)
	}
	updated := group.settings
	updated.DownMode = mode
	if err := c.dataplane.SetGroup(updated); err != nil {
		return err
	}
	group.settings = updated
	group.downs.setMode(mode)
	return nil
}

func (c *clientController) setDownMaskLocked(group *pathGroup, mask uint8) error {
	updated := group.settings
	updated.DownMask = mask
	if err := c.dataplane.SetGroup(updated); err != nil {
		return err
	}
	group.settings = updated
	return nil
}

// handleDownProbe answers the probe of a down path on an up path of its
// group: the healthy up path with the lowest priority, or every up path when
// none is healthy, so that a probe can bring the group back.
func (c *clientController) handleDownProbe(probe downProbe) {
	frame := probe.frame
	c.mu.Lock()
	if frame.AdvertisedIP != c.client.AdvertisedIP || frame.InstanceNonce != c.nonce ||
		int(frame.PathID) >= len(c.downSlots) {
		c.mu.Unlock()
		return
	}
	down := c.downSlots[frame.PathID]
	if down == nil || !downSourceMatches(down.path, probe.source, probe.transport, probe.port) {
		c.mu.Unlock()
		return
	}
	down.lastProbe = probe.received
	path := down.path
	targets := c.upTargetsLocked(down.group)
	c.mu.Unlock()
	for _, registration := range targets {
		reply, err := downProbeReplyFrame(registration, probe, path)
		if err != nil {
			return
		}
		_ = c.controls.sendUp(registration, reply)
	}
}

func (c *clientController) upTargetsLocked(group *pathGroup) []pathRegistration {
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
		if group.downs != nil {
			converted.DownMode = group.settings.DownMode.String()
		}
		for _, path := range paths {
			if path.ListenPort != converted.ListenPort {
				continue
			}
			if path.Direction == directionDown {
				converted.DownPaths++
				if path.Healthy {
					converted.HealthyDownPaths++
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
	directionUp   = "up"
	directionDown = "down"
)

func (c *clientController) pathsLocked() []api.Path {
	inUse := c.inUseSlotsLocked()
	paths := make([]api.Path, 0, config.MaxPaths)
	for slot, current := range c.slots {
		if current != nil {
			paths = append(paths, c.pathLocked(slot, inUse))
		}
	}
	seen, err := c.dataplane.DownPathsSeen()
	if err != nil {
		for slot := range seen {
			seen[slot] = -1
		}
	}
	now := time.Now()
	for slot, down := range c.downSlots {
		if down != nil {
			paths = append(paths, c.downPathLocked(slot, seen, now))
		}
	}
	return paths
}

// downPathLocked describes a down path. It is healthy while the probes of
// the servers arrive, and in use while the program accepts replies on it.
func (c *clientController) downPathLocked(slot int, seen [dataplane.MaxDownPaths]time.Duration, now time.Time) api.Path {
	down := c.downSlots[slot]
	var returnIP string
	switch {
	case down.path.IsPool():
		returnIP = netip.PrefixFrom(down.path.ReturnIP, int(down.path.ReturnPrefix)).String()
	case down.path.ReturnIP.IsValid():
		returnIP = down.path.ReturnIP.String()
	}
	return api.Path{
		ID:         slot,
		Direction:  directionDown,
		Bridge:     down.path.Bridge,
		ListenPort: down.group.settings.ListenPort,
		Server:     down.path.Server.String(),
		Port:       down.path.ServerPort,
		Transport:  down.path.Transport.String(),
		ReturnIP:   returnIP,
		Healthy:    !down.lastProbe.IsZero() && now.Sub(down.lastProbe) < downHealthWindow,
		InUse:      seen[slot] >= 0 && seen[slot] < downInUse,
		LastProbe:  down.lastProbe,
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
	if current.group.downs != nil {
		direction = directionUp
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
// Fallback uses the healthy path with the lowest priority. The other modes use
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
			if group.settings.Mode != config.ModeFallback {
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
