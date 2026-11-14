package app

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/xshecan/mup/api"
	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/control"
	"github.com/xshecan/mup/dataplane"
)

const (
	controlReplyTimeout = 900 * time.Millisecond
	missLimit           = 3
	registrationRefresh = 10 * time.Second
	registrationRetry   = time.Second
)

// probeReporter passes the result of one REGISTER to the controller.
type probeReporter func(ctx context.Context, sequence uint32, sentAt time.Time, success bool) error

// pathConn owns the control socket of one path.
type pathConn interface {
	// Run sends REGISTER frames until ctx ends, and then closes the socket.
	Run(ctx context.Context, report probeReporter) error
	Close() error
}

// pathRegistration holds the values that a path sends in its REGISTER frames.
type pathRegistration struct {
	advertisedIP netip.Addr
	listenPort   uint16
	returnIP     netip.Addr
	path         config.Path
	nonce        uint64
	pathID       uint16
}

// pathOpener opens the control socket of a path. A path that cannot open its
// socket fails before it goes live.
type pathOpener func(pathRegistration) (pathConn, error)

type clientDataplane interface {
	UpdatePathState(healthyMask uint8, generation uint32) error
	SetPath(slot int, path dataplane.PathSettings) error
	ClearPath(slot int) error
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
	success  bool
}

type clientPath struct {
	path     config.Path
	group    *pathGroup
	ifindex  int
	priority uint8
	epoch    uint64
	cancel   context.CancelFunc
}

// pathGroup is the runtime state of one configured group.
type pathGroup struct {
	settings dataplane.GroupSettings
}

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
	open          pathOpener
	interfaceName func(int) string
	health        *control.HealthEngine
	slots         [config.MaxPaths]*clientPath
	nextPriority  int
	nextEpoch     uint64
	probes        chan pathProbeResult
	failures      chan error
	ctx           context.Context
	startedAt     time.Time
}

func newClientController(
	client config.Client,
	settings dataplane.ClientSettings,
	plane clientDataplane,
	resolver routeResolver,
	open pathOpener,
	startedAt time.Time,
) *clientController {
	groups := make([]*pathGroup, 0, len(settings.Groups))
	for _, group := range settings.Groups {
		groups = append(groups, &pathGroup{settings: group})
	}
	return &clientController{
		client:        client,
		nonce:         settings.InstanceNonce,
		groups:        groups,
		initial:       settings.Paths,
		dataplane:     plane,
		resolver:      resolver,
		open:          open,
		interfaceName: interfaceName,
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
	slot := 0
	for index, group := range c.groups {
		for _, path := range c.client.Groups[index].Paths {
			conn, err := c.open(c.registrationLocked(group, path, slot))
			if err != nil {
				return err
			}
			if _, err := c.health.StartHealthy(slot); err != nil {
				_ = conn.Close()
				return err
			}
			settings := c.initial[slot]
			c.launchLocked(slot, path, group, settings.Ifindex, settings.Priority, conn)
			slot++
		}
	}
	c.nextPriority = len(c.initial)
	return c.publishHealthLocked()
}

func (c *clientController) registrationLocked(group *pathGroup, path config.Path, slot int) pathRegistration {
	return pathRegistration{
		advertisedIP: c.client.AdvertisedIP,
		listenPort:   group.settings.ListenPort,
		returnIP:     path.ReturnIP,
		path:         path,
		nonce:        c.nonce,
		pathID:       uint16(slot),
	}
}

func (c *clientController) launchLocked(slot int, path config.Path, group *pathGroup, ifindex int, priority uint8, conn pathConn) {
	c.nextEpoch++
	epoch := c.nextEpoch
	pathContext, cancel := context.WithCancel(c.ctx)
	c.slots[slot] = &clientPath{path: path, group: group, ifindex: ifindex, priority: priority, epoch: epoch, cancel: cancel}
	report := func(ctx context.Context, sequence uint32, sentAt time.Time, success bool) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case c.probes <- pathProbeResult{slot: slot, epoch: epoch, sequence: sequence, sentAt: sentAt, success: success}:
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
	changed := false
	if probe.success {
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
		return c.publishHealthLocked()
	}
	return nil
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
	path, err := config.ParsePath(raw)
	if err != nil {
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
	slot := -1
	for index, current := range c.slots {
		if current == nil {
			if slot < 0 {
				slot = index
			}
			continue
		}
		if current.path.Route() == path.Route() {
			return api.Path{}, conflict("path %s already exists as path %d", path, index)
		}
		if current.group != group && current.path.Endpoint() == path.Endpoint() {
			return api.Path{}, conflict("server %s is in the group of listen port %d, and a server can serve one group", path.Endpoint(), current.group.settings.ListenPort)
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
	conn, err := c.open(c.registrationLocked(group, path, slot))
	if err != nil {
		return api.Path{}, err
	}
	if err := c.dataplane.AttachClient([]int{ifindex}); err != nil {
		_ = conn.Close()
		return api.Path{}, err
	}
	priority := uint8(c.nextPriority)
	settings := dataplane.PathSettings{
		DestinationIP: path.Server,
		SourceIP:      c.client.AdvertisedIP,
		Ifindex:       ifindex,
		ServerPort:    path.ServerPort,
		Transport:     path.Transport,
		Priority:      priority,
		ReturnIP:      path.ReturnIP,
	}
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
	c.launchLocked(slot, path, group, ifindex, priority, conn)
	return c.pathLocked(slot, c.inUseSlotsLocked()), nil
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
	}
	return api.Status{Role: api.RoleClient, StartedAt: c.startedAt, Client: status, Drops: apiDrops(snapshot)}, nil
}

func (c *clientController) groupsLocked(paths []api.Path, routes []dataplane.ClientRoute) []api.Group {
	groups := make([]api.Group, 0, len(c.groups))
	for _, group := range c.groups {
		converted := api.Group{ListenPort: group.settings.ListenPort, Mode: group.settings.Mode.String()}
		for _, path := range paths {
			if path.ListenPort != converted.ListenPort {
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

func (c *clientController) pathsLocked() []api.Path {
	inUse := c.inUseSlotsLocked()
	paths := make([]api.Path, 0, config.MaxPaths)
	for slot, current := range c.slots {
		if current != nil {
			paths = append(paths, c.pathLocked(slot, inUse))
		}
	}
	return paths
}

func (c *clientController) pathLocked(slot int, inUse [config.MaxPaths]bool) api.Path {
	current := c.slots[slot]
	health, _ := c.health.Path(slot)
	name := current.path.Interface
	if name == "" {
		name = c.interfaceName(current.ifindex)
	}
	var returnIP string
	if current.path.ReturnIP.IsValid() {
		returnIP = current.path.ReturnIP.String()
	}
	return api.Path{
		ID:         slot,
		ListenPort: current.group.settings.ListenPort,
		Server:     current.path.Server.String(),
		Port:       current.path.ServerPort,
		Transport:  current.path.Transport.String(),
		ReturnIP:   returnIP,
		Interface:  name,
		Priority:   current.priority,
		Healthy:    health.Healthy,
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
