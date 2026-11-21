package app

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/xshecan/mup/api"
	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/protocol"
)

const (
	// downProbeInterval is the time between two probes of each down path.
	downProbeInterval = 2 * time.Second
	// downHealthWindow is how long a down path, or a pool member of it, stays
	// healthy after its latest probe reply. A new down path is healthy for its
	// first window, before the first probe replies arrive.
	downHealthWindow = 6 * time.Second
)

// downPlane is the part of the dataplane that the down registry writes.
type downPlane interface {
	SetServerDownPath(dataplane.DownPathEntry) error
	DeleteServerDownPath(dataplane.ClientKey, uint16) error
	SetServerDownGroup(dataplane.DownGroupEntry) error
	DeleteServerDownGroup(dataplane.ClientKey) error
	ObservePool(base netip.Addr, prefix uint8, transport protocol.TransportID) error
	PoolMembers(dataplane.PoolKey) []netip.Addr
}

// downLocator finds the interface that sends from a server address to a
// destination. It fails when the address is not an address of this host.
type downLocator func(server, destination netip.Addr) (ifindex int, err error)

// bridgeRouter finds the route to a bridge: the source address and the
// interface of the wrapped replies.
type bridgeRouter func(bridge netip.Addr) (source netip.Addr, ifindex int, err error)

func routeToBridge(bridge netip.Addr) (netip.Addr, int, error) {
	return systemResolver{}.Resolve(bridge, "")
}

type downKey struct {
	client dataplane.ClientKey
	id     uint16
}

// serverDownPath is one down path of one client on this server. A path with
// bridge goes through a MUP bridge: server is the bridge address, and the
// wrapped replies leave from localIP.
type serverDownPath struct {
	key        downKey
	listenPort uint16
	bridge     bool
	localIP    netip.Addr
	server     netip.Addr
	port       uint16
	transport  protocol.TransportID
	returnIP   netip.Addr
	prefix     uint8
	perPacket  bool
	ifindex    int
	since      time.Time
	expires    time.Time
	// replies holds the time of the latest probe reply through each member,
	// or through the server address of a direct path.
	replies map[netip.Addr]time.Time
	written *dataplane.DownPathEntry
	cursor  int
}

func (p *serverDownPath) pool() bool {
	return p.prefix != 0
}

// sameAs reports whether a DOWN_REGISTER describes the path as it is.
func (p *serverDownPath) sameAs(frame protocol.ControlFrame) bool {
	return p.server == frame.DownServer && p.port == frame.ServerPort && p.transport == frame.Transport &&
		p.returnIP == frame.ReturnIP && p.prefix == frame.ReturnPrefix &&
		p.perPacket == (frame.Flags&protocol.ControlFlagBalancePerPacket != 0) &&
		p.bridge == (frame.Flags&protocol.ControlFlagBridge != 0)
}

// destination is the address that the server sends a reply of the path to:
// the reflector of an ICMP path with a return IP or a pool, and the client
// otherwise.
func (p *serverDownPath) destination() netip.Addr {
	if p.transport == protocol.TransportICMP && p.returnIP.IsValid() {
		if p.pool() {
			return p.returnIP.Next()
		}
		return p.returnIP
	}
	return p.key.client.AdvertisedIP
}

type serverDownGroup struct {
	listenPort uint16
	mode       config.Mode
	written    *dataplane.DownGroupEntry
}

// downTarget is one way to send a control frame on a down path. Member is the
// reflector of a path with a return IP or a pool, and invalid for a direct
// path. A target with bridge goes through the bridge at server, wrapped from
// localIP.
type downTarget struct {
	client     dataplane.ClientKey
	pathID     uint16
	listenPort uint16
	server     netip.Addr
	port       uint16
	transport  protocol.TransportID
	member     netip.Addr
	bridge     bool
	localIP    netip.Addr
}

// downRegistry holds the down paths that clients declare with DOWN_REGISTER
// frames. It measures the health of each path and pool member from the probe
// replies, and it writes the paths and their health to the dataplane.
type downRegistry struct {
	mu     sync.Mutex
	ports  config.PortRange
	lease  time.Duration
	plane  downPlane
	locate downLocator
	route  bridgeRouter
	logger *log.Logger
	paths  map[downKey]*serverDownPath
	groups map[dataplane.ClientKey]*serverDownGroup
}

func newDownRegistry(ports config.PortRange, plane downPlane, locate downLocator, logger *log.Logger) *downRegistry {
	return &downRegistry{
		ports:  ports,
		lease:  registrationLeaseSeconds * time.Second,
		plane:  plane,
		locate: locate,
		route:  routeToBridge,
		logger: logger,
		paths:  make(map[downKey]*serverDownPath),
		groups: make(map[dataplane.ClientKey]*serverDownGroup),
	}
}

var errDownNotLocal = errors.New("the down path server address is not an address of this host")

// register keeps the down path of a DOWN_REGISTER that arrived from source.
// A server keeps only the down paths that send from one of its addresses. It
// keeps every down path through a bridge, because the client does not know
// which server the bridge serves. The probes find that out: the bridge drops
// the wrapped probes of the other servers.
func (r *downRegistry) register(frame protocol.ControlFrame, source netip.Addr, now time.Time) error {
	if frame.Type != protocol.ControlDownRegister {
		return errors.New("not a DOWN_REGISTER frame")
	}
	if source != frame.AdvertisedIP {
		return fmt.Errorf("DOWN_REGISTER from %s names advertised IP %s", source, frame.AdvertisedIP)
	}
	bridge := frame.Flags&protocol.ControlFlagBridge != 0
	if !bridge && !r.ports.Contains(frame.ServerPort) {
		return fmt.Errorf("down path port %d is not a server port", frame.ServerPort)
	}
	if frame.PathID >= dataplane.MaxDownPaths {
		return fmt.Errorf("down path ID %d is too large", frame.PathID)
	}
	client := dataplane.ClientKey{AdvertisedIP: frame.AdvertisedIP, InstanceNonce: frame.InstanceNonce}
	key := downKey{client: client, id: frame.PathID}
	r.mu.Lock()
	defer r.mu.Unlock()
	path := r.paths[key]
	// A lease of zero withdraws a down path that the client removed.
	if frame.LeaseSeconds == 0 {
		if path != nil && path.sameAs(frame) {
			path.expires = time.Time{}
			r.syncClientLocked(client, now)
		}
		return nil
	}
	if path == nil || !path.sameAs(frame) {
		path = &serverDownPath{
			key:        key,
			listenPort: frame.ListenPort,
			server:     frame.DownServer,
			port:       frame.ServerPort,
			transport:  frame.Transport,
			returnIP:   frame.ReturnIP,
			prefix:     frame.ReturnPrefix,
			perPacket:  frame.Flags&protocol.ControlFlagBalancePerPacket != 0,
			bridge:     bridge,
			since:      now,
			replies:    make(map[netip.Addr]time.Time),
		}
		if bridge {
			localIP, ifindex, err := r.route(path.server)
			if err != nil {
				return fmt.Errorf("route to bridge %s: %w", path.server, err)
			}
			if !localIP.Is4() || ifindex <= 0 {
				return fmt.Errorf("route to bridge %s has no IPv4 source or interface", path.server)
			}
			path.localIP, path.ifindex = localIP, ifindex
		} else {
			ifindex, err := r.locate(path.server, path.destination())
			if err != nil {
				return err
			}
			path.ifindex = ifindex
		}
		if path.pool() {
			if err := r.plane.ObservePool(path.returnIP, path.prefix, path.transport); err != nil {
				return err
			}
		}
		r.paths[key] = path
	}
	path.listenPort = frame.ListenPort
	path.expires = now.Add(r.lease)
	group := r.groups[client]
	if group == nil {
		group = &serverDownGroup{}
		r.groups[client] = group
	}
	group.listenPort = frame.ListenPort
	group.mode = config.Mode(frame.DownMode)
	r.syncClientLocked(client, now)
	return nil
}

// confirm records a PROBE_REPLY of a down path. It names the member that the
// probe came through in its return IP. The server ignores a reply for an
// unknown path or a member outside the path.
func (r *downRegistry) confirm(frame protocol.ControlFrame, now time.Time) bool {
	if frame.Type != protocol.ControlProbeReply || frame.Flags&protocol.ControlFlagDownPath == 0 {
		return false
	}
	client := dataplane.ClientKey{AdvertisedIP: frame.AdvertisedIP, InstanceNonce: frame.InstanceNonce}
	r.mu.Lock()
	defer r.mu.Unlock()
	path := r.paths[downKey{client: client, id: frame.PathID}]
	if path == nil || now.After(path.expires) || frame.Transport != path.transport {
		return false
	}
	member := frame.ReturnIP
	switch {
	case path.pool():
		if !netip.PrefixFrom(path.returnIP, int(path.prefix)).Contains(member) {
			return false
		}
	case path.returnIP.IsValid():
		if member != path.returnIP {
			return false
		}
	default:
		member = path.server
	}
	path.replies[member] = now
	return true
}

// revoke forgets the down paths of a client that restarted.
func (r *downRegistry) revoke(client dataplane.ClientKey, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, path := range r.paths {
		if key.client == client {
			path.expires = time.Time{}
		}
	}
	r.syncClientLocked(client, now)
}

// candidatesLocked returns the members that a path can send through: the
// members of its pool, its return IP, or its server address.
func (r *downRegistry) candidatesLocked(path *serverDownPath) []netip.Addr {
	switch {
	case path.pool():
		return r.plane.PoolMembers(dataplane.PoolKey{Base: path.returnIP, Transport: path.transport})
	case path.returnIP.IsValid():
		return []netip.Addr{path.returnIP}
	default:
		return []netip.Addr{path.server}
	}
}

// healthyLocked returns the healthy candidates of a path. A new path is healthy
// for its first window, but a path through a bridge waits for its first probe
// reply, because the bridge can serve another server.
func (r *downRegistry) healthyLocked(path *serverDownPath, now time.Time) []netip.Addr {
	candidates := r.candidatesLocked(path)
	if !path.bridge && now.Sub(path.since) < downHealthWindow {
		return candidates
	}
	healthy := make([]netip.Addr, 0, len(candidates))
	for _, candidate := range candidates {
		if replied, ok := path.replies[candidate]; ok && now.Sub(replied) < downHealthWindow {
			healthy = append(healthy, candidate)
		}
	}
	return healthy
}

func (path *serverDownPath) target(member netip.Addr) downTarget {
	target := downTarget{
		client:     path.key.client,
		pathID:     path.key.id,
		listenPort: path.listenPort,
		server:     path.server,
		port:       path.port,
		transport:  path.transport,
		bridge:     path.bridge,
		localIP:    path.localIP,
	}
	if path.returnIP.IsValid() {
		target.member = member
	}
	return target
}

// probeTargets returns one target for each live path and each of its
// candidates, so each probe tests one member.
func (r *downRegistry) probeTargets(now time.Time) []downTarget {
	r.mu.Lock()
	defer r.mu.Unlock()
	var targets []downTarget
	for _, path := range r.paths {
		if now.After(path.expires) {
			continue
		}
		for _, candidate := range r.candidatesLocked(path) {
			targets = append(targets, path.target(candidate))
		}
	}
	return targets
}

// ackTargets returns one target for each live down path of a client. A pool
// path takes its healthy members in turn, or all its candidates in turn when
// none is healthy.
func (r *downRegistry) ackTargets(client dataplane.ClientKey, now time.Time) []downTarget {
	r.mu.Lock()
	defer r.mu.Unlock()
	var targets []downTarget
	for key, path := range r.paths {
		if key.client != client || now.After(path.expires) {
			continue
		}
		members := r.healthyLocked(path, now)
		if len(members) == 0 {
			members = r.candidatesLocked(path)
		}
		if len(members) == 0 {
			continue
		}
		path.cursor = (path.cursor + 1) % len(members)
		targets = append(targets, path.target(members[path.cursor]))
	}
	return targets
}

// sync expires the paths whose lease ended, and writes the health of every
// path to the dataplane.
func (r *downRegistry) sync(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for client := range r.groups {
		r.syncClientLocked(client, now)
	}
}

// syncClientLocked writes the paths and the group of one client. A failed
// write leaves the old entry, and the next sync tries again.
func (r *downRegistry) syncClientLocked(client dataplane.ClientKey, now time.Time) {
	var pathMask, healthyMask, icmpMask uint8
	for key, path := range r.paths {
		if key.client != client {
			continue
		}
		if now.After(path.expires) {
			if err := r.plane.DeleteServerDownPath(client, key.id); err != nil {
				r.logger.Printf("mup down path %d of %s: %v", key.id, client.AdvertisedIP, err)
				continue
			}
			delete(r.paths, key)
			continue
		}
		for member, replied := range path.replies {
			if now.Sub(replied) >= downHealthWindow {
				delete(path.replies, member)
			}
		}
		healthy := r.healthyLocked(path, now)
		entry := dataplane.DownPathEntry{
			Client:     client,
			PathID:     key.id,
			Server:     path.server,
			ServerPort: path.port,
			Transport:  path.transport,
			Ifindex:    path.ifindex,
			ReturnIP:   path.returnIP,
			Pool:       path.pool(),
			PerPacket:  path.perPacket,
			Bridge:     path.bridge,
			LocalIP:    path.localIP,
		}
		if path.pool() {
			entry.Members = healthy
		}
		if path.written == nil || !sameDownEntry(*path.written, entry) {
			if err := r.plane.SetServerDownPath(entry); err != nil {
				r.logger.Printf("mup down path %d of %s: %v", key.id, client.AdvertisedIP, err)
				continue
			}
			path.written = &entry
		}
		pathMask |= 1 << key.id
		if path.transport == protocol.TransportICMP {
			icmpMask |= 1 << key.id
		}
		if len(healthy) > 0 {
			healthyMask |= 1 << key.id
		}
	}
	group := r.groups[client]
	if group == nil {
		return
	}
	if pathMask == 0 {
		if err := r.plane.DeleteServerDownGroup(client); err != nil {
			r.logger.Printf("mup down group of %s: %v", client.AdvertisedIP, err)
			return
		}
		delete(r.groups, client)
		return
	}
	entry := dataplane.DownGroupEntry{
		Client:      client,
		ListenPort:  group.listenPort,
		Mode:        group.mode,
		PathMask:    pathMask,
		HealthyMask: healthyMask,
		ICMPMask:    icmpMask,
	}
	if group.written != nil && *group.written == entry {
		return
	}
	if err := r.plane.SetServerDownGroup(entry); err != nil {
		r.logger.Printf("mup down group of %s: %v", client.AdvertisedIP, err)
		return
	}
	group.written = &entry
}

func sameDownEntry(a, b dataplane.DownPathEntry) bool {
	members := slices.Equal(a.Members, b.Members)
	a.Members, b.Members = nil, nil
	return members && a.Client == b.Client && a.PathID == b.PathID && a.Server == b.Server &&
		a.ServerPort == b.ServerPort && a.Transport == b.Transport && a.Ifindex == b.Ifindex &&
		a.ReturnIP == b.ReturnIP && a.Pool == b.Pool && a.PerPacket == b.PerPacket &&
		a.Bridge == b.Bridge && a.LocalIP == b.LocalIP
}

// clients returns the down paths of each client for mupctl, keyed by client.
func (r *downRegistry) clients(now time.Time) map[dataplane.ClientKey]api.DownGroup {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make(map[dataplane.ClientKey]api.DownGroup, len(r.groups))
	for client, group := range r.groups {
		view := api.DownGroup{Mode: group.mode.String()}
		for key, path := range r.paths {
			if key.client != client || now.After(path.expires) {
				continue
			}
			healthy := r.healthyLocked(path, now)
			down := api.DownPath{
				ID:             key.id,
				Bridge:         path.bridge,
				Server:         path.server.String(),
				Port:           path.port,
				Transport:      path.transport.String(),
				Healthy:        len(healthy) > 0,
				Members:        len(r.candidatesLocked(path)),
				HealthyMembers: len(healthy),
				LeaseSeconds:   path.expires.Sub(now).Seconds(),
			}
			switch {
			case path.pool():
				down.ReturnIP = netip.PrefixFrom(path.returnIP, int(path.prefix)).String()
			case path.returnIP.IsValid():
				down.ReturnIP = path.returnIP.String()
			}
			view.Paths = append(view.Paths, down)
		}
		sort.Slice(view.Paths, func(i, j int) bool { return view.Paths[i].ID < view.Paths[j].ID })
		result[client] = view
	}
	return result
}
