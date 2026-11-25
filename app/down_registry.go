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
	// egressProbeInterval is the time between two probes of each egress path.
	egressProbeInterval = 2 * time.Second
	// egressHealthWindow is how long an egress path, or a pool member of it, stays
	// healthy after its latest probe reply. A new egress path is healthy for its
	// first window, before the first probe replies arrive.
	egressHealthWindow = 6 * time.Second
)

// egressPlane is the part of the dataplane that the egress registry writes.
type egressPlane interface {
	SetServerEgressPath(dataplane.EgressPathEntry) error
	DeleteServerEgressPath(dataplane.ClientKey, uint16) error
	SetServerEgressGroup(dataplane.EgressGroupEntry) error
	DeleteServerEgressGroup(client dataplane.ClientKey, listenPort uint16) error
	ObservePool(base netip.Addr, prefix uint8, transport protocol.TransportID) error
	PoolMembers(dataplane.PoolKey) []netip.Addr
}

// egressLocator finds the interface that sends from a server address to a
// destination. It fails when the address is not an address of this host.
type egressLocator func(server, destination netip.Addr) (ifindex int, err error)

// bridgeRouter finds the route to a bridge: the source address and the
// interface of the wrapped replies.
type bridgeRouter func(bridge netip.Addr) (source netip.Addr, ifindex int, err error)

func routeToBridge(bridge netip.Addr) (netip.Addr, int, error) {
	return systemResolver{}.Resolve(bridge, "")
}

type egressKey struct {
	client dataplane.ClientKey
	id     uint16
}

// serverEgressPath is one egress path of one client on this server. A path with
// bridge goes through a MUP bridge: server is the bridge address, and the
// wrapped replies leave from localIP. A path with bridgeVia as well wraps the
// direct reply from the bridge address, which the bridge sends from its own
// address, and applies the member to the wrapper. A UDP path forges the
// wrapper from the member to the bridge. An ICMP path reflects it: the wrapper
// is an Echo Request from the bridge address to the member, and the member
// answers it to the bridge (reflectsWrapper).
type serverEgressPath struct {
	key        egressKey
	listenPort uint16
	bridge     bool
	bridgeVia  bool
	localIP    netip.Addr
	server     netip.Addr
	port       uint16
	transport  protocol.TransportID
	returnIP   netip.Addr
	prefix     uint8
	perPacket  bool
	ifindex    int
	// srcFirst and srcLast are the source range of the replies, or zero for
	// none. The probes and the ACKs keep port.
	srcFirst uint16
	srcLast  uint16
	since    time.Time
	expires  time.Time
	// replies holds the time of the latest probe reply through each member,
	// or through the server address of a direct path.
	replies map[netip.Addr]time.Time
	written *dataplane.EgressPathEntry
	cursor  int
}

func (p *serverEgressPath) pool() bool {
	return p.prefix != 0
}

// reflectsWrapper reports a bridge via path on ICMP with a return IP or a
// pool. Its wrapper is an Echo Request from the bridge address to a member, so
// it leaves on the route to the member, and the members must answer pings.
func (p *serverEgressPath) reflectsWrapper() bool {
	return p.bridge && p.bridgeVia && p.transport == protocol.TransportICMP && p.returnIP.IsValid()
}

// poolTransport is the transport of the pool of the path. The members of a
// UDP bridge via path are only the forged sources of the UDP wrapper to the
// bridge, so the path uses the UDP pool, which lists every address that the
// server can forge. A path that reflects its wrapper uses the ICMP pool, which
// lists only the hosts that answer pings. Every other path uses the pool of
// its transport.
func (p *serverEgressPath) poolTransport() protocol.TransportID {
	if p.reflectsWrapper() {
		return protocol.TransportICMP
	}
	if p.bridgeVia {
		return protocol.TransportUDP
	}
	return p.transport
}

// sameAs reports whether a EGRESS_REGISTER describes the path as it is.
func (p *serverEgressPath) sameAs(frame protocol.ControlFrame) bool {
	return p.server == frame.EgressServer && p.port == frame.ServerPort && p.transport == frame.Transport &&
		p.returnIP == frame.ReturnIP && p.prefix == frame.ReturnPrefix &&
		p.perPacket == (frame.Flags&protocol.ControlFlagBalancePerPacket != 0) &&
		p.bridge == (frame.Flags&protocol.ControlFlagBridge != 0) &&
		p.bridgeVia == (frame.Flags&protocol.ControlFlagBridgeVia != 0) &&
		p.srcFirst == frame.SrcFirst && p.srcLast == frame.SrcLast
}

// destination is the address that the server sends a reply of the path to:
// the reflector of an ICMP path with a return IP or a pool, and the client
// otherwise.
func (p *serverEgressPath) destination() netip.Addr {
	if p.transport == protocol.TransportICMP && p.returnIP.IsValid() {
		if p.pool() {
			return p.returnIP.Next()
		}
		return p.returnIP
	}
	return p.key.client.AdvertisedIP
}

// egressGroupKey names one group of a client: its listen port.
type egressGroupKey struct {
	client     dataplane.ClientKey
	listenPort uint16
}

type serverEgressGroup struct {
	mode    config.Mode
	written *dataplane.EgressGroupEntry
}

// egressTarget is one way to send a control frame on an egress path. Member is the
// reflector of a path with a return IP or a pool, and invalid for a direct
// path. A target with bridge goes through the bridge at server, wrapped from
// localIP. A target with bridgeVia as well wraps the direct form, which the
// bridge sends from its own address. On UDP the wrapper is forged from member
// to the bridge. On ICMP the wrapper reflects off member (reflectsWrapper).
type egressTarget struct {
	client     dataplane.ClientKey
	pathID     uint16
	listenPort uint16
	server     netip.Addr
	port       uint16
	transport  protocol.TransportID
	member     netip.Addr
	bridge     bool
	bridgeVia  bool
	localIP    netip.Addr
}

// reflectsWrapper reports a target whose wrapper is an Echo Request from the
// bridge address to member, which member answers to the bridge.
func (t egressTarget) reflectsWrapper() bool {
	return t.bridge && t.bridgeVia && t.transport == protocol.TransportICMP && t.member.IsValid()
}

// egressRegistry holds the egress paths that clients declare with EGRESS_REGISTER
// frames. It measures the health of each path and pool member from the probe
// replies, and it writes the paths and their health to the dataplane.
type egressRegistry struct {
	mu     sync.Mutex
	ports  config.PortRange
	lease  time.Duration
	plane  egressPlane
	locate egressLocator
	route  bridgeRouter
	logger *log.Logger
	paths  map[egressKey]*serverEgressPath
	groups map[egressGroupKey]*serverEgressGroup
}

func newEgressRegistry(ports config.PortRange, plane egressPlane, locate egressLocator, logger *log.Logger) *egressRegistry {
	return &egressRegistry{
		ports:  ports,
		lease:  registrationLeaseSeconds * time.Second,
		plane:  plane,
		locate: locate,
		route:  routeToBridge,
		logger: logger,
		paths:  make(map[egressKey]*serverEgressPath),
		groups: make(map[egressGroupKey]*serverEgressGroup),
	}
}

var errEgressNotLocal = errors.New("the egress path server address is not an address of this host")

// register keeps the egress path of a EGRESS_REGISTER. The service checks the
// source of the frame before. A server keeps only the egress paths that send from one of its addresses. It
// keeps every egress path through a bridge, because the client does not know
// which server the bridge serves. The probes find that out: the bridge drops
// the wrapped probes of the other servers.
func (r *egressRegistry) register(frame protocol.ControlFrame, now time.Time) error {
	if frame.Type != protocol.ControlEgressRegister {
		return errors.New("not a EGRESS_REGISTER frame")
	}
	bridge := frame.Flags&protocol.ControlFlagBridge != 0
	if !bridge && !r.ports.Contains(frame.ServerPort) {
		return fmt.Errorf("egress path port %d is not a server port", frame.ServerPort)
	}
	if frame.PathID >= dataplane.MaxEgressPaths {
		return fmt.Errorf("egress path ID %d is too large", frame.PathID)
	}
	client := dataplane.ClientKey{AdvertisedIP: frame.AdvertisedIP, InstanceNonce: frame.InstanceNonce}
	key := egressKey{client: client, id: frame.PathID}
	r.mu.Lock()
	defer r.mu.Unlock()
	path := r.paths[key]
	// A lease of zero withdraws an egress path that the client removed.
	if frame.LeaseSeconds == 0 {
		if path != nil && path.sameAs(frame) {
			path.expires = time.Time{}
			r.syncClientLocked(client, now)
		}
		return nil
	}
	if path == nil || !path.sameAs(frame) {
		path = &serverEgressPath{
			key:        key,
			listenPort: frame.ListenPort,
			server:     frame.EgressServer,
			port:       frame.ServerPort,
			transport:  frame.Transport,
			returnIP:   frame.ReturnIP,
			prefix:     frame.ReturnPrefix,
			perPacket:  frame.Flags&protocol.ControlFlagBalancePerPacket != 0,
			bridge:     bridge,
			bridgeVia:  frame.Flags&protocol.ControlFlagBridgeVia != 0,
			srcFirst:   frame.SrcFirst,
			srcLast:    frame.SrcLast,
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
			// A reflected wrapper goes to the member, so it leaves on
			// the route to the member, as on a reflect route.
			if path.reflectsWrapper() {
				destination := path.destination()
				_, ifindex, err := r.route(destination)
				if err != nil {
					return fmt.Errorf("route to bridge via member %s: %w", destination, err)
				}
				if ifindex <= 0 {
					return fmt.Errorf("route to bridge via member %s has no interface", destination)
				}
				path.ifindex = ifindex
			}
		} else {
			ifindex, err := r.locate(path.server, path.destination())
			if err != nil {
				return err
			}
			path.ifindex = ifindex
		}
		if path.pool() {
			if err := r.plane.ObservePool(path.returnIP, path.prefix, path.poolTransport()); err != nil {
				return err
			}
		}
		r.paths[key] = path
	}
	// A path that changes its listen port moves to the new group, and the sync
	// below also visits the old group.
	path.listenPort = frame.ListenPort
	path.expires = now.Add(r.lease)
	groupKey := egressGroupKey{client: client, listenPort: frame.ListenPort}
	group := r.groups[groupKey]
	if group == nil {
		group = &serverEgressGroup{}
		r.groups[groupKey] = group
	}
	group.mode = config.Mode(frame.EgressMode)
	r.syncClientLocked(client, now)
	return nil
}

// confirm records a PROBE_REPLY of an egress path. It names the member that the
// probe came through in its return IP. The server ignores a reply for an
// unknown path or a member outside the path.
func (r *egressRegistry) confirm(frame protocol.ControlFrame, now time.Time) bool {
	if frame.Type != protocol.ControlProbeReply || frame.Flags&protocol.ControlFlagEgressPath == 0 {
		return false
	}
	client := dataplane.ClientKey{AdvertisedIP: frame.AdvertisedIP, InstanceNonce: frame.InstanceNonce}
	r.mu.Lock()
	defer r.mu.Unlock()
	path := r.paths[egressKey{client: client, id: frame.PathID}]
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

// revoke forgets the egress paths of a client that restarted.
func (r *egressRegistry) revoke(client dataplane.ClientKey, now time.Time) {
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
func (r *egressRegistry) candidatesLocked(path *serverEgressPath) []netip.Addr {
	switch {
	case path.pool():
		return r.plane.PoolMembers(dataplane.PoolKey{Base: path.returnIP, Transport: path.poolTransport()})
	case path.returnIP.IsValid():
		return []netip.Addr{path.returnIP}
	default:
		return []netip.Addr{path.server}
	}
}

// healthyLocked returns the healthy candidates of a path. A new path is healthy
// for its first window, but a path through a bridge waits for its first probe
// reply, because the bridge can serve another server.
func (r *egressRegistry) healthyLocked(path *serverEgressPath, now time.Time) []netip.Addr {
	candidates := r.candidatesLocked(path)
	if !path.bridge && now.Sub(path.since) < egressHealthWindow {
		return candidates
	}
	healthy := make([]netip.Addr, 0, len(candidates))
	for _, candidate := range candidates {
		if replied, ok := path.replies[candidate]; ok && now.Sub(replied) < egressHealthWindow {
			healthy = append(healthy, candidate)
		}
	}
	return healthy
}

func (path *serverEgressPath) target(member netip.Addr) egressTarget {
	target := egressTarget{
		client:     path.key.client,
		pathID:     path.key.id,
		listenPort: path.listenPort,
		server:     path.server,
		port:       path.port,
		transport:  path.transport,
		bridge:     path.bridge,
		bridgeVia:  path.bridgeVia,
		localIP:    path.localIP,
	}
	if path.returnIP.IsValid() {
		target.member = member
	}
	return target
}

// probeTargets returns one target for each live path and each of its
// candidates, so each probe tests one member.
func (r *egressRegistry) probeTargets(now time.Time) []egressTarget {
	r.mu.Lock()
	defer r.mu.Unlock()
	var targets []egressTarget
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

// ackTargets returns one target for each live egress path of a client. A pool
// path takes its healthy members in turn, or all its candidates in turn when
// none is healthy.
func (r *egressRegistry) ackTargets(client dataplane.ClientKey, now time.Time) []egressTarget {
	r.mu.Lock()
	defer r.mu.Unlock()
	var targets []egressTarget
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
func (r *egressRegistry) sync(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := make(map[dataplane.ClientKey]bool, len(r.groups))
	for key := range r.groups {
		if seen[key.client] {
			continue
		}
		seen[key.client] = true
		r.syncClientLocked(key.client, now)
	}
}

// syncClientLocked writes the paths and the groups of one client. Each listen
// port has its own group with only the paths of that port. A failed
// write leaves the old entry, and the next sync tries again.
func (r *egressRegistry) syncClientLocked(client dataplane.ClientKey, now time.Time) {
	type masks struct{ path, healthy, icmp uint8 }
	byPort := make(map[uint16]*masks)
	for key, path := range r.paths {
		if key.client != client {
			continue
		}
		if now.After(path.expires) {
			if err := r.plane.DeleteServerEgressPath(client, key.id); err != nil {
				r.logger.Printf("mup egress path %d of %s: %v", key.id, client.AdvertisedIP, err)
				continue
			}
			delete(r.paths, key)
			continue
		}
		for member, replied := range path.replies {
			if now.Sub(replied) >= egressHealthWindow {
				delete(path.replies, member)
			}
		}
		healthy := r.healthyLocked(path, now)
		entry := dataplane.EgressPathEntry{
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
			BridgeVia:  path.bridgeVia,
			LocalIP:    path.localIP,
			SrcFirst:   path.srcFirst,
			SrcLast:    path.srcLast,
		}
		if path.pool() {
			entry.Members = healthy
		}
		if path.written == nil || !sameEgressEntry(*path.written, entry) {
			if err := r.plane.SetServerEgressPath(entry); err != nil {
				r.logger.Printf("mup egress path %d of %s: %v", key.id, client.AdvertisedIP, err)
				continue
			}
			path.written = &entry
		}
		group := byPort[path.listenPort]
		if group == nil {
			group = &masks{}
			byPort[path.listenPort] = group
		}
		group.path |= 1 << key.id
		if path.transport == protocol.TransportICMP {
			group.icmp |= 1 << key.id
		}
		if len(healthy) > 0 {
			group.healthy |= 1 << key.id
		}
	}
	for key, group := range r.groups {
		if key.client != client {
			continue
		}
		mask := byPort[key.listenPort]
		if mask == nil || mask.path == 0 {
			if err := r.plane.DeleteServerEgressGroup(client, key.listenPort); err != nil {
				r.logger.Printf("mup egress group %d of %s: %v", key.listenPort, client.AdvertisedIP, err)
				continue
			}
			delete(r.groups, key)
			continue
		}
		entry := dataplane.EgressGroupEntry{
			Client:      client,
			ListenPort:  key.listenPort,
			Mode:        group.mode,
			PathMask:    mask.path,
			HealthyMask: mask.healthy,
			ICMPMask:    mask.icmp,
		}
		if group.written != nil && *group.written == entry {
			continue
		}
		if err := r.plane.SetServerEgressGroup(entry); err != nil {
			r.logger.Printf("mup egress group %d of %s: %v", key.listenPort, client.AdvertisedIP, err)
			continue
		}
		group.written = &entry
	}
}

func sameEgressEntry(a, b dataplane.EgressPathEntry) bool {
	members := slices.Equal(a.Members, b.Members)
	a.Members, b.Members = nil, nil
	return members && a.Client == b.Client && a.PathID == b.PathID && a.Server == b.Server &&
		a.ServerPort == b.ServerPort && a.Transport == b.Transport && a.Ifindex == b.Ifindex &&
		a.ReturnIP == b.ReturnIP && a.Pool == b.Pool && a.PerPacket == b.PerPacket &&
		a.Bridge == b.Bridge && a.BridgeVia == b.BridgeVia && a.LocalIP == b.LocalIP &&
		a.SrcFirst == b.SrcFirst && a.SrcLast == b.SrcLast
}

// clients returns the egress groups of each client for mupctl, keyed by client
// and sorted by listen port.
func (r *egressRegistry) clients(now time.Time) map[dataplane.ClientKey][]api.EgressGroup {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make(map[dataplane.ClientKey][]api.EgressGroup)
	for groupKey, group := range r.groups {
		view := api.EgressGroup{ListenPort: groupKey.listenPort, Mode: group.mode.String()}
		for key, path := range r.paths {
			if key.client != groupKey.client || path.listenPort != groupKey.listenPort || now.After(path.expires) {
				continue
			}
			healthy := r.healthyLocked(path, now)
			egress := api.EgressPath{
				ID:             key.id,
				Bridge:         path.bridge,
				BridgeVia:      path.bridgeVia,
				Server:         path.server.String(),
				Port:           path.port,
				Transport:      path.transport.String(),
				Healthy:        len(healthy) > 0,
				Members:        len(r.candidatesLocked(path)),
				HealthyMembers: len(healthy),
				LeaseSeconds:   path.expires.Sub(now).Seconds(),
				SrcFirst:       path.srcFirst,
				SrcLast:        path.srcLast,
			}
			switch {
			case path.pool():
				egress.ReturnIP = netip.PrefixFrom(path.returnIP, int(path.prefix)).String()
			case path.returnIP.IsValid():
				egress.ReturnIP = path.returnIP.String()
			}
			view.Paths = append(view.Paths, egress)
		}
		sort.Slice(view.Paths, func(i, j int) bool { return view.Paths[i].ID < view.Paths[j].ID })
		result[groupKey.client] = append(result[groupKey.client], view)
	}
	for _, views := range result {
		sort.Slice(views, func(i, j int) bool { return views[i].ListenPort < views[j].ListenPort })
	}
	return result
}
