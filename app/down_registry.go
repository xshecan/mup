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
	"github.com/xshecan/mup/measure"
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
	pathCounterStore
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
	// measure holds the loss, the probes and the rate of the path.
	measure *egressMeasure
	// gate and memberGates are the loss gates of the path and of its members
	// in a group with a loss tolerance.
	gate        measure.LossGate
	memberGates map[netip.Addr]*measure.LossGate
	// degradedMembers holds the members that the gates degraded in the
	// latest sync.
	degradedMembers []netip.Addr
	// limit is the rate limit that the latest EGRESS_LIMIT of the path set,
	// or zero for none. unlimited counts the EGRESS_REGISTER frames of the
	// path in a row with no EGRESS_LIMIT after them, and the path loses its
	// limit after egressLimitMisses of them.
	limit     dataplane.RateLimit
	unlimited int
}

// egressLimitMisses is the number of EGRESS_REGISTER frames of a path in a row
// with no EGRESS_LIMIT after them that remove the limit of the path, because
// the client removed it.
const egressLimitMisses = 3

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

// serverEgressGroup is one egress group of a client. Its mode and its
// settings come from the latest EGRESS_REGISTER of the group. dataMask holds
// the paths that carry replies. With hasPreferred, the failover mode tries the
// path preferred first: the path of the latency choice.
type serverEgressGroup struct {
	mode         config.Mode
	settings     protocol.EgressSettings
	chooser      measure.LatencyChooser
	dataMask     uint8
	hasPreferred bool
	preferred    uint8
	written      *dataplane.EgressGroupEntry
}

// activeMask holds the paths that the server sends replies on now, as the
// program picks them from the data set: in the failover mode the preferred
// path of a latency choice, or else the path with the lowest ID, and every
// path of the data set in the other modes.
func (g *serverEgressGroup) activeMask() uint8 {
	if g.mode == config.ModeFailover {
		if g.hasPreferred && g.dataMask&(1<<g.preferred) != 0 {
			return 1 << g.preferred
		}
		return g.dataMask & -g.dataMask
	}
	return g.dataMask
}

// policy is the loss tolerance and the path choice of the group.
func (g *serverEgressGroup) policy() dataPolicy {
	return egressPolicy(g.settings, g.mode)
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
			key:         key,
			listenPort:  frame.ListenPort,
			server:      frame.EgressServer,
			port:        frame.ServerPort,
			transport:   frame.Transport,
			returnIP:    frame.ReturnIP,
			prefix:      frame.ReturnPrefix,
			perPacket:   frame.Flags&protocol.ControlFlagBalancePerPacket != 0,
			bridge:      bridge,
			bridgeVia:   frame.Flags&protocol.ControlFlagBridgeVia != 0,
			srcFirst:    frame.SrcFirst,
			srcLast:     frame.SrcLast,
			since:       now,
			replies:     make(map[netip.Addr]time.Time),
			measure:     newEgressMeasure(),
			memberGates: make(map[netip.Addr]*measure.LossGate),
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
		// A missing counter only leaves the loss of the path unknown.
		_ = r.plane.EnsureServerPathCounter(client, key.id, dataplane.PathCounterEgress)
	}
	// A path that changes its listen port moves to the new group, and the sync
	// below also visits the old group.
	path.listenPort = frame.ListenPort
	path.expires = now.Add(r.lease)
	// An EGRESS_LIMIT follows each EGRESS_REGISTER of a path with a limit, so
	// a path that misses it again and again has none any more.
	if path.limit.BitsPerSecond != 0 {
		path.unlimited++
		if path.unlimited >= egressLimitMisses {
			path.limit, path.unlimited = dataplane.RateLimit{}, 0
		}
	}
	groupKey := egressGroupKey{client: client, listenPort: frame.ListenPort}
	group := r.groups[groupKey]
	if group == nil {
		group = &serverEgressGroup{}
		r.groups[groupKey] = group
	}
	group.mode = config.Mode(frame.EgressMode)
	// The lease field also carries the settings of the group. The frame of
	// an older client has none.
	_, group.settings = protocol.UnpackEgressLease(frame.LeaseSeconds)
	r.syncClientLocked(client, now)
	return nil
}

// limit keeps the rate limit of an EGRESS_LIMIT with the egress path that it
// names. The service checks the source of the frame before, as for an
// EGRESS_REGISTER. The path must be a live path of the client on this server
// with the same server port, transport and listen port, so a limit never
// creates a path. A rate of zero removes the limit at once. The dataplane
// gets the limit with the next sync.
func (r *egressRegistry) limit(frame protocol.ControlFrame, now time.Time) error {
	if frame.Type != protocol.ControlEgressLimit {
		return errors.New("not an EGRESS_LIMIT frame")
	}
	if frame.PathID >= dataplane.MaxEgressPaths {
		return fmt.Errorf("egress path ID %d is too large", frame.PathID)
	}
	client := dataplane.ClientKey{AdvertisedIP: frame.AdvertisedIP, InstanceNonce: frame.InstanceNonce}
	r.mu.Lock()
	defer r.mu.Unlock()
	path := r.paths[egressKey{client: client, id: frame.PathID}]
	if path == nil || now.After(path.expires) {
		return nil
	}
	if path.port != frame.ServerPort || path.transport != frame.Transport || path.listenPort != frame.ListenPort {
		return fmt.Errorf("EGRESS_LIMIT names server port %d/%s of listen port %d, but the egress path has %d/%s of listen port %d",
			frame.ServerPort, frame.Transport, frame.ListenPort, path.port, path.transport, path.listenPort)
	}
	path.unlimited = 0
	path.limit = dataplane.RateLimit{
		BitsPerSecond: uint64(frame.LimitKbps) * 1000,
		PerMember:     frame.LimitKbps != 0 && frame.LimitFlags&protocol.EgressLimitPerMember != 0,
	}
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
	path.measure.answered(frame.Sequence, member, frame.LeaseSeconds, now)
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

// egressProbeSend is one probe of a round: its target, its sequence, and the
// count code of the data packets that the server sent on the path.
type egressProbeSend struct {
	target   egressTarget
	sequence uint32
	count    uint32
}

// probeRound returns the probes of one round: one for each live path and
// each of its candidates, as probeTargets. It reads the egress counter of each
// path once, and every probe of the path carries that count. next gives the
// sequence of each probe.
func (r *egressRegistry) probeRound(now time.Time, next func() uint32) []egressProbeSend {
	r.mu.Lock()
	defer r.mu.Unlock()
	var sends []egressProbeSend
	for key, path := range r.paths {
		if now.After(path.expires) {
			continue
		}
		candidates := r.candidatesLocked(path)
		counter, counted, err := r.plane.ServerPathCounter(key.client, key.id, dataplane.PathCounterEgress)
		round := path.measure.startRound(counter, counted && err == nil, candidates, now)
		for _, candidate := range candidates {
			sequence := next()
			path.measure.sent(round, sequence, candidate, now)
			sends = append(sends, egressProbeSend{target: path.target(candidate), sequence: sequence, count: round.tx})
		}
	}
	return sends
}

// members lists each candidate of each live egress path of each client, with
// the measurement of its probes.
func (r *egressRegistry) members(now time.Time) []api.Member {
	r.mu.Lock()
	defer r.mu.Unlock()
	var members []api.Member
	for key, path := range r.paths {
		if now.After(path.expires) {
			continue
		}
		healthy := r.healthyLocked(path, now)
		for _, candidate := range r.candidatesLocked(path) {
			members = append(members, api.Member{
				Client:      key.client.AdvertisedIP.String(),
				Direction:   directionEgress,
				PathID:      int(key.id),
				ListenPort:  path.listenPort,
				Address:     candidate.String(),
				Healthy:     containsAddr(healthy, candidate),
				Degraded:    containsAddr(path.degradedMembers, candidate),
				Measurement: path.measure.memberView(candidate, now),
			})
		}
	}
	sort.Slice(members, func(i, j int) bool {
		a, b := members[i], members[j]
		if a.Client != b.Client {
			return a.Client < b.Client
		}
		if a.PathID != b.PathID {
			return a.PathID < b.PathID
		}
		return netip.MustParseAddr(a.Address).Less(netip.MustParseAddr(b.Address))
	})
	return members
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
	type masks struct {
		path, icmp uint8
		candidates []dataCandidate
		shares     []rateShare
	}
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
			_ = r.plane.DeleteServerPathCounter(client, key.id, dataplane.PathCounterEgress)
			continue
		}
		for member, replied := range path.replies {
			if now.Sub(replied) >= egressHealthWindow {
				delete(path.replies, member)
			}
		}
		healthy := r.healthyLocked(path, now)
		var policy dataPolicy
		if group := r.groups[egressGroupKey{client: client, listenPort: path.listenPort}]; group != nil {
			policy = group.policy()
		}
		degraded := r.evaluateGatesLocked(path, policy, now)
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
			Limit:      path.limit,
		}
		if path.pool() {
			entry.Members = publishedMembers(healthy, path.degradedMembers)
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
		group.candidates = append(group.candidates, dataCandidate{
			id:       int(key.id),
			priority: int(key.id),
			healthy:  len(healthy) > 0,
			degraded: degraded,
			rtt:      choiceRTT(&path.measure.probes, now),
		})
		group.shares = append(group.shares, rateShare{id: int(key.id), limit: path.limit, members: len(r.candidatesLocked(path))})
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
		var chooser *measure.LatencyChooser
		if group.policy().latency {
			chooser = &group.chooser
		}
		dataMask, chosen, ok := dataSet(mask.candidates, chooser, now)
		group.dataMask = dataMask
		// The latency choice names the path that the failover mode tries
		// first. The data set stays the usable set, so a full path can
		// spill to the others. The last choice stays while no path is
		// usable.
		if chooser == nil {
			group.hasPreferred = false
		} else if ok {
			group.hasPreferred, group.preferred = true, uint8(chosen)
		}
		if group.hasPreferred && mask.path&(1<<group.preferred) == 0 {
			group.hasPreferred = false
		}
		entry := dataplane.EgressGroupEntry{
			Client:       client,
			ListenPort:   key.listenPort,
			Mode:         group.mode,
			PathMask:     mask.path,
			HealthyMask:  group.dataMask,
			ICMPMask:     mask.icmp,
			Weights:      balancerWeights(group.mode, mask.shares),
			HasPreferred: group.hasPreferred,
			Preferred:    group.preferred,
		}
		if !entry.HasPreferred {
			entry.Preferred = 0
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

// evaluateGatesLocked runs the loss gates of a path and of its members, and
// reports whether the path is degraded. Without a loss tolerance nothing is
// degraded. The evidence of the path is the loss of its data, or else the
// loss of its probes, and the evidence of a member is the loss of its probes.
func (r *egressRegistry) evaluateGatesLocked(path *serverEgressPath, policy dataPolicy, now time.Time) bool {
	limit := policy.tolerance.Percent()
	if limit == 0 {
		path.gate = measure.LossGate{}
		clear(path.memberGates)
		path.degradedMembers = nil
		return false
	}
	data, _ := lossMeasurement(&path.measure.loss, now)
	var probe *float64
	if loss, ok := path.measure.probes.LossPercent(now); ok {
		probe = &loss
	}
	degraded := path.gate.Evaluate(limit, data, probe, now)
	path.degradedMembers = nil
	if !path.returnIP.IsValid() {
		return degraded
	}
	candidates := r.candidatesLocked(path)
	for member := range path.memberGates {
		if !containsAddr(candidates, member) {
			delete(path.memberGates, member)
		}
	}
	for _, member := range candidates {
		tracker := path.measure.members[member]
		if tracker == nil {
			continue
		}
		gate := path.memberGates[member]
		if gate == nil {
			gate = &measure.LossGate{}
			path.memberGates[member] = gate
		}
		var loss *float64
		if value, ok := tracker.LossPercent(now); ok {
			loss = &value
		}
		if gate.Evaluate(limit, nil, loss, now) {
			path.degradedMembers = append(path.degradedMembers, member)
		}
	}
	return degraded
}

func sameEgressEntry(a, b dataplane.EgressPathEntry) bool {
	members := slices.Equal(a.Members, b.Members)
	a.Members, b.Members = nil, nil
	return members && a.Client == b.Client && a.PathID == b.PathID && a.Server == b.Server &&
		a.ServerPort == b.ServerPort && a.Transport == b.Transport && a.Ifindex == b.Ifindex &&
		a.ReturnIP == b.ReturnIP && a.Pool == b.Pool && a.PerPacket == b.PerPacket &&
		a.Bridge == b.Bridge && a.BridgeVia == b.BridgeVia && a.LocalIP == b.LocalIP &&
		a.SrcFirst == b.SrcFirst && a.SrcLast == b.SrcLast && a.Limit == b.Limit
}

// clients returns the egress groups of each client for mupctl, keyed by client
// and sorted by listen port.
func (r *egressRegistry) clients(now time.Time) map[dataplane.ClientKey][]api.EgressGroup {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make(map[dataplane.ClientKey][]api.EgressGroup)
	for groupKey, group := range r.groups {
		policy := group.policy()
		view := api.EgressGroup{
			ListenPort:       groupKey.listenPort,
			Mode:             group.mode.String(),
			TolerancePercent: policy.tolerance.Percent(),
			Prefer:           policy.prefer(),
		}
		active := group.activeMask()
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
				Active:         active&(1<<key.id) != 0,
				Degraded:       len(healthy) > 0 && path.gate.Degraded(),
				Measurement:    path.measure.view(now),

				BandwidthBitsPerSecond: float64(path.limit.BitsPerSecond),
				BandwidthPerMember:     path.limit.PerMember,
			}
			if egress.Degraded {
				egress.Reason = path.gate.Reason()
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
