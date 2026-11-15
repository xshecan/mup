//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/cilium/ebpf"

	"github.com/xshecan/mup/protocol"
)

// reflectorConfirmTTL is how long a UDP reflector stays healthy after the
// client last confirmed it received a spoofed-source probe from it. It is a few
// probe cycles, so a reflector stays healthy while the probe keeps arriving.
const reflectorConfirmTTL = 6 * time.Second

type Runtime struct {
	mu             sync.Mutex
	objects        mupObjects
	links          []attachedLink
	pinRoot        string
	peerQuarantine resourceQuarantine[uint32]
	portQuarantine resourceQuarantine[uint16]
	pools          map[PoolKey]PoolInfo
	// confirmations holds, for each UDP reflector source the client reported
	// receiving, the monotonic time of that report. A UDP pool member is healthy
	// while its confirmation is fresh.
	confirmations map[netip.Addr]uint64
	closed        bool
}

func Load(cfg Config) (runtime *Runtime, err error) {
	if err := validatePinRoot(cfg.PinRoot); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.PinRoot, 0o755); err != nil {
		return nil, fmt.Errorf("create BPF pin root: %w", err)
	}
	peerPoolIsNew, err := pinDoesNotExist(filepath.Join(cfg.PinRoot, "free_peer_tokens"))
	if err != nil {
		return nil, fmt.Errorf("inspect peer-token queue pin: %w", err)
	}
	portPoolIsNew, err := pinDoesNotExist(filepath.Join(cfg.PinRoot, "free_target_ports"))
	if err != nil {
		return nil, fmt.Errorf("inspect target-port queue pin: %w", err)
	}
	// v0.1.9 pinned the pool map under this name with a smaller key.
	if err := os.Remove(filepath.Join(cfg.PinRoot, "reflector_health")); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove old reflector pin: %w", err)
	}
	options := &ebpf.CollectionOptions{}
	options.Maps.PinPath = cfg.PinRoot
	runtime = &Runtime{
		pinRoot:       cfg.PinRoot,
		pools:         make(map[PoolKey]PoolInfo),
		confirmations: make(map[netip.Addr]uint64),
	}
	if err := loadMupObjects(&runtime.objects, options); err != nil {
		return nil, fmt.Errorf("load MUP BPF objects: %w", err)
	}
	defer func() {
		if err != nil {
			_ = runtime.objects.Close()
			runtime = nil
		}
	}()

	now, err := monotonicDuration()
	if err != nil {
		return nil, fmt.Errorf("read monotonic clock: %w", err)
	}
	if err := runtime.repairRouteInvariants(now); err != nil {
		return nil, err
	}
	if err := runtime.syncClientRoutesBySource(); err != nil {
		return nil, err
	}
	if peerPoolIsNew {
		if err := initializeQueue(runtime.objects.FreePeerTokens, peerTokenPool()); err != nil {
			return nil, fmt.Errorf("initialize peer-token queue: %w", err)
		}
	} else if err := runtime.reconcilePeerPool(now); err != nil {
		return nil, err
	}
	if portPoolIsNew {
		if err := initializeQueue(runtime.objects.FreeTargetPorts, targetPortPool()); err != nil {
			return nil, fmt.Errorf("initialize target-port queue: %w", err)
		}
	} else if err := runtime.reconcilePortPool(now); err != nil {
		return nil, err
	}
	return runtime, nil
}

func pinDoesNotExist(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return false, nil
	}
	if os.IsNotExist(err) {
		return true, nil
	}
	return false, err
}

func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var first error
	for i := len(r.links) - 1; i >= 0; i-- {
		if err := r.links[i].link.Close(); err != nil && first == nil {
			first = err
		}
	}
	if err := r.objects.Close(); err != nil && first == nil {
		first = err
	}
	return first
}

func (r *Runtime) ConfigureClient(settings ClientSettings) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("configure client: MUP dataplane is closed")
	}
	// The slots of a group from the previous run can belong to another group now.
	if err := r.deleteOtherGroups(settings.Groups); err != nil {
		return err
	}
	return applyClientSettings(configurationMaps{
		client:  r.objects.ClientConfig,
		groups:  r.objects.PathGroups,
		paths:   r.objects.PathConfig,
		returns: r.objects.PathReturns,
		state:   r.objects.PathState,
	}, settings)
}

func (r *Runtime) deleteOtherGroups(keep []GroupSettings) error {
	groups, err := mapEntries[uint16, mupPathGroupV1](r.objects.PathGroups)
	if err != nil && !errors.Is(err, ebpf.ErrIterationAborted) {
		return fmt.Errorf("list path groups: %w", err)
	}
	for listenPort := range groups {
		if slices.ContainsFunc(keep, func(group GroupSettings) bool { return group.ListenPort == listenPort }) {
			continue
		}
		if err := deleteEntry(r.objects.PathGroups, listenPort); err != nil {
			return fmt.Errorf("delete path group of listen port %d: %w", listenPort, err)
		}
	}
	return nil
}

func (r *Runtime) ConfigureServer(settings ServerSettings) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("configure server: MUP dataplane is closed")
	}
	if err := applyServerSettings(configurationMaps{
		server:  r.objects.ServerConfig,
		ports:   r.objects.ServerPorts,
		ingress: r.objects.TargetIngress,
	}, settings); err != nil {
		return err
	}
	if settings.Target.Addr() == settings.SourceIP {
		return r.releaseLocalTargetPort(settings.Target.Port())
	}
	return nil
}

func (r *Runtime) releaseLocalTargetPort(port uint16) error {
	var reverse mupServerReverseValueV1
	if err := r.objects.ServerRouteByPort.Lookup(port, &reverse); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("look up route of local target port %d: %w", port, err)
	}
	var forward mupServerRouteValueV1
	err := r.objects.ServerRouteByKey.Lookup(reverse.RouteKey, &forward)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("look up forward route of local target port %d: %w", port, err)
	}
	if err == nil && forward.TargetPort == port {
		if err := deleteEntry(r.objects.ServerRouteByKey, reverse.RouteKey); err != nil {
			return fmt.Errorf("delete route of local target port %d: %w", port, err)
		}
	}
	if err := deleteEntry(r.objects.ServerRouteByPort, port); err != nil {
		return fmt.Errorf("delete reverse route of local target port %d: %w", port, err)
	}
	now, err := monotonicDuration()
	if err != nil {
		return fmt.Errorf("read monotonic clock: %w", err)
	}
	r.portQuarantine.Add(port, now, resourceQuarantineDelay)
	return nil
}

func (r *Runtime) RegisterPath(settings RegistrationSettings) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("register path: MUP dataplane is closed")
	}
	return applyRegistrationSettings(
		r.objects.RegistrationByKey,
		r.objects.RegisteredPaths,
		settings,
	)
}

func (r *Runtime) RevokeRegistration(client ClientKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("revoke registration: MUP dataplane is closed")
	}
	return revokeRegistration(r.objects.RegistrationByKey, client)
}

// ObservePool records a return pool from a registration. On the first sight of
// a pool it seeds a bootstrap member set so the server can reflect at once. An
// ICMP pool seeds every member healthy, and the prober refines it. A UDP pool
// seeds every member unhealthy, because a UDP reflector is used only after the
// client confirms it reaches them. The prober and probe refine both later.
func (r *Runtime) ObservePool(base netip.Addr, prefix uint8, transport protocol.TransportID) error {
	addresses, err := poolAddresses(base, prefix)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("observe pool: MUP dataplane is closed")
	}
	key := PoolKey{Base: base, Transport: transport}
	if _, exists := r.pools[key]; exists {
		return nil
	}
	var healthy []bool
	if transport == protocol.TransportUDP {
		healthy = make([]bool, len(addresses))
	}
	pool, err := encodeReflectorPool(addresses, healthy)
	if err != nil {
		return err
	}
	mapKey, err := reflectorKey(key)
	if err != nil {
		return err
	}
	if err := r.objects.ReflectorPools.Update(mapKey, pool, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("seed reflector pool %s %s: %w", base, transport, err)
	}
	r.pools[key] = PoolInfo{Base: base, Prefix: prefix, Transport: transport, Addresses: addresses}
	return nil
}

// Reflectors returns every pool address with its current health, sorted by
// pool base, transport, and address.
func (r *Runtime) Reflectors() ([]Reflector, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, fmt.Errorf("list reflectors: MUP dataplane is closed")
	}
	var reflectors []Reflector
	for key, info := range r.pools {
		mapKey, err := reflectorKey(key)
		if err != nil {
			return nil, err
		}
		var pool mupReflectorPoolV1
		if err := r.objects.ReflectorPools.Lookup(mapKey, &pool); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return nil, fmt.Errorf("read reflector pool %s %s: %w", key.Base, key.Transport, err)
		}
		for index, address := range info.Addresses {
			reflectors = append(reflectors, Reflector{
				Base:      key.Base,
				Prefix:    info.Prefix,
				Transport: info.Transport,
				Address:   address,
				Healthy:   pool.HealthyMask&(uint64(1)<<uint(index)) != 0,
			})
		}
	}
	slices.SortFunc(reflectors, func(a, b Reflector) int {
		if c := a.Base.Compare(b.Base); c != 0 {
			return c
		}
		if a.Transport != b.Transport {
			return int(a.Transport) - int(b.Transport)
		}
		return a.Address.Compare(b.Address)
	})
	return reflectors, nil
}

// Pools returns the observed pools, for the prober to probe.
func (r *Runtime) Pools() []PoolInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	pools := make([]PoolInfo, 0, len(r.pools))
	for _, pool := range r.pools {
		pools = append(pools, pool)
	}
	return pools
}

// SetPool replaces the members of a pool and their health. The prober calls it
// each cycle with the addresses it discovered alive and which of them are
// healthy. For a UDP pool the health argument is ignored and each member is
// healthy only while its client confirmation is fresh, because a UDP reflector
// never answers the server and its real health comes from the client receipt.
// An empty address slice writes an empty pool, so the server reflects nothing
// until the next sweep finds a live member.
func (r *Runtime) SetPool(key PoolKey, addresses []netip.Addr, healthy []bool) error {
	if len(healthy) != len(addresses) {
		return fmt.Errorf("set pool: got %d health bits, want %d", len(healthy), len(addresses))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("set pool: MUP dataplane is closed")
	}
	info, exists := r.pools[key]
	if !exists {
		return fmt.Errorf("set pool: pool %s %s is not observed", key.Base, key.Transport)
	}
	info.Addresses = append([]netip.Addr(nil), addresses...)
	if key.Transport == protocol.TransportUDP {
		now, err := monotonicDuration()
		if err != nil {
			return err
		}
		r.pruneConfirmationsLocked(uint64(now))
		healthy = r.udpHealthLocked(info.Addresses, uint64(now))
	}
	if err := r.writePoolLocked(key, info.Addresses, healthy); err != nil {
		return err
	}
	r.pools[key] = info
	return nil
}

// ConfirmReflector records that the client received a spoofed-source probe from
// a UDP reflector, and refreshes the health of every UDP pool that holds it.
func (r *Runtime) ConfirmReflector(source netip.Addr) error {
	if !source.Is4() {
		return fmt.Errorf("confirm reflector %s: must be IPv4", source)
	}
	now, err := monotonicDuration()
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("confirm reflector: MUP dataplane is closed")
	}
	r.confirmations[source] = uint64(now)
	for key, info := range r.pools {
		if key.Transport != protocol.TransportUDP {
			continue
		}
		if !netip.PrefixFrom(info.Base, int(info.Prefix)).Contains(source) {
			continue
		}
		healthy := r.udpHealthLocked(info.Addresses, uint64(now))
		if err := r.writePoolLocked(key, info.Addresses, healthy); err != nil {
			return err
		}
	}
	return nil
}

// PoolMembers returns the current member addresses of a pool. The UDP probe
// emitter reads them to probe each reflector.
func (r *Runtime) PoolMembers(key PoolKey) []netip.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	info, exists := r.pools[key]
	if !exists {
		return nil
	}
	return append([]netip.Addr(nil), info.Addresses...)
}

// udpHealthLocked returns the health of each address from the freshness of its
// client confirmation.
func (r *Runtime) udpHealthLocked(addresses []netip.Addr, now uint64) []bool {
	healthy := make([]bool, len(addresses))
	for index, address := range addresses {
		confirmed, ok := r.confirmations[address]
		healthy[index] = ok && now >= confirmed && now-confirmed < uint64(reflectorConfirmTTL)
	}
	return healthy
}

// pruneConfirmationsLocked forgets confirmations older than the health window.
func (r *Runtime) pruneConfirmationsLocked(now uint64) {
	for address, confirmed := range r.confirmations {
		if now < confirmed || now-confirmed >= uint64(reflectorConfirmTTL) {
			delete(r.confirmations, address)
		}
	}
}

// writePoolLocked writes a pool's members and health to the BPF map. An empty
// address slice writes an empty pool.
func (r *Runtime) writePoolLocked(key PoolKey, addresses []netip.Addr, healthy []bool) error {
	var pool mupReflectorPoolV1
	if len(addresses) > 0 {
		encoded, err := encodeReflectorPool(addresses, healthy)
		if err != nil {
			return err
		}
		pool = encoded
	}
	mapKey, err := reflectorKey(key)
	if err != nil {
		return err
	}
	if err := r.objects.ReflectorPools.Update(mapKey, pool, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update reflector pool %s %s: %w", key.Base, key.Transport, err)
	}
	return nil
}

func (r *Runtime) UpdatePathState(healthyMask uint8, generation uint32) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("update path state: MUP dataplane is closed")
	}
	return applyPathState(r.objects.PathState, healthyMask, generation)
}
