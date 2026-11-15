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

	"github.com/cilium/ebpf"

	"github.com/xshecan/mup/protocol"
)

type Runtime struct {
	mu             sync.Mutex
	objects        mupObjects
	links          []attachedLink
	pinRoot        string
	peerQuarantine resourceQuarantine[uint32]
	portQuarantine resourceQuarantine[uint16]
	pools          map[PoolKey]PoolInfo
	closed         bool
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
	runtime = &Runtime{pinRoot: cfg.PinRoot, pools: make(map[PoolKey]PoolInfo)}
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
		server: r.objects.ServerConfig,
		ports:  r.objects.ServerPorts,
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
// a pool it seeds the health map with every address healthy, so the server can
// reflect through the pool at once. The prober refines the health later.
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
	pool, err := encodeReflectorPool(addresses, nil)
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

// SetPoolHealth writes the health of a pool. The healthy slice has one entry
// for each address, in the order of PoolInfo.Addresses.
func (r *Runtime) SetPoolHealth(key PoolKey, healthy []bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("set pool health: MUP dataplane is closed")
	}
	info, exists := r.pools[key]
	if !exists {
		return fmt.Errorf("set pool health: pool %s %s is not observed", key.Base, key.Transport)
	}
	if len(healthy) != len(info.Addresses) {
		return fmt.Errorf("set pool health: got %d health bits, want %d", len(healthy), len(info.Addresses))
	}
	pool, err := encodeReflectorPool(info.Addresses, healthy)
	if err != nil {
		return err
	}
	mapKey, err := reflectorKey(key)
	if err != nil {
		return err
	}
	return r.objects.ReflectorPools.Update(mapKey, pool, ebpf.UpdateAny)
}

func (r *Runtime) UpdatePathState(healthyMask uint8, generation uint32) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("update path state: MUP dataplane is closed")
	}
	return applyPathState(r.objects.PathState, healthyMask, generation)
}
