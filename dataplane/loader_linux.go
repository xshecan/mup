//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/cilium/ebpf"
)

type Runtime struct {
	mu             sync.Mutex
	objects        mupObjects
	links          []attachedLink
	pinRoot        string
	peerQuarantine resourceQuarantine[uint32]
	portQuarantine resourceQuarantine[uint16]
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
	options := &ebpf.CollectionOptions{}
	options.Maps.PinPath = cfg.PinRoot
	runtime = &Runtime{pinRoot: cfg.PinRoot}
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
		client: r.objects.ClientConfig,
		groups: r.objects.PathGroups,
		paths:  r.objects.PathConfig,
		state:  r.objects.PathState,
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
	return applyServerSettings(configurationMaps{
		server: r.objects.ServerConfig,
	}, settings)
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

func (r *Runtime) UpdatePathState(healthyMask uint8, generation uint32) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("update path state: MUP dataplane is closed")
	}
	return applyPathState(r.objects.PathState, healthyMask, generation)
}
