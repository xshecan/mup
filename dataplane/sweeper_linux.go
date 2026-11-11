//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
)

const (
	routeIdleTimeout        = 180 * time.Second
	resourceQuarantineDelay = 120 * time.Second
)

func (r *Runtime) Sweep(nowNS uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("sweep dataplane: MUP dataplane is closed")
	}
	now := time.Duration(nowNS)
	if err := r.repairRouteInvariants(now); err != nil {
		return err
	}
	registrations, err := r.expireRegistrations(nowNS)
	if err != nil {
		return err
	}
	if err := r.expireClientRoutes(nowNS, now); err != nil {
		return err
	}
	if err := r.expireServerRoutes(nowNS, now, registrations); err != nil {
		return err
	}
	if err := r.peerQuarantine.Release(now, func(token uint32) error {
		return releaseResource[uint32, mupPeerEndpointValueV1](
			r.objects.FreePeerTokens, r.objects.ClientEndpointByToken, token)
	}); err != nil {
		return fmt.Errorf("release peer token: %w", err)
	}
	if err := r.portQuarantine.Release(now, func(port uint16) error {
		return releaseResource[uint16, mupServerReverseValueV1](
			r.objects.FreeTargetPorts, r.objects.ServerRouteByPort, port)
	}); err != nil {
		return fmt.Errorf("release target port: %w", err)
	}
	return nil
}

// releaseResource returns a quarantined value to its free queue. A value that
// a route owns again, for example after a restart race, is not pushed. The
// expiry of that route quarantines the value again.
func releaseResource[T uint16 | uint32, V any](queue, owners *ebpf.Map, value T) error {
	owned, err := hasEntry[V](owners, value)
	if err != nil {
		return fmt.Errorf("look up owner of %d: %w", value, err)
	}
	if owned {
		return nil
	}
	return queue.Put(nil, value)
}

// expireRegistrations deletes expired registrations, and the registered paths
// of expired or revoked registrations. It returns the live registrations.
// Only Go writes these maps, and r.mu serializes the writers.
func (r *Runtime) expireRegistrations(nowNS uint64) (map[mupClientKeyV1]mupRegistrationValueV1, error) {
	registrations, err := mapEntries[mupClientKeyV1, mupRegistrationValueV1](r.objects.RegistrationByKey)
	if err != nil {
		return nil, fmt.Errorf("iterate registrations: %w", err)
	}
	for key, registration := range registrations {
		if registration.ExpiresAtNs > nowNS {
			continue
		}
		if err := deleteEntry(r.objects.RegistrationByKey, key); err != nil {
			return nil, fmt.Errorf("delete expired registration: %w", err)
		}
		delete(registrations, key)
	}

	paths, err := mapEntries[mupRegisteredPathKeyV1, mupRegisteredPathValueV1](r.objects.RegisteredPaths)
	if err != nil {
		return nil, fmt.Errorf("iterate registered paths: %w", err)
	}
	for key, path := range paths {
		if _, registered := registrations[path.Client]; registered && path.ExpiresAtNs > nowNS {
			continue
		}
		if err := deleteEntry(r.objects.RegisteredPaths, key); err != nil {
			return nil, fmt.Errorf("delete expired path: %w", err)
		}
	}
	return registrations, nil
}

func (r *Runtime) expireClientRoutes(nowNS uint64, now time.Duration) error {
	routes, err := mapEntries[mupPeerEndpointKeyV1, mupPeerTokenValueV1](r.objects.ClientPeerByEndpoint)
	if errors.Is(err, ebpf.ErrIterationAborted) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("iterate client routes: %w", err)
	}
	for endpoint, route := range routes {
		if !routeIsIdle(route.LastSeenNs, nowNS) {
			continue
		}
		var current mupPeerTokenValueV1
		if err := r.objects.ClientPeerByEndpoint.Lookup(endpoint, &current); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return fmt.Errorf("recheck client route: %w", err)
		}
		if current.LastSeenNs != route.LastSeenNs || current.PeerToken != route.PeerToken {
			continue
		}
		var reverse mupPeerEndpointValueV1
		if err := r.objects.ClientEndpointByToken.Lookup(route.PeerToken, &reverse); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return fmt.Errorf("lookup client reverse route: %w", err)
		}
		if reverse.Endpoint != endpoint {
			continue
		}
		if err := r.objects.ClientPeerByEndpoint.Delete(endpoint); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return fmt.Errorf("delete client route: %w", err)
		}
		if err := deleteEntry(r.objects.ClientEndpointByToken, route.PeerToken); err != nil {
			return fmt.Errorf("delete client reverse route: %w", err)
		}
		r.peerQuarantine.Add(route.PeerToken, now, resourceQuarantineDelay)
	}
	return nil
}

// expireServerRoutes deletes idle server routes and the routes of expired or
// revoked registrations.
func (r *Runtime) expireServerRoutes(
	nowNS uint64,
	now time.Duration,
	registrations map[mupClientKeyV1]mupRegistrationValueV1,
) error {
	routes, err := mapEntries[mupServerRouteKeyV1, mupServerRouteValueV1](r.objects.ServerRouteByKey)
	if errors.Is(err, ebpf.ErrIterationAborted) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("iterate server routes: %w", err)
	}
	for routeKey, route := range routes {
		if _, registered := registrations[routeKey.Client]; registered && !routeIsIdle(route.LastSeenNs, nowNS) {
			continue
		}
		var current mupServerRouteValueV1
		if err := r.objects.ServerRouteByKey.Lookup(routeKey, &current); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return fmt.Errorf("recheck server route: %w", err)
		}
		if current.LastSeenNs != route.LastSeenNs || current.TargetPort != route.TargetPort {
			continue
		}
		var reverse mupServerReverseValueV1
		if err := r.objects.ServerRouteByPort.Lookup(route.TargetPort, &reverse); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return fmt.Errorf("lookup server reverse route: %w", err)
		}
		if reverse.RouteKey != routeKey {
			continue
		}
		if err := r.objects.ServerRouteByKey.Delete(routeKey); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return fmt.Errorf("delete server route: %w", err)
		}
		if err := deleteEntry(r.objects.ServerRouteByPort, route.TargetPort); err != nil {
			return fmt.Errorf("delete server reverse route: %w", err)
		}
		r.portQuarantine.Add(route.TargetPort, now, resourceQuarantineDelay)
	}
	return nil
}

func routeIsIdle(lastSeenNS, nowNS uint64) bool {
	return lastSeenNS <= nowNS && nowNS-lastSeenNS >= uint64(routeIdleTimeout)
}
