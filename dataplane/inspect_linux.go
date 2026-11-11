//go:build linux

package dataplane

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	"github.com/cilium/ebpf"
)

// SetPath writes the configuration of one client path slot.
func (r *Runtime) SetPath(slot int, path PathSettings) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("set path: MUP dataplane is closed")
	}
	return applyPath(r.objects.PathConfig, r.objects.PathReturns, slot, path)
}

// ClearPath removes the configuration of one client path slot.
func (r *Runtime) ClearPath(slot int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("clear path: MUP dataplane is closed")
	}
	return clearPath(r.objects.PathConfig, r.objects.PathReturns, slot)
}

// SetGroup writes the mode and the path mask of one group.
func (r *Runtime) SetGroup(group GroupSettings) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("set path group: MUP dataplane is closed")
	}
	return applyGroup(r.objects.PathGroups, group)
}

// ClientRoutes lists the peers of a client, sorted by token.
func (r *Runtime) ClientRoutes() ([]ClientRoute, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, errors.New("list client routes: MUP dataplane is closed")
	}
	forward, err := mapEntries[mupPeerEndpointKeyV1, mupPeerTokenValueV1](r.objects.ClientPeerByEndpoint)
	if err != nil && !errors.Is(err, ebpf.ErrIterationAborted) {
		return nil, fmt.Errorf("list client routes: %w", err)
	}
	reverse, err := mapEntries[uint32, mupPeerEndpointValueV1](r.objects.ClientEndpointByToken)
	if err != nil && !errors.Is(err, ebpf.ErrIterationAborted) {
		return nil, fmt.Errorf("list client reverse routes: %w", err)
	}
	now, err := monotonicDuration()
	if err != nil {
		return nil, err
	}
	routes := make([]ClientRoute, 0, len(forward))
	for endpoint, route := range forward {
		reverseRoute, exists := reverse[route.PeerToken]
		hasReverse := exists && reverseRoute.Endpoint == endpoint
		routes = append(routes, decodeClientRoute(endpoint, route, reverseRoute, hasReverse, uint64(now)))
	}
	slices.SortFunc(routes, func(a, b ClientRoute) int { return cmp.Compare(a.Token, b.Token) })
	return routes, nil
}

// ServerRoutes lists the peers of every client on a server, sorted by client
// and token.
func (r *Runtime) ServerRoutes() ([]ServerRoute, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, errors.New("list server routes: MUP dataplane is closed")
	}
	reverse, err := mapEntries[uint16, mupServerReverseValueV1](r.objects.ServerRouteByPort)
	if err != nil && !errors.Is(err, ebpf.ErrIterationAborted) {
		return nil, fmt.Errorf("list server routes: %w", err)
	}
	now, err := monotonicDuration()
	if err != nil {
		return nil, err
	}
	routes := make([]ServerRoute, 0, len(reverse))
	for _, route := range reverse {
		routes = append(routes, decodeServerRoute(route, uint64(now)))
	}
	slices.SortFunc(routes, func(a, b ServerRoute) int {
		if order := compareClientKeys(a.Client, b.Client); order != 0 {
			return order
		}
		return cmp.Compare(a.Token, b.Token)
	})
	return routes, nil
}

// Registrations lists the client registrations of a server.
func (r *Runtime) Registrations() ([]Registration, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, errors.New("list registrations: MUP dataplane is closed")
	}
	entries, err := mapEntries[mupClientKeyV1, mupRegistrationValueV1](r.objects.RegistrationByKey)
	if err != nil {
		return nil, fmt.Errorf("list registrations: %w", err)
	}
	now, err := monotonicDuration()
	if err != nil {
		return nil, err
	}
	registrations := make([]Registration, 0, len(entries))
	for key, value := range entries {
		registrations = append(registrations, decodeRegistration(key, value, uint64(now)))
	}
	slices.SortFunc(registrations, func(a, b Registration) int { return compareClientKeys(a.Client, b.Client) })
	return registrations, nil
}

// RegisteredPaths lists the registered client paths of a server.
func (r *Runtime) RegisteredPaths() ([]RegisteredPath, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, errors.New("list registered paths: MUP dataplane is closed")
	}
	entries, err := mapEntries[mupRegisteredPathKeyV1, mupRegisteredPathValueV1](r.objects.RegisteredPaths)
	if err != nil {
		return nil, fmt.Errorf("list registered paths: %w", err)
	}
	now, err := monotonicDuration()
	if err != nil {
		return nil, err
	}
	paths := make([]RegisteredPath, 0, len(entries))
	for key, value := range entries {
		paths = append(paths, decodeRegisteredPath(key, value, uint64(now)))
	}
	slices.SortFunc(paths, func(a, b RegisteredPath) int {
		if order := compareClientKeys(a.Client, b.Client); order != 0 {
			return order
		}
		return cmp.Compare(a.PathID, b.PathID)
	})
	return paths, nil
}

func compareClientKeys(a, b ClientKey) int {
	if order := a.AdvertisedIP.Compare(b.AdvertisedIP); order != 0 {
		return order
	}
	return cmp.Compare(a.InstanceNonce, b.InstanceNonce)
}
