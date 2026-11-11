//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
)

func (r *Runtime) repairRouteInvariants(now time.Duration) error {
	if err := r.repairClientRouteInvariants(now); err != nil {
		return err
	}
	if err := r.repairServerRouteInvariants(now); err != nil {
		return err
	}
	return nil
}

func (r *Runtime) repairClientRouteInvariants(now time.Duration) error {
	forwardRoutes, err := mapEntries[mupPeerEndpointKeyV1, mupPeerTokenValueV1](r.objects.ClientPeerByEndpoint)
	if errors.Is(err, ebpf.ErrIterationAborted) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect client forward invariants: %w", err)
	}
	reverseRoutes, err := mapEntries[uint32, mupPeerEndpointValueV1](r.objects.ClientEndpointByToken)
	if errors.Is(err, ebpf.ErrIterationAborted) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect client reverse invariants: %w", err)
	}
	forward := make(map[mupPeerEndpointKeyV1]uint32, len(forwardRoutes))
	for endpoint, route := range forwardRoutes {
		forward[endpoint] = route.PeerToken
	}
	reverse := make(map[uint32]mupPeerEndpointKeyV1, len(reverseRoutes))
	for token, route := range reverseRoutes {
		reverse[token] = route.Endpoint
	}

	invalidForward, invalidReverse := classifyPairs(forward, reverse)
	candidates := make(map[uint32]struct{}, len(invalidForward)+len(invalidReverse))
	for _, key := range invalidForward {
		var current mupPeerTokenValueV1
		if err := r.objects.ClientPeerByEndpoint.Lookup(key, &current); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return fmt.Errorf("recheck invalid client forward route: %w", err)
		}
		if current.PeerToken != forward[key] {
			continue
		}
		var currentReverse mupPeerEndpointValueV1
		err := r.objects.ClientEndpointByToken.Lookup(current.PeerToken, &currentReverse)
		if err == nil && currentReverse.Endpoint == key {
			continue
		}
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("recheck client reverse route: %w", err)
		}
		if err := deleteEntry(r.objects.ClientPeerByEndpoint, key); err != nil {
			return fmt.Errorf("delete invalid client forward route: %w", err)
		}
		candidates[current.PeerToken] = struct{}{}
	}

	for _, candidate := range invalidReverse {
		var current mupPeerEndpointValueV1
		if err := r.objects.ClientEndpointByToken.Lookup(candidate, &current); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return fmt.Errorf("recheck invalid client reverse route: %w", err)
		}
		if current.Endpoint != reverse[candidate] {
			continue
		}
		var currentForward mupPeerTokenValueV1
		err := r.objects.ClientPeerByEndpoint.Lookup(current.Endpoint, &currentForward)
		if err == nil && currentForward.PeerToken == candidate {
			continue
		}
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("recheck client forward route: %w", err)
		}
		if err := deleteEntry(r.objects.ClientEndpointByToken, candidate); err != nil {
			return fmt.Errorf("delete invalid client reverse route: %w", err)
		}
		candidates[candidate] = struct{}{}
	}

	referenced, err := r.currentPeerTokenReferences()
	if err != nil {
		if errors.Is(err, ebpf.ErrIterationAborted) {
			return nil
		}
		return err
	}
	for candidate := range candidates {
		if candidate == 0 || candidate > uint32(peerTokenPoolSize) {
			continue
		}
		if _, stillReferenced := referenced[candidate]; !stillReferenced {
			r.peerQuarantine.Add(candidate, now, resourceQuarantineDelay)
		}
	}
	return nil
}

func (r *Runtime) currentPeerTokenReferences() (map[uint32]struct{}, error) {
	forward, err := mapEntries[mupPeerEndpointKeyV1, mupPeerTokenValueV1](r.objects.ClientPeerByEndpoint)
	if err != nil {
		return nil, fmt.Errorf("collect client forward references: %w", err)
	}
	reverse, err := mapEntries[uint32, mupPeerEndpointValueV1](r.objects.ClientEndpointByToken)
	if err != nil {
		return nil, fmt.Errorf("collect client reverse references: %w", err)
	}
	referenced := make(map[uint32]struct{}, len(forward)+len(reverse))
	for _, route := range forward {
		referenced[route.PeerToken] = struct{}{}
	}
	for token := range reverse {
		referenced[token] = struct{}{}
	}
	return referenced, nil
}

func (r *Runtime) repairServerRouteInvariants(now time.Duration) error {
	forwardRoutes, err := mapEntries[mupServerRouteKeyV1, mupServerRouteValueV1](r.objects.ServerRouteByKey)
	if errors.Is(err, ebpf.ErrIterationAborted) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect server forward invariants: %w", err)
	}
	reverseRoutes, err := mapEntries[uint16, mupServerReverseValueV1](r.objects.ServerRouteByPort)
	if errors.Is(err, ebpf.ErrIterationAborted) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect server reverse invariants: %w", err)
	}
	forward := make(map[mupServerRouteKeyV1]uint16, len(forwardRoutes))
	for routeKey, route := range forwardRoutes {
		forward[routeKey] = route.TargetPort
	}
	reverse := make(map[uint16]mupServerRouteKeyV1, len(reverseRoutes))
	for port, route := range reverseRoutes {
		reverse[port] = route.RouteKey
	}

	invalidForward, invalidReverse := classifyPairs(forward, reverse)
	candidates := make(map[uint16]struct{}, len(invalidForward)+len(invalidReverse))
	for _, key := range invalidForward {
		var current mupServerRouteValueV1
		if err := r.objects.ServerRouteByKey.Lookup(key, &current); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return fmt.Errorf("recheck invalid server forward route: %w", err)
		}
		if current.TargetPort != forward[key] {
			continue
		}
		var currentReverse mupServerReverseValueV1
		err := r.objects.ServerRouteByPort.Lookup(current.TargetPort, &currentReverse)
		if err == nil && currentReverse.RouteKey == key {
			continue
		}
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("recheck server reverse route: %w", err)
		}
		if err := deleteEntry(r.objects.ServerRouteByKey, key); err != nil {
			return fmt.Errorf("delete invalid server forward route: %w", err)
		}
		candidates[current.TargetPort] = struct{}{}
	}

	for _, candidate := range invalidReverse {
		var current mupServerReverseValueV1
		if err := r.objects.ServerRouteByPort.Lookup(candidate, &current); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return fmt.Errorf("recheck invalid server reverse route: %w", err)
		}
		if current.RouteKey != reverse[candidate] {
			continue
		}
		var currentForward mupServerRouteValueV1
		err := r.objects.ServerRouteByKey.Lookup(current.RouteKey, &currentForward)
		if err == nil && currentForward.TargetPort == candidate {
			continue
		}
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("recheck server forward route: %w", err)
		}
		if err := deleteEntry(r.objects.ServerRouteByPort, candidate); err != nil {
			return fmt.Errorf("delete invalid server reverse route: %w", err)
		}
		candidates[candidate] = struct{}{}
	}

	referenced, err := r.currentTargetPortReferences()
	if err != nil {
		if errors.Is(err, ebpf.ErrIterationAborted) {
			return nil
		}
		return err
	}
	for candidate := range candidates {
		if candidate < firstTargetPort || candidate > lastTargetPort {
			continue
		}
		if _, stillReferenced := referenced[candidate]; !stillReferenced {
			r.portQuarantine.Add(candidate, now, resourceQuarantineDelay)
		}
	}
	return nil
}

func (r *Runtime) currentTargetPortReferences() (map[uint16]struct{}, error) {
	forward, err := mapEntries[mupServerRouteKeyV1, mupServerRouteValueV1](r.objects.ServerRouteByKey)
	if err != nil {
		return nil, fmt.Errorf("collect server forward references: %w", err)
	}
	reverse, err := mapEntries[uint16, mupServerReverseValueV1](r.objects.ServerRouteByPort)
	if err != nil {
		return nil, fmt.Errorf("collect server reverse references: %w", err)
	}
	referenced := make(map[uint16]struct{}, len(forward)+len(reverse))
	for _, route := range forward {
		referenced[route.TargetPort] = struct{}{}
	}
	for port := range reverse {
		referenced[port] = struct{}{}
	}
	return referenced, nil
}
