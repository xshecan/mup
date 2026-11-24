//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
)

// SetEgressPath writes one client egress path slot. A nil path clears the slot.
func (r *Runtime) SetEgressPath(slot int, path *EgressPathSettings) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("set egress path: MUP dataplane is closed")
	}
	return applyEgressPath(r.objects.ClientDownPaths, slot, path)
}

// EgressPathsSeen returns, for each client egress path slot, the time since the
// client program last accepted a reply from it. A slot without a reply has
// a negative duration.
func (r *Runtime) EgressPathsSeen() ([MaxEgressPaths]time.Duration, error) {
	var seen [MaxEgressPaths]time.Duration
	for slot := range seen {
		seen[slot] = -1
	}
	now, err := monotonicDuration()
	if err != nil {
		return seen, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return seen, errors.New("read egress paths: MUP dataplane is closed")
	}
	for slot := range MaxEgressPaths {
		var egress mupClientDownPathV1
		if err := r.objects.ClientDownPaths.Lookup(uint32(slot), &egress); err != nil {
			return seen, fmt.Errorf("read client egress path %d: %w", slot, err)
		}
		if egress.ServerIp != 0 && egress.LastSeenNs != 0 && uint64(now) >= egress.LastSeenNs {
			seen[slot] = time.Duration(uint64(now) - egress.LastSeenNs)
		}
	}
	return seen, nil
}

// SetServerEgressPath writes one egress path of a client on a server.
func (r *Runtime) SetServerEgressPath(entry EgressPathEntry) error {
	key, value, err := encodeEgressPathEntry(entry)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("set server egress path: MUP dataplane is closed")
	}
	if err := r.objects.ServerDownPaths.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update egress path %d of %s: %w", entry.PathID, entry.Client.AdvertisedIP, err)
	}
	return nil
}

// DeleteServerEgressPath removes one egress path of a client on a server.
func (r *Runtime) DeleteServerEgressPath(client ClientKey, pathID uint16) error {
	key, err := encodeEgressPathKey(client, pathID)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("delete server egress path: MUP dataplane is closed")
	}
	if err := deleteEntry(r.objects.ServerDownPaths, key); err != nil {
		return fmt.Errorf("delete egress path %d of %s: %w", pathID, client.AdvertisedIP, err)
	}
	return nil
}

// SetServerEgressGroup writes the egress group of one listen port of a client
// on a server.
func (r *Runtime) SetServerEgressGroup(entry EgressGroupEntry) error {
	key, value, err := encodeEgressGroupEntry(entry)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("set server egress group: MUP dataplane is closed")
	}
	if err := r.objects.ServerDownGroups.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update egress group of %s on listen port %d: %w", entry.Client.AdvertisedIP, entry.ListenPort, err)
	}
	return nil
}

// DeleteServerEgressGroup removes the egress group of one listen port of a
// client on a server. Its replies then follow the ingress paths again.
func (r *Runtime) DeleteServerEgressGroup(client ClientKey, listenPort uint16) error {
	key, err := encodeEgressGroupKey(client, listenPort)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("delete server egress group: MUP dataplane is closed")
	}
	if err := deleteEntry(r.objects.ServerDownGroups, key); err != nil {
		return fmt.Errorf("delete egress group of %s on listen port %d: %w", client.AdvertisedIP, listenPort, err)
	}
	return nil
}
