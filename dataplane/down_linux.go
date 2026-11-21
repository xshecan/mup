//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
)

// SetDownPath writes one client down path slot. A nil path clears the slot.
func (r *Runtime) SetDownPath(slot int, path *DownPathSettings) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("set down path: MUP dataplane is closed")
	}
	return applyDownPath(r.objects.ClientDownPaths, slot, path)
}

// DownPathsSeen returns, for each client down path slot, the time since the
// client program last accepted a reply from it. A slot without a reply has
// a negative duration.
func (r *Runtime) DownPathsSeen() ([MaxDownPaths]time.Duration, error) {
	var seen [MaxDownPaths]time.Duration
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
		return seen, errors.New("read down paths: MUP dataplane is closed")
	}
	for slot := range MaxDownPaths {
		var down mupClientDownPathV1
		if err := r.objects.ClientDownPaths.Lookup(uint32(slot), &down); err != nil {
			return seen, fmt.Errorf("read client down path %d: %w", slot, err)
		}
		if down.ServerIp != 0 && down.LastSeenNs != 0 && uint64(now) >= down.LastSeenNs {
			seen[slot] = time.Duration(uint64(now) - down.LastSeenNs)
		}
	}
	return seen, nil
}

// SetServerDownPath writes one down path of a client on a server.
func (r *Runtime) SetServerDownPath(entry DownPathEntry) error {
	key, value, err := encodeDownPathEntry(entry)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("set server down path: MUP dataplane is closed")
	}
	if err := r.objects.ServerDownPaths.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update down path %d of %s: %w", entry.PathID, entry.Client.AdvertisedIP, err)
	}
	return nil
}

// DeleteServerDownPath removes one down path of a client on a server.
func (r *Runtime) DeleteServerDownPath(client ClientKey, pathID uint16) error {
	key, err := encodeDownPathKey(client, pathID)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("delete server down path: MUP dataplane is closed")
	}
	if err := deleteEntry(r.objects.ServerDownPaths, key); err != nil {
		return fmt.Errorf("delete down path %d of %s: %w", pathID, client.AdvertisedIP, err)
	}
	return nil
}

// SetServerDownGroup writes the down group of a client on a server.
func (r *Runtime) SetServerDownGroup(entry DownGroupEntry) error {
	key, value, err := encodeDownGroupEntry(entry)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("set server down group: MUP dataplane is closed")
	}
	if err := r.objects.ServerDownGroups.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update down group of %s: %w", entry.Client.AdvertisedIP, err)
	}
	return nil
}

// DeleteServerDownGroup removes the down group of a client on a server. Its
// replies then follow the upstream paths again.
func (r *Runtime) DeleteServerDownGroup(client ClientKey) error {
	key, err := encodeClientKey(client)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("delete server down group: MUP dataplane is closed")
	}
	if err := deleteEntry(r.objects.ServerDownGroups, key); err != nil {
		return fmt.Errorf("delete down group of %s: %w", client.AdvertisedIP, err)
	}
	return nil
}
