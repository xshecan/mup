//go:build linux

package dataplane

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/protocol"
)

// clientEgressCounterBase is the index of the counter of egress path slot 0 in
// client_path_counters. It must match MUP_PATH_COUNTER_EGRESS_BASE.
const clientEgressCounterBase = config.MaxPaths

// ClientPathCounters returns the data packets that the client sent on each
// ingress path slot and accepted from each egress path slot. It sums the CPUs.
func (r *Runtime) ClientPathCounters() ([config.MaxPaths]PathCounter, [MaxEgressPaths]PathCounter, error) {
	var ingress [config.MaxPaths]PathCounter
	var egress [MaxEgressPaths]PathCounter
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ingress, egress, errors.New("read client path counters: MUP dataplane is closed")
	}
	for slot := range ingress {
		counter, err := readClientPathCounter(r.objects.ClientPathCounters, uint32(slot))
		if err != nil {
			return ingress, egress, fmt.Errorf("read the counter of ingress path %d: %w", slot, err)
		}
		ingress[slot] = counter
	}
	for slot := range egress {
		counter, err := readClientPathCounter(r.objects.ClientPathCounters, uint32(clientEgressCounterBase+slot))
		if err != nil {
			return ingress, egress, fmt.Errorf("read the counter of egress path %d: %w", slot, err)
		}
		egress[slot] = counter
	}
	return ingress, egress, nil
}

func readClientPathCounter(counters *ebpf.Map, index uint32) (PathCounter, error) {
	var values []mupPathCounterV1
	if err := counters.Lookup(index, &values); err != nil {
		return PathCounter{}, err
	}
	return sumPathCounters(values), nil
}

// sumPathCounters adds the per-CPU values of one counter.
func sumPathCounters(values []mupPathCounterV1) PathCounter {
	var total PathCounter
	for _, value := range values {
		total.Packets += value.Packets
		total.Bytes += value.Bytes
	}
	return total
}

// encodeServerPathCounterKey checks the path ID and the direction of a server
// path counter and builds its key. An ingress path ID goes up to
// protocol.MaxPathID, and an egress path ID is below MaxEgressPaths.
func encodeServerPathCounterKey(client ClientKey, pathID uint16, direction uint8) (mupPathCounterKeyV1, error) {
	key, err := encodeClientKey(client)
	if err != nil {
		return mupPathCounterKeyV1{}, err
	}
	switch direction {
	case PathCounterIngress:
		if pathID > protocol.MaxPathID {
			return mupPathCounterKeyV1{}, fmt.Errorf("ingress path ID %d is outside 0 to %d", pathID, protocol.MaxPathID)
		}
	case PathCounterEgress:
		if pathID >= MaxEgressPaths {
			return mupPathCounterKeyV1{}, fmt.Errorf("egress path ID %d is outside 0 to %d", pathID, MaxEgressPaths-1)
		}
	default:
		return mupPathCounterKeyV1{}, fmt.Errorf("path counter direction %d is neither ingress nor egress", direction)
	}
	return mupPathCounterKeyV1{Client: key, PathId: uint32(pathID), Direction: uint32(direction)}, nil
}

// EnsureServerPathCounter creates a zero counter for one path of a client if
// none exists. It never resets a counter.
func (r *Runtime) EnsureServerPathCounter(client ClientKey, pathID uint16, direction uint8) error {
	key, err := encodeServerPathCounterKey(client, pathID, direction)
	if err != nil {
		return err
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("count the CPUs: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("create server path counter: MUP dataplane is closed")
	}
	return ensurePathCounter(r.objects.ServerPathCounters, key, cpus)
}

// ensurePathCounter inserts a zero counter only where none exists, so a
// counter that the program already counts keeps its value.
func ensurePathCounter(counters *ebpf.Map, key mupPathCounterKeyV1, cpus int) error {
	zero := make([]mupPathCounterV1, cpus)
	err := counters.Update(key, zero, ebpf.UpdateNoExist)
	if err == nil || errors.Is(err, ebpf.ErrKeyExist) {
		return nil
	}
	return fmt.Errorf("create the counter of path %d direction %d: %w", key.PathId, key.Direction, err)
}

// DeleteServerPathCounter removes the counter of one path of a client. A
// missing counter is no error.
func (r *Runtime) DeleteServerPathCounter(client ClientKey, pathID uint16, direction uint8) error {
	key, err := encodeServerPathCounterKey(client, pathID, direction)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("delete server path counter: MUP dataplane is closed")
	}
	if err := deleteEntry(r.objects.ServerPathCounters, key); err != nil {
		return fmt.Errorf("delete the counter of path %d direction %d of %s: %w", pathID, direction, client.AdvertisedIP, err)
	}
	return nil
}

// ServerPathCounter returns the counter of one path of a client, as the sum of
// the CPUs. ok is false when the path has no counter.
func (r *Runtime) ServerPathCounter(client ClientKey, pathID uint16, direction uint8) (PathCounter, bool, error) {
	key, err := encodeServerPathCounterKey(client, pathID, direction)
	if err != nil {
		return PathCounter{}, false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return PathCounter{}, false, errors.New("read server path counter: MUP dataplane is closed")
	}
	return readServerPathCounter(r.objects.ServerPathCounters, key)
}

func readServerPathCounter(counters *ebpf.Map, key mupPathCounterKeyV1) (PathCounter, bool, error) {
	var values []mupPathCounterV1
	err := counters.Lookup(key, &values)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return PathCounter{}, false, nil
	}
	if err != nil {
		return PathCounter{}, false, fmt.Errorf("read the counter of path %d direction %d: %w", key.PathId, key.Direction, err)
	}
	return sumPathCounters(values), true, nil
}
