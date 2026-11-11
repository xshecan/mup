//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func (r *Runtime) reconcilePeerPool(now time.Duration) error {
	used, err := r.currentPeerTokenReferences()
	if err != nil {
		return err
	}
	return reconcilePool(r.objects.FreePeerTokens, peerTokenPool(), used, &r.peerQuarantine, now, "peer-token")
}

func (r *Runtime) reconcilePortPool(now time.Duration) error {
	used, err := r.currentTargetPortReferences()
	if err != nil {
		return err
	}
	return reconcilePool(r.objects.FreeTargetPorts, targetPortPool(), used, &r.portQuarantine, now, "target-port")
}

// reconcilePool rebuilds a free queue after a restart. Values that are neither
// free, used, nor quarantined were lost in a crash, and enter quarantine.
func reconcilePool[T uint16 | uint32](
	queue *ebpf.Map,
	pool []T,
	used map[T]struct{},
	quarantine *resourceQuarantine[T],
	now time.Duration,
	name string,
) error {
	quarantined := quarantine.Values()
	for value := range quarantined {
		used[value] = struct{}{}
	}

	free, err := drainQueue[T](queue)
	if err != nil {
		if restoreErr := refillQueue(queue, pool, free); restoreErr != nil {
			return fmt.Errorf("drain %s queue: %w; restore drained values: %v", name, err, restoreErr)
		}
		return fmt.Errorf("drain %s queue: %w", name, err)
	}
	for value := range quarantined {
		delete(free, value)
	}
	available, lost, err := classifyPool(pool, free, used)
	if err != nil {
		_ = refillQueue(queue, pool, free)
		return fmt.Errorf("reconcile %s queue: %w", name, err)
	}
	for _, value := range available {
		if err := queue.Put(nil, value); err != nil {
			return fmt.Errorf("restore %s %d: %w", name, value, err)
		}
	}
	for _, value := range lost {
		quarantine.Add(value, now, resourceQuarantineDelay)
	}
	return nil
}

func drainQueue[T uint16 | uint32](queue *ebpf.Map) (map[T]struct{}, error) {
	values := make(map[T]struct{})
	for {
		var value T
		err := queue.LookupAndDelete(nil, &value)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return values, nil
		}
		if err != nil {
			return values, err
		}
		if _, duplicate := values[value]; duplicate {
			return values, fmt.Errorf("duplicate queue value %d", value)
		}
		values[value] = struct{}{}
	}
}

// refillQueue pushes values back in pool order.
func refillQueue[T uint16 | uint32](queue *ebpf.Map, pool []T, values map[T]struct{}) error {
	for _, value := range pool {
		if _, exists := values[value]; !exists {
			continue
		}
		if err := queue.Put(nil, value); err != nil {
			return err
		}
	}
	return nil
}

func monotonicDuration() (time.Duration, error) {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return 0, err
	}
	return time.Duration(now.Nano()), nil
}
