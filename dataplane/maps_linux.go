//go:build linux

package dataplane

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// mapEntries copies every entry of a BPF map. Callers delete entries only
// after the copy is complete, because deleting the key under the iterator
// restarts a hash-map iteration. On error, the partial copy is returned.
func mapEntries[K comparable, V any](entries *ebpf.Map) (map[K]V, error) {
	result := make(map[K]V)
	iterator := entries.Iterate()
	var key K
	var value V
	for iterator.Next(&key, &value) {
		result[key] = value
	}
	return result, iterator.Err()
}

// countEntries counts the entries of a BPF map. An iteration that concurrent
// deletions abort returns the partial count.
func countEntries[K, V any](entries *ebpf.Map, name string) (uint64, error) {
	iterator := entries.Iterate()
	var key K
	var value V
	var count uint64
	for iterator.Next(&key, &value) {
		count++
	}
	if err := iterator.Err(); err != nil && !errors.Is(err, ebpf.ErrIterationAborted) {
		return 0, fmt.Errorf("count %s: %w", name, err)
	}
	return count, nil
}

func deleteEntry(entries *ebpf.Map, key any) error {
	if err := entries.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

func hasEntry[V any](entries *ebpf.Map, key any) (bool, error) {
	var value V
	err := entries.Lookup(key, &value)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, nil
	}
	return err == nil, err
}
