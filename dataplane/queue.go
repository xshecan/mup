package dataplane

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

type bpfQueue interface {
	Lookup(key, valueOut interface{}) error
	Put(key, value interface{}) error
}

func initializeQueue[T uint16 | uint32](queue bpfQueue, values []T) error {
	var first T
	err := queue.Lookup(nil, &first)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("inspect queue: %w", err)
	}
	for _, value := range values {
		if err := queue.Put(nil, value); err != nil {
			return fmt.Errorf("seed queue with %d: %w", value, err)
		}
	}
	return nil
}
