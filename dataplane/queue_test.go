package dataplane

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

type fakeQueue struct {
	values []uint32
	lookup error
}

func (q *fakeQueue) Lookup(_ interface{}, valueOut interface{}) error {
	if q.lookup != nil {
		return q.lookup
	}
	if len(q.values) == 0 {
		return ebpf.ErrKeyNotExist
	}
	*(valueOut.(*uint32)) = q.values[0]
	return nil
}

func (q *fakeQueue) Put(_ interface{}, value interface{}) error {
	q.values = append(q.values, value.(uint32))
	return nil
}

func TestInitializeNewQueue(t *testing.T) {
	t.Parallel()

	queue := &fakeQueue{lookup: ebpf.ErrKeyNotExist}
	if err := initializeQueue(queue, []uint32{1, 2, 3}); err != nil {
		t.Fatalf("initializeQueue: %v", err)
	}
	if len(queue.values) != 3 || queue.values[0] != 1 || queue.values[2] != 3 {
		t.Fatalf("queue values = %v", queue.values)
	}
}

func TestInitializeQueueDoesNotDuplicateExistingValues(t *testing.T) {
	t.Parallel()

	queue := &fakeQueue{values: []uint32{9}}
	if err := initializeQueue(queue, []uint32{1, 2, 3}); err != nil {
		t.Fatalf("initializeQueue: %v", err)
	}
	if len(queue.values) != 1 || queue.values[0] != 9 {
		t.Fatalf("queue values = %v, want [9]", queue.values)
	}
}

func TestInitializeQueueReportsLookupFailure(t *testing.T) {
	t.Parallel()

	want := errors.New("lookup failed")
	queue := &fakeQueue{lookup: want}
	if err := initializeQueue(queue, []uint32{1}); !errors.Is(err, want) {
		t.Fatalf("initializeQueue error = %v, want %v", err, want)
	}
}
