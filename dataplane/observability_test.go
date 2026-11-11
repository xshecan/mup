package dataplane

import (
	"encoding/binary"
	"testing"

	"github.com/xshecan/mup/protocol"
)

func TestAggregatePerCPU(t *testing.T) {
	t.Parallel()

	if got := aggregatePerCPU([]uint64{2, 3, 5, 7}); got != 17 {
		t.Fatalf("aggregatePerCPU = %d, want 17", got)
	}
}

func TestDecodeEvent(t *testing.T) {
	t.Parallel()

	raw := make([]byte, eventRecordSize)
	binary.NativeEndian.PutUint64(raw[0:8], 123)
	binary.NativeEndian.PutUint32(raw[8:12], uint32(protocol.DropMapInvariant))
	binary.NativeEndian.PutUint32(raw[12:16], 9)

	event, err := decodeEvent(raw)
	if err != nil {
		t.Fatalf("decodeEvent: %v", err)
	}
	if event.TimestampNS != 123 || event.Reason != protocol.DropMapInvariant ||
		event.Ifindex != 9 {
		t.Fatalf("event = %#v", event)
	}
}

func TestDecodeEventRejectsWrongSize(t *testing.T) {
	t.Parallel()

	if _, err := decodeEvent(make([]byte, eventRecordSize-1)); err == nil {
		t.Fatal("short event unexpectedly accepted")
	}
}

func TestAvailableResourcesSaturatesAtZero(t *testing.T) {
	t.Parallel()

	if got := availableResources(10, 3, 2); got != 5 {
		t.Fatalf("availableResources = %d, want 5", got)
	}
	if got := availableResources(10, 9, 2); got != 0 {
		t.Fatalf("oversubscribed availableResources = %d, want 0", got)
	}
}
