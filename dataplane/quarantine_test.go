package dataplane

import (
	"testing"
	"time"
)

func TestResourceQuarantineReleasesOnlyAfterDeadline(t *testing.T) {
	t.Parallel()

	var quarantine resourceQuarantine[uint32]
	now := 10 * time.Second
	quarantine.Add(7, now, 2*time.Minute)

	var released []uint32
	release := func(value uint32) error {
		released = append(released, value)
		return nil
	}
	if err := quarantine.Release(now+2*time.Minute-time.Nanosecond, release); err != nil {
		t.Fatalf("early release: %v", err)
	}
	if len(released) != 0 {
		t.Fatalf("released early: %v", released)
	}
	if err := quarantine.Release(now+2*time.Minute, release); err != nil {
		t.Fatalf("release: %v", err)
	}
	if len(released) != 1 || released[0] != 7 || quarantine.Len() != 0 {
		t.Fatalf("released/quarantine = %v/%d", released, quarantine.Len())
	}
}

func TestResourceQuarantineHoldsEachValueOnce(t *testing.T) {
	t.Parallel()

	var quarantine resourceQuarantine[uint16]
	quarantine.Add(20000, time.Second, time.Minute)
	quarantine.Add(20000, 2*time.Second, time.Minute)
	if quarantine.Len() != 1 {
		t.Fatalf("quarantine length = %d, want 1", quarantine.Len())
	}

	var released []uint16
	release := func(value uint16) error {
		released = append(released, value)
		return nil
	}
	if err := quarantine.Release(time.Second+time.Minute, release); err != nil {
		t.Fatalf("release before the later deadline: %v", err)
	}
	if len(released) != 0 {
		t.Fatalf("released before the later deadline: %v", released)
	}
	if err := quarantine.Release(2*time.Second+time.Minute, release); err != nil {
		t.Fatalf("release: %v", err)
	}
	if len(released) != 1 || released[0] != 20000 || quarantine.Len() != 0 {
		t.Fatalf("released/quarantine = %v/%d", released, quarantine.Len())
	}
}
