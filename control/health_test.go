package control

import (
	"errors"
	"testing"
	"time"
)

func TestHealthTransitionsDownAfterThreeMissesAndUpAfterReply(t *testing.T) {
	t.Parallel()

	engine := NewHealthEngine(2, 900*time.Millisecond, 3)
	now := time.Unix(1000, 0)
	if transition, err := engine.StartHealthy(0); err != nil || !transition.Changed || !transition.Healthy {
		t.Fatalf("Registered = %#v, %v", transition, err)
	}
	for sequence := uint32(1); sequence <= 3; sequence++ {
		if err := engine.Sent(0, sequence, now); err != nil {
			t.Fatalf("Sent(%d): %v", sequence, err)
		}
		transitions := engine.ExpireProbes(now.Add(900 * time.Millisecond))
		if sequence < 3 && len(transitions) != 0 {
			t.Fatalf("miss %d changed health: %#v", sequence, transitions)
		}
		if sequence == 3 && (len(transitions) != 1 || transitions[0].Healthy) {
			t.Fatalf("third miss transitions = %#v", transitions)
		}
		now = now.Add(time.Second)
	}
	if mask, _ := engine.Snapshot(); mask != 0 {
		t.Fatalf("healthy mask after misses = %#x, want 0", mask)
	}
	if err := engine.Sent(0, 4, now); err != nil {
		t.Fatalf("Sent recovery probe: %v", err)
	}
	transition, rtt, err := engine.Reply(0, 4, now.Add(20*time.Millisecond))
	if err != nil {
		t.Fatalf("Reply: %v", err)
	}
	if !transition.Changed || !transition.Healthy || rtt != 20*time.Millisecond {
		t.Fatalf("recovery = %#v, %v", transition, rtt)
	}
}

func TestHealthRejectsStaleReply(t *testing.T) {
	t.Parallel()

	engine := NewHealthEngine(1, 900*time.Millisecond, 3)
	now := time.Unix(2000, 0)
	if err := engine.Sent(0, 10, now); err != nil {
		t.Fatalf("Sent: %v", err)
	}
	if _, _, err := engine.Reply(0, 9, now.Add(time.Millisecond)); !errors.Is(err, ErrProbeSequence) {
		t.Fatalf("Reply error = %v, want %v", err, ErrProbeSequence)
	}
}

func TestHealthAddedPathWaitsForFirstReply(t *testing.T) {
	t.Parallel()

	engine := NewHealthEngine(8, 900*time.Millisecond, 3)
	if _, err := engine.StartHealthy(0); err != nil {
		t.Fatalf("Registered: %v", err)
	}
	if err := engine.StartUnhealthy(5); err != nil {
		t.Fatalf("Added: %v", err)
	}
	if mask, _ := engine.Snapshot(); mask != 0b1 {
		t.Fatalf("mask after Added = %#b, want 0b1", mask)
	}
	now := time.Unix(3000, 0)
	if err := engine.Sent(5, 1, now); err != nil {
		t.Fatalf("Sent: %v", err)
	}
	if _, _, err := engine.Reply(5, 1, now.Add(15*time.Millisecond)); err != nil {
		t.Fatalf("Reply: %v", err)
	}
	mask, generation := engine.Snapshot()
	if mask != 0b100001 {
		t.Fatalf("mask after reply = %#b, want 0b100001", mask)
	}
	health, err := engine.Path(5)
	if err != nil || !health.Healthy || health.RTT != 15*time.Millisecond || !health.LastReply.Equal(now.Add(15*time.Millisecond)) {
		t.Fatalf("Path(5) = %#v, %v", health, err)
	}

	transition, err := engine.Forget(5)
	if err != nil || !transition.Changed || transition.Generation != generation+1 {
		t.Fatalf("Removed = %#v, %v", transition, err)
	}
	if mask, _ := engine.Snapshot(); mask != 0b1 {
		t.Fatalf("mask after Removed = %#b, want 0b1", mask)
	}
	if transition, err := engine.Forget(5); err != nil || transition.Changed {
		t.Fatalf("second Removed = %#v, %v", transition, err)
	}
}
