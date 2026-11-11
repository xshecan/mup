package protocol

import "testing"

func TestDuplicateIdentityChangesWithWireGuardCounter(t *testing.T) {
	t.Parallel()

	first := make([]byte, TransportDataMinLength)
	first[0] = MessageTransportData
	first[3] = 1
	second := append([]byte(nil), first...)
	second[11] = 1

	firstIdentity, err := DuplicateIdentity(first)
	if err != nil {
		t.Fatalf("first DuplicateIdentity: %v", err)
	}
	secondIdentity, err := DuplicateIdentity(second)
	if err != nil {
		t.Fatalf("second DuplicateIdentity: %v", err)
	}
	if firstIdentity == secondIdentity {
		t.Fatal("different WireGuard counters produced the same identity")
	}
}
