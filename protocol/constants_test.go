package protocol

import "testing"

func TestDropReasonABI(t *testing.T) {
	t.Parallel()

	want := []DropReason{
		DropNone,
		DropMalformedIPv4,
		DropIPv4Options,
		DropIPv4Fragment,
		DropMalformedL4,
		DropWireGuardType,
		DropWireGuardLength,
		DropWireGuardReserved,
		DropNotRegistered,
		DropPathMismatch,
		DropTransport,
		DropPeerTokenPool,
		DropTargetPortPool,
		DropMapInvariant,
		DropRouteMiss,
		DropNoPath,
		DropDuplicate,
		DropFIB,
		DropNeighbor,
		DropTailCall,
		DropChecksum,
		DropSourceLimit,
		DropDownstreamSource,
	}
	for number, reason := range want {
		if got := uint32(reason); got != uint32(number) {
			t.Fatalf("drop reason at index %d has ABI number %d", number, got)
		}
	}
}

func TestDropReasonNamesMatchTheABI(t *testing.T) {
	t.Parallel()

	if got := DropDownstreamSource.String(); got != "DOWNSTREAM_SOURCE" {
		t.Fatalf("DropDownstreamSource = %q", got)
	}
	if got := DropNoPath.String(); got != "NO_PATH" {
		t.Fatalf("DropNoPath = %q", got)
	}
	if got := DropReason(99).String(); got != "REASON_99" {
		t.Fatalf("unknown reason = %q", got)
	}
	for reason := DropNone; reason <= DropDownstreamSource; reason++ {
		if reason.String() == "" {
			t.Fatalf("reason %d has no name", reason)
		}
	}
}
