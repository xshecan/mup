package dataplane

import (
	"testing"

	"github.com/xshecan/mup/protocol"
)

func TestPeerTokenPoolCoversV1RangeExactlyOnce(t *testing.T) {
	t.Parallel()

	pool := peerTokenPool()
	if len(pool) != int(protocol.MaxPeerToken) {
		t.Fatalf("pool length = %d, want %d", len(pool), protocol.MaxPeerToken)
	}
	seen := make(map[uint32]struct{}, len(pool))
	for _, token := range pool {
		if token == 0 || token > protocol.MaxPeerToken {
			t.Fatalf("out-of-range token %d", token)
		}
		if _, duplicate := seen[token]; duplicate {
			t.Fatalf("duplicate token %d", token)
		}
		seen[token] = struct{}{}
	}
}

func TestTargetPortPoolCoversConfiguredRangeExactlyOnce(t *testing.T) {
	t.Parallel()

	pool := targetPortPool()
	if len(pool) != 41000 {
		t.Fatalf("pool length = %d, want 41000", len(pool))
	}
	for index, port := range pool {
		want := uint16(20000 + index)
		if port != want {
			t.Fatalf("pool[%d] = %d, want %d", index, port, want)
		}
	}
}
