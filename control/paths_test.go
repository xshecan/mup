package control

import (
	"reflect"
	"testing"

	"github.com/xshecan/mup/config"
)

func TestSelectPathsFallbackUsesLowestPriority(t *testing.T) {
	t.Parallel()

	got := SelectPaths(config.ModeFallback, 17, []uint8{20, 5, 10}, 0b111)
	if !reflect.DeepEqual(got, []int{1}) {
		t.Fatalf("fallback selection = %v, want [1]", got)
	}
}

func TestSelectPathsBurstReturnsEveryHealthyPath(t *testing.T) {
	t.Parallel()

	got := SelectPaths(config.ModeBurst, 17, []uint8{0, 1, 2, 3}, 0b1011)
	if !reflect.DeepEqual(got, []int{0, 1, 3}) {
		t.Fatalf("burst selection = %v, want [0 1 3]", got)
	}
}

func TestSelectPathsBalancerIsStableAndHealthy(t *testing.T) {
	t.Parallel()

	priorities := []uint8{0, 1, 2, 3}
	first := SelectPaths(config.ModeBalancer, 123, priorities, 0b1010)
	second := SelectPaths(config.ModeBalancer, 123, priorities, 0b1010)
	if !reflect.DeepEqual(first, second) || len(first) != 1 {
		t.Fatalf("balancer is not stable: %v and %v", first, second)
	}
	if first[0] != 1 && first[0] != 3 {
		t.Fatalf("balancer selected unhealthy path %d", first[0])
	}
	if got := SelectPaths(config.ModeBalancer, 123, priorities, 0); got != nil {
		t.Fatalf("no-health selection = %v, want nil", got)
	}
}
