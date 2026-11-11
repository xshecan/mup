//go:build linux

package dataplane

import "testing"

func TestValidateIfindexes(t *testing.T) {
	t.Parallel()

	if got, err := validateIfindexes([]int{2, 5}); err != nil || len(got) != 2 || got[0] != 2 || got[1] != 5 {
		t.Fatalf("validateIfindexes valid = %v, %v", got, err)
	}
	for _, input := range [][]int{nil, {0}, {-1}, {2, 2}} {
		if _, err := validateIfindexes(input); err == nil {
			t.Fatalf("validateIfindexes(%v) unexpectedly succeeded", input)
		}
	}
}
