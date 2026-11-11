package dataplane

import "testing"

func TestClassifyPoolPreservesFreeUsedAndQuarantinesLost(t *testing.T) {
	t.Parallel()

	available, lost, err := classifyPool(
		[]uint32{1, 2, 3, 4},
		map[uint32]struct{}{1: {}, 4: {}},
		map[uint32]struct{}{2: {}},
	)
	if err != nil {
		t.Fatalf("classifyPool: %v", err)
	}
	if len(available) != 2 || available[0] != 1 || available[1] != 4 {
		t.Fatalf("available = %v", available)
	}
	if len(lost) != 1 || lost[0] != 3 {
		t.Fatalf("lost = %v", lost)
	}
}

func TestClassifyPoolRejectsFreeResourceStillInUse(t *testing.T) {
	t.Parallel()

	_, _, err := classifyPool(
		[]uint16{20000},
		map[uint16]struct{}{20000: {}},
		map[uint16]struct{}{20000: {}},
	)
	if err == nil {
		t.Fatal("overlapping free and used resource unexpectedly accepted")
	}
}

func TestClassifyPairsFindsBrokenDirections(t *testing.T) {
	t.Parallel()

	invalidForward, invalidReverse := classifyPairs(
		map[string]uint32{
			"valid":           1,
			"missing-reverse": 2,
			"wrong-reverse":   3,
		},
		map[uint32]string{
			1: "valid",
			3: "other",
			4: "missing-forward",
		},
	)
	if !sameSet(invalidForward, []string{"missing-reverse", "wrong-reverse"}) {
		t.Fatalf("invalid forward = %v", invalidForward)
	}
	if !sameSet(invalidReverse, []uint32{3, 4}) {
		t.Fatalf("invalid reverse = %v", invalidReverse)
	}
}

func sameSet[T comparable](got, want []T) bool {
	if len(got) != len(want) {
		return false
	}
	values := make(map[T]int, len(got))
	for _, value := range got {
		values[value]++
	}
	for _, value := range want {
		values[value]--
	}
	for _, count := range values {
		if count != 0 {
			return false
		}
	}
	return true
}
