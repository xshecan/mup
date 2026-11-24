package app

import (
	"net/netip"
	"slices"
	"time"
)

// reflectMemberSet tracks the candidate members of an ingress reflect path across
// rounds. A member stays published while it missed fewer than missLimit rounds
// in a row since its last answer, so one lost answer does not remove it.
type reflectMemberSet struct {
	candidates []netip.Addr
	answered   []bool
	misses     []int
}

func newReflectMemberSet(candidates []netip.Addr) *reflectMemberSet {
	return &reflectMemberSet{
		candidates: candidates,
		answered:   make([]bool, len(candidates)),
		misses:     make([]int, len(candidates)),
	}
}

// round records the members that answered in one round. It returns the published
// members in candidate order, and whether a published member is pending, which
// means that it missed at least one round since its last answer.
func (s *reflectMemberSet) round(answers []netip.Addr) ([]netip.Addr, bool) {
	var published []netip.Addr
	pending := false
	for index, candidate := range s.candidates {
		if slices.Contains(answers, candidate) {
			s.answered[index] = true
			s.misses[index] = 0
		} else if s.misses[index] < missLimit {
			s.misses[index]++
		}
		if !s.answered[index] || s.misses[index] >= missLimit {
			continue
		}
		published = append(published, candidate)
		if s.misses[index] > 0 {
			pending = true
		}
	}
	return published, pending
}

// reflectRegistrationDelay returns the wait before the next round of an ingress
// reflect path. A round with a pending member comes again soon, so a dead member
// leaves the list within a few seconds.
func reflectRegistrationDelay(acked, pending bool) time.Duration {
	return registrationDelay(acked && !pending)
}
