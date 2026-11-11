package dataplane

import "time"

// resourceQuarantine holds released values until late packets for their old
// routes can no longer arrive. A value is held at most once, so it cannot be
// pushed into its free queue twice.
type resourceQuarantine[T uint16 | uint32] struct {
	releaseAt map[T]time.Duration
}

func (q *resourceQuarantine[T]) Add(value T, now, delay time.Duration) {
	if q.releaseAt == nil {
		q.releaseAt = make(map[T]time.Duration)
	}
	releaseAt := now + delay
	if current, exists := q.releaseAt[value]; !exists || current < releaseAt {
		q.releaseAt[value] = releaseAt
	}
}

// Release passes every value whose delay has passed to release and forgets
// it. It stops at the first error and keeps the failed value.
func (q *resourceQuarantine[T]) Release(now time.Duration, release func(T) error) error {
	for value, releaseAt := range q.releaseAt {
		if releaseAt > now {
			continue
		}
		if err := release(value); err != nil {
			return err
		}
		delete(q.releaseAt, value)
	}
	return nil
}

func (q *resourceQuarantine[T]) Len() int {
	return len(q.releaseAt)
}

func (q *resourceQuarantine[T]) Values() map[T]struct{} {
	values := make(map[T]struct{}, len(q.releaseAt))
	for value := range q.releaseAt {
		values[value] = struct{}{}
	}
	return values
}
