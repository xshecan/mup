package dataplane

import "fmt"

func classifyPairs[K, R comparable](
	forward map[K]R,
	reverse map[R]K,
) (invalidForward []K, invalidReverse []R) {
	for key, resource := range forward {
		reverseKey, exists := reverse[resource]
		if !exists || reverseKey != key {
			invalidForward = append(invalidForward, key)
		}
	}
	for resource, key := range reverse {
		forwardResource, exists := forward[key]
		if !exists || forwardResource != resource {
			invalidReverse = append(invalidReverse, resource)
		}
	}
	return invalidForward, invalidReverse
}

func classifyPool[T uint16 | uint32](
	all []T,
	free map[T]struct{},
	used map[T]struct{},
) (available []T, lost []T, err error) {
	known := make(map[T]struct{}, len(all))
	for _, value := range all {
		known[value] = struct{}{}
		_, isFree := free[value]
		_, isUsed := used[value]
		if isFree && isUsed {
			return nil, nil, fmt.Errorf("resource %d is both free and used", value)
		}
		if isFree {
			available = append(available, value)
		} else if !isUsed {
			lost = append(lost, value)
		}
	}
	for value := range free {
		if _, exists := known[value]; !exists {
			return nil, nil, fmt.Errorf("free resource %d is outside the pool", value)
		}
	}
	for value := range used {
		if _, exists := known[value]; !exists {
			return nil, nil, fmt.Errorf("used resource %d is outside the pool", value)
		}
	}
	return available, lost, nil
}
