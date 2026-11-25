//go:build linux

package dataplane

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/xshecan/mup/config"
)

// setPathLimitFields writes the limit bits and the balancer weight of a
// client path.
func setPathLimitFields(encoded *mupPathConfigV1, path PathSettings) {
	encoded.Limit = limitFlags(path.Limit)
	encoded.Weight = normalizeWeight(path.Weight)
}

// setEgressPathLimitFields writes the limit bits of an egress path of a
// client on a server.
func setEgressPathLimitFields(value *mupDownPathV1, limit RateLimit) {
	value.Limit = limitFlags(limit)
}

// setEgressGroupShares writes the weights, the flags and the preferred path of
// an egress group. Its limit mask comes from the runtime, which knows the
// limits of the egress paths.
func setEgressGroupShares(value *mupDownGroupV1, entry EgressGroupEntry) {
	value.Weights, value.Flags, value.Preferred = encodeGroupShares(entry)
}

// rateBucket returns a fresh bucket of a limit.
func rateBucket(limit RateLimit) mupRateBucketV1 {
	cost, burst := encodeRate(limit.BitsPerSecond)
	return mupRateBucketV1{CostQ16: cost, BurstNs: burst}
}

// sameBucketLimit reports whether a bucket has the cost and the burst of a
// fresh bucket of the same limit.
func sameBucketLimit(current, fresh mupRateBucketV1) bool {
	return current.CostQ16 == fresh.CostQ16 && current.BurstNs == fresh.BurstNs
}

type lookupUpdateMap interface {
	Lookup(key, valueOut interface{}) error
	Update(key, value interface{}, flags ebpf.MapUpdateFlags) error
}

// clientPathMaps are the maps of the client path slots that SetPath writes.
type clientPathMaps struct {
	paths          lookupUpdateMap
	returns        lookupUpdateMap
	ingressReflect configurationMap
	pathSrc        configurationMap
	buckets        lookupUpdateMap
}

// slotHoldsPath reports whether a client path slot holds the path already:
// the same destination, server port, transport, return IP or pool, and
// bridge. It also returns the limit bits of the slot.
func slotHoldsPath(maps clientPathMaps, slot int, path PathSettings) (bool, uint8, error) {
	encoded, err := encodePathSettings(slot, path)
	if err != nil {
		return false, 0, err
	}
	pathReturn, err := encodePathReturn(slot, path)
	if err != nil {
		return false, 0, err
	}
	var current mupPathConfigV1
	if err := maps.paths.Lookup(uint32(slot), &current); err != nil {
		return false, 0, fmt.Errorf("read client path %d: %w", slot, err)
	}
	var currentReturn mupPathReturnV1
	if err := maps.returns.Lookup(uint32(slot), &currentReturn); err != nil {
		return false, 0, fmt.Errorf("read return IP of client path %d: %w", slot, err)
	}
	same := current.DestinationIp != 0 &&
		current.DestinationIp == encoded.DestinationIp &&
		current.ServerPort == encoded.ServerPort &&
		current.Transport == encoded.Transport &&
		current.Bridge == encoded.Bridge &&
		currentReturn == pathReturn
	return same, current.Limit, nil
}

// setClientPath writes one client path slot. A slot that holds the same path
// already keeps its reflect members and the state of its limit, and gets only
// its new priority, weight, source, interface and limit. The bucket starts
// over when the limit changes. A new path on the slot clears the members and
// starts the buckets over. The buckets come before the path, so the program
// never applies a limit without its bucket.
func setClientPath(maps clientPathMaps, slot int, path PathSettings) error {
	if slot < 0 || slot >= config.MaxPaths {
		return fmt.Errorf("path slot %d is outside 0 to %d", slot, config.MaxPaths-1)
	}
	same, oldLimit, err := slotHoldsPath(maps, slot, path)
	if err != nil {
		return err
	}
	if maps.buckets != nil {
		if err := applyClientBuckets(maps.buckets, slot, same, oldLimit, path.Limit); err != nil {
			return err
		}
	}
	ingressReflect := maps.ingressReflect
	if same {
		ingressReflect = nil
	}
	return applyPath(maps.paths, maps.returns, ingressReflect, maps.pathSrc, slot, path)
}

// applyClientBuckets writes the buckets of a client path slot for limit. It
// keeps them when the slot holds the same path with the same limit, and a
// slot without a limit before and after needs no buckets.
func applyClientBuckets(buckets lookupUpdateMap, slot int, same bool, oldLimit uint8, limit RateLimit) error {
	flags := limitFlags(limit)
	if flags == 0 && oldLimit == 0 {
		return nil
	}
	pathIndex, memberBase := clientBucketIndexes(slot)
	fresh := rateBucket(limit)
	if same && flags == oldLimit {
		index := pathIndex
		if flags == limitFlagMember {
			index = memberBase
		}
		var current mupRateBucketV1
		if err := buckets.Lookup(index, &current); err != nil {
			return fmt.Errorf("read the bucket of client path %d: %w", slot, err)
		}
		if sameBucketLimit(current, fresh) {
			return nil
		}
	}
	var pathBucket, memberBucket mupRateBucketV1
	switch flags {
	case limitFlagPath:
		pathBucket = fresh
	case limitFlagMember:
		memberBucket = fresh
	}
	if err := buckets.Update(pathIndex, pathBucket, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update the bucket of client path %d: %w", slot, err)
	}
	for member := range uint32(MaxPool) {
		if err := buckets.Update(memberBase+member, memberBucket, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update the bucket of member %d of client path %d: %w", member, slot, err)
		}
	}
	return nil
}

// clearClientBuckets empties the buckets of a client path slot.
func clearClientBuckets(buckets configurationMap, slot int) error {
	pathIndex, memberBase := clientBucketIndexes(slot)
	if err := buckets.Update(pathIndex, mupRateBucketV1{}, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("clear the bucket of client path %d: %w", slot, err)
	}
	for member := range uint32(MaxPool) {
		if err := buckets.Update(memberBase+member, mupRateBucketV1{}, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("clear the bucket of member %d of client path %d: %w", member, slot, err)
		}
	}
	return nil
}

// applyConfiguredBuckets writes the buckets of every client path slot before
// a full client configuration. A slot that keeps its path and its limit keeps
// its bucket, as with SetPath.
func applyConfiguredBuckets(maps clientPathMaps, paths []PathSettings) error {
	for slot := range config.MaxPaths {
		if slot >= len(paths) {
			if err := clearClientBuckets(maps.buckets, slot); err != nil {
				return err
			}
			continue
		}
		same, oldLimit, err := slotHoldsPath(maps, slot, paths[slot])
		if err != nil {
			return err
		}
		if err := applyClientBuckets(maps.buckets, slot, same, oldLimit, paths[slot].Limit); err != nil {
			return err
		}
	}
	return nil
}

// rateBucketKey returns the key of a bucket of an egress path of a client on
// a server.
func rateBucketKey(path mupDownPathKeyV1, member uint32) mupRateBucketKeyV1 {
	return mupRateBucketKeyV1{Client: path.Client, PathId: path.PathId, Member: member}
}

// sameEgressPath reports whether two entries of server_down_paths are the same
// path with the same kind of limit. The members of a pool, the interface and
// the source range can change and the path stays the same.
func sameEgressPath(current, next mupDownPathV1) bool {
	return current.ServerIp == next.ServerIp &&
		current.ServerPort == next.ServerPort &&
		current.Transport == next.Transport &&
		current.Flags == next.Flags &&
		current.ReturnIp == next.ReturnIp &&
		current.LocalIp == next.LocalIp &&
		current.Limit == next.Limit
}

// applyEgressBuckets writes the buckets of an egress path of a client on a
// server before the path itself. It keeps them when the key holds the same
// path with the same limit already. It returns the members whose buckets the
// path no longer uses, which the caller deletes after the path.
func applyEgressBuckets(buckets lookupUpdateMap, key mupDownPathKeyV1, exists bool, current, next mupDownPathV1, limit RateLimit) ([]uint32, error) {
	fresh := rateBucket(limit)
	used := uint32(0)
	switch next.Limit {
	case limitFlagPath:
		used = 1
	case limitFlagMember:
		used = MaxPool
	}
	if exists && sameEgressPath(current, next) {
		if used == 0 {
			return nil, nil
		}
		var bucket mupRateBucketV1
		err := buckets.Lookup(rateBucketKey(key, 0), &bucket)
		if err == nil && sameBucketLimit(bucket, fresh) {
			return nil, nil
		}
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, fmt.Errorf("read the bucket of egress path %d: %w", key.PathId, err)
		}
	}
	for member := range used {
		if err := buckets.Update(rateBucketKey(key, member), fresh, ebpf.UpdateAny); err != nil {
			return nil, fmt.Errorf("update the bucket of member %d of egress path %d: %w", member, key.PathId, err)
		}
	}
	var stale []uint32
	for member := used; member < MaxPool; member++ {
		stale = append(stale, member)
	}
	return stale, nil
}

// deleteEgressBuckets removes the buckets of the members of an egress path.
func deleteEgressBuckets(buckets *ebpf.Map, key mupDownPathKeyV1, members []uint32) error {
	for _, member := range members {
		if err := deleteEntry(buckets, rateBucketKey(key, member)); err != nil {
			return fmt.Errorf("delete the bucket of member %d of egress path %d: %w", member, key.PathId, err)
		}
	}
	return nil
}

// allEgressMembers lists every member index of an egress path.
func allEgressMembers() []uint32 {
	members := make([]uint32, MaxPool)
	for member := range members {
		members[member] = uint32(member)
	}
	return members
}

// setEgressLimitBit records whether egress path pathID of a client has a
// limit, and writes the new limit mask into the egress groups of the client
// when it changed. The caller holds r.mu.
func (r *Runtime) setEgressLimitBit(client ClientKey, pathID uint16, limited bool) error {
	if r.egressLimits == nil {
		r.egressLimits = make(map[ClientKey]uint8)
	}
	before := r.egressLimits[client]
	after := before &^ (1 << pathID)
	if limited {
		after |= 1 << pathID
	}
	if after == 0 {
		delete(r.egressLimits, client)
	} else {
		r.egressLimits[client] = after
	}
	if after == before {
		return nil
	}
	encoded, err := encodeClientKey(client)
	if err != nil {
		return err
	}
	groups, err := mapEntries[mupDownGroupKeyV1, mupDownGroupV1](r.objects.ServerDownGroups)
	if err != nil && !errors.Is(err, ebpf.ErrIterationAborted) {
		return fmt.Errorf("list egress groups: %w", err)
	}
	for key, group := range groups {
		if key.Client != encoded || group.LimitMask == after&group.PathMask {
			continue
		}
		group.LimitMask = after & group.PathMask
		if err := r.objects.ServerDownGroups.Update(key, group, ebpf.UpdateExist); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("update the limits of the egress group of %s on listen port %d: %w", client.AdvertisedIP, key.ListenPort, err)
		}
	}
	return nil
}
