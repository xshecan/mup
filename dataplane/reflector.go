package dataplane

import (
	"fmt"
	"net/netip"

	"github.com/xshecan/mup/protocol"
)

// MaxPool is the largest number of addresses in a return pool. It mirrors
// MUP_MAX_POOL in bpf/include/mup_abi.h.
const MaxPool = 16

// PoolKey names a return pool. A UDP route and an ICMP route can use the same
// range, and each has its own pool and health.
type PoolKey struct {
	Base      netip.Addr
	Transport protocol.TransportID
}

// Key returns the key of the pool.
func (p PoolInfo) Key() PoolKey {
	return PoolKey{Base: p.Base, Transport: p.Transport}
}

// PoolInfo describes a return pool that the server observed from a
// registration. The prober uses it to ping the members of an ICMP pool.
type PoolInfo struct {
	Base      netip.Addr
	Prefix    uint8
	Transport protocol.TransportID
	Addresses []netip.Addr
}

// Reflector is one address of a return pool, with its current health. The
// reflector view of mupctl shows these.
type Reflector struct {
	Base      netip.Addr
	Prefix    uint8
	Transport protocol.TransportID
	Address   netip.Addr
	Healthy   bool
}

// PoolCandidates returns the host addresses of a pool range in order, up to max
// addresses. The network and broadcast addresses are not hosts, except in a /31
// (RFC 3021). The prober pings them to discover which reflectors are live. A
// max of zero returns no addresses.
func PoolCandidates(base netip.Addr, prefix uint8, max int) ([]netip.Addr, error) {
	if !base.Is4() {
		return nil, fmt.Errorf("pool base %s must be IPv4", base)
	}
	if prefix < 1 || prefix > 31 {
		return nil, fmt.Errorf("pool prefix %d must be between 1 and 31", prefix)
	}
	if max <= 0 {
		return nil, nil
	}
	address := base.Next()
	count := uint64(1)<<(32-prefix) - 2
	if prefix == 31 {
		address = base
		count = 2
	}
	if count > uint64(max) {
		count = uint64(max)
	}
	addresses := make([]netip.Addr, 0, count)
	for index := uint64(0); index < count; index++ {
		addresses = append(addresses, address)
		address = address.Next()
	}
	return addresses, nil
}

// poolAddresses returns the first addresses of the pool, after the network
// base. It returns at most MaxPool addresses, for the bootstrap of a pool
// before the prober discovers its live members.
func poolAddresses(base netip.Addr, prefix uint8) ([]netip.Addr, error) {
	return PoolCandidates(base, prefix, MaxPool)
}

// encodeReflectorPool builds the map value of a pool. A nil healthy slice marks
// every address healthy. Bit index of the healthy mask matches the address at
// the same index.
func encodeReflectorPool(addresses []netip.Addr, healthy []bool) (mupReflectorPoolV1, error) {
	var pool mupReflectorPoolV1
	if len(addresses) == 0 || len(addresses) > MaxPool {
		return pool, fmt.Errorf("pool needs between 1 and %d addresses, got %d", MaxPool, len(addresses))
	}
	pool.Count = uint32(len(addresses))
	for index, address := range addresses {
		word, err := requiredIPv4Word(address, "pool address")
		if err != nil {
			return pool, err
		}
		pool.Addresses[index] = word
		if healthy == nil || healthy[index] {
			pool.HealthyMask |= uint64(1) << uint(index)
		}
	}
	return pool, nil
}

// poolHasHealthy reports whether a pool value has a healthy member among its
// first count addresses, as the server program reads it.
func poolHasHealthy(pool mupReflectorPoolV1) bool {
	if pool.Count == 0 || pool.Count > MaxPool {
		return false
	}
	return pool.HealthyMask&(uint64(1)<<pool.Count-1) != 0
}

// reflectorKey builds the map key of a pool.
func reflectorKey(key PoolKey) (mupReflectorKeyV1, error) {
	base, err := requiredIPv4Word(key.Base, "pool base")
	if err != nil {
		return mupReflectorKeyV1{}, err
	}
	return mupReflectorKeyV1{Base: base, Transport: uint8(key.Transport)}, nil
}
