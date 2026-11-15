//go:build linux

package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/xshecan/mup/dataplane"
)

const (
	reflectorProbeInterval = 2 * time.Second
	reflectorProbeWindow   = time.Second
	// reflectorMaxSweep caps how many addresses one sweep pings in each pool,
	// so a wide prefix does not flood the range.
	reflectorMaxSweep = 1024
	reflectorProbeID  = 0x4d50
)

// reflectorRuntime is the part of the dataplane that the prober uses.
type reflectorRuntime interface {
	Pools() []dataplane.PoolInfo
	SetPool(key dataplane.PoolKey, addresses []netip.Addr, healthy []bool) error
}

// reflectorProber pings the whole range of each return pool, pools the live
// hosts, and writes their health to the dataplane.
type reflectorProber struct {
	runtime reflectorRuntime
	states  map[dataplane.PoolKey]*poolProbeState
	seq     uint16
}

func newReflectorProbeLoop(runtime *dataplane.Runtime) loop {
	prober := &reflectorProber{runtime: runtime, states: make(map[dataplane.PoolKey]*poolProbeState)}
	return prober.run
}

func (p *reflectorProber) run(ctx context.Context) error {
	ticker := time.NewTicker(reflectorProbeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := p.probeAll(ctx); err != nil && ctx.Err() == nil {
				log.Printf("mup reflector probe: %v", err)
			}
		}
	}
}

// probeAll pings the candidates of every pool in one sweep, so one cycle takes
// one probe window for any number of pools. A UDP pool and an ICMP pool of the
// same range share their pings.
func (p *reflectorProber) probeAll(ctx context.Context) error {
	pools := p.runtime.Pools()
	if len(pools) == 0 {
		return nil
	}
	candidates := make(map[dataplane.PoolKey][]netip.Addr, len(pools))
	seen := make(map[netip.Addr]bool)
	var all []netip.Addr
	for _, pool := range pools {
		addresses, err := dataplane.PoolCandidates(pool.Base, pool.Prefix, reflectorMaxSweep)
		if err != nil {
			return err
		}
		candidates[pool.Key()] = addresses
		for _, address := range addresses {
			if !seen[address] {
				seen[address] = true
				all = append(all, address)
			}
		}
	}
	connection, err := net.ListenIP("ip4:icmp", &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		return fmt.Errorf("listen ICMP: %w", err)
	}
	defer connection.Close()
	p.seq++
	responders := sweepEcho(ctx, connection, all, reflectorProbeID, p.seq, reflectorProbeWindow)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var errs []error
	for _, pool := range pools {
		state := p.states[pool.Key()]
		if state == nil {
			state = newPoolProbeState()
			p.states[pool.Key()] = state
		}
		members, healthy := state.update(poolResponders(responders, pool), pool.Transport, candidates[pool.Key()])
		if err := p.runtime.SetPool(pool.Key(), members, healthy); err != nil {
			errs = append(errs, err)
			continue
		}
		if live, changed := state.liveChanged(); changed {
			log.Printf("mup reflector pool %s/%d %s: %d of %d addresses answer ping, %d members",
				pool.Base, pool.Prefix, pool.Transport, live, len(candidates[pool.Key()]), len(members))
		}
	}
	return errors.Join(errs...)
}

// sweepEcho sends one Echo Request to every candidate and returns the set of
// addresses that answered within the window. ReadFromIP returns an ip4 packet
// without its IPv4 header, because the net package strips it. ReadMsgIP keeps
// the header, so only the ReadMsgIP callers strip it themselves.
func sweepEcho(ctx context.Context, connection *net.IPConn, candidates []netip.Addr,
	identifier, sequence uint16, window time.Duration,
) map[netip.Addr]bool {
	request := marshalICMPEcho(icmpEchoRequest, identifier, sequence, []byte("mup-reflector-probe"))
	for _, address := range candidates {
		_, _ = connection.WriteToIP(request, &net.IPAddr{IP: address.AsSlice()})
	}
	responders := make(map[netip.Addr]bool, len(candidates))
	deadline := time.Now().Add(window)
	buffer := make([]byte, 1500)
	for ctx.Err() == nil {
		_ = connection.SetReadDeadline(deadline)
		count, source, err := connection.ReadFromIP(buffer)
		if err != nil {
			break
		}
		echo, err := parseICMPEcho(buffer[:count])
		if err != nil || echo.echoType != icmpEchoReply ||
			echo.identifier != identifier || echo.sequence != sequence {
			continue
		}
		if address, ok := netip.AddrFromSlice(source.IP.To4()); ok {
			responders[address.Unmap()] = true
		}
	}
	return responders
}
