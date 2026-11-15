//go:build linux

package app

import (
	"context"
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
	// reflectorMaxSweep caps how many addresses one sweep pings, so a wide
	// prefix does not flood the range.
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

func (p *reflectorProber) probeAll(ctx context.Context) error {
	pools := p.runtime.Pools()
	if len(pools) == 0 {
		return nil
	}
	connection, err := net.ListenIP("ip4:icmp", &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		return fmt.Errorf("listen ICMP: %w", err)
	}
	defer connection.Close()
	for _, pool := range pools {
		if err := p.probePool(ctx, connection, pool); err != nil {
			return err
		}
	}
	return nil
}

func (p *reflectorProber) probePool(ctx context.Context, connection *net.IPConn, pool dataplane.PoolInfo) error {
	candidates, err := dataplane.PoolCandidates(pool.Base, pool.Prefix, reflectorMaxSweep)
	if err != nil {
		return err
	}
	responders := p.sweep(ctx, connection, candidates)
	state := p.states[pool.Key()]
	if state == nil {
		state = newPoolProbeState()
		p.states[pool.Key()] = state
	}
	members, healthy := state.update(responders, pool.Transport)
	return p.runtime.SetPool(pool.Key(), members, healthy)
}

// sweep pings every candidate once and returns the set of addresses that
// answered within the window.
func (p *reflectorProber) sweep(ctx context.Context, connection *net.IPConn, candidates []netip.Addr) map[netip.Addr]bool {
	p.seq++
	sequence := p.seq
	payload := []byte("mup-reflector-probe")
	for _, address := range candidates {
		echo := marshalICMPEcho(icmpEchoRequest, reflectorProbeID, sequence, payload)
		_, _ = connection.WriteToIP(echo, &net.IPAddr{IP: address.AsSlice()})
	}
	responders := make(map[netip.Addr]bool, len(candidates))
	deadline := time.Now().Add(reflectorProbeWindow)
	buffer := make([]byte, 1500)
	for {
		if ctx.Err() != nil {
			return responders
		}
		_ = connection.SetReadDeadline(deadline)
		count, source, err := connection.ReadFromIP(buffer)
		if err != nil {
			break
		}
		echo, err := parseICMPEcho(stripIPv4Header(buffer[:count]))
		if err != nil || echo.echoType != icmpEchoReply ||
			echo.identifier != reflectorProbeID || echo.sequence != sequence {
			continue
		}
		if address, ok := netip.AddrFromSlice(source.IP.To4()); ok {
			responders[address.Unmap()] = true
		}
	}
	return responders
}
