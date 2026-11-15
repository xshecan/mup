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
	"github.com/xshecan/mup/protocol"
)

const (
	reflectorProbeInterval = 2 * time.Second
	reflectorProbeWindow   = time.Second
	// reflectorMissThreshold marks a reflector unhealthy after this many
	// probes in a row without a reply.
	reflectorMissThreshold = 3
	reflectorProbeID       = 0x4d50
)

// reflectorRuntime is the part of the dataplane that the prober uses.
type reflectorRuntime interface {
	Pools() []dataplane.PoolInfo
	SetPoolHealth(key dataplane.PoolKey, healthy []bool) error
}

// reflectorProber pings the members of each ICMP return pool and writes their
// health to the dataplane. A UDP pool has no host to ping, so the prober leaves
// it healthy.
type reflectorProber struct {
	runtime reflectorRuntime
	misses  map[netip.Addr]int
	seq     uint16
}

func newReflectorProbeLoop(runtime *dataplane.Runtime) loop {
	prober := &reflectorProber{runtime: runtime, misses: make(map[netip.Addr]int)}
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
	var pools []dataplane.PoolInfo
	for _, pool := range p.runtime.Pools() {
		if pool.Transport == protocol.TransportICMP {
			pools = append(pools, pool)
		}
	}
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
	p.seq++
	sequence := p.seq
	payload := []byte("mup-reflector-probe")
	for _, address := range pool.Addresses {
		echo := marshalICMPEcho(icmpEchoRequest, reflectorProbeID, sequence, payload)
		_, _ = connection.WriteToIP(echo, &net.IPAddr{IP: address.AsSlice()})
	}
	responded := make(map[netip.Addr]bool, len(pool.Addresses))
	deadline := time.Now().Add(reflectorProbeWindow)
	buffer := make([]byte, 1500)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
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
			responded[address.Unmap()] = true
		}
	}
	healthy := make([]bool, len(pool.Addresses))
	for index, address := range pool.Addresses {
		if responded[address] {
			p.misses[address] = 0
			healthy[index] = true
		} else {
			p.misses[address]++
			healthy[index] = p.misses[address] < reflectorMissThreshold
		}
	}
	return p.runtime.SetPoolHealth(pool.Key(), healthy)
}
