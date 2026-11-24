package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/xshecan/mup/api"
	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
)

// bridgeAddressInterval is the time between two reads of the host addresses.
const bridgeAddressInterval = 10 * time.Second

type bridgeDataplane interface {
	Snapshot() (dataplane.StatsSnapshot, error)
	BridgeCounters() (dataplane.BridgeCounters, error)
	SetBridgeAddresses([]netip.Addr) error
}

// bridgeInspector answers the API calls of a bridge.
type bridgeInspector struct {
	entries   []config.Bridge
	dataplane bridgeDataplane
	startedAt time.Time
	addresses func() ([]netip.Addr, error)
	interval  time.Duration
}

func newBridgeInspector(entries []config.Bridge, plane bridgeDataplane, startedAt time.Time) *bridgeInspector {
	return &bridgeInspector{
		entries:   entries,
		dataplane: plane,
		startedAt: startedAt,
		addresses: hostIPv4Addresses,
		interval:  bridgeAddressInterval,
	}
}

func (b *bridgeInspector) Status() (api.Status, error) {
	snapshot, err := b.dataplane.Snapshot()
	if err != nil {
		return api.Status{}, err
	}
	counters, err := b.dataplane.BridgeCounters()
	if err != nil {
		return api.Status{}, err
	}
	status := &api.BridgeStatus{
		IngressPackets: counters.IngressPackets,
		IngressBytes:   counters.IngressBytes,
		EgressPackets:  counters.EgressPackets,
		EgressBytes:    counters.EgressBytes,
	}
	for _, entry := range b.entries {
		entryStatus := api.BridgeEntryStatus{Server: entry.Server.String(), Port: entry.Port.First, PortLast: entry.Port.Last}
		for _, prefix := range entry.Allow {
			entryStatus.Allow = append(entryStatus.Allow, prefix.String())
		}
		status.Entries = append(status.Entries, entryStatus)
	}
	// The top-level fields show the first entry, so an older mupctl still
	// shows a bridge.
	if len(status.Entries) > 0 {
		first := status.Entries[0]
		status.Server, status.Port, status.PortLast, status.Allow = first.Server, first.Port, first.PortLast, first.Allow
	}
	if addresses, err := b.addresses(); err == nil {
		for _, address := range addresses {
			status.Addresses = append(status.Addresses, address.String())
		}
	}
	return api.Status{Role: api.RoleBridge, StartedAt: b.startedAt, Bridge: status, Drops: apiDrops(snapshot)}, nil
}

// refreshAddresses writes the addresses of the host to the dataplane every
// 10 seconds, so the bridge follows an address that the host gains or loses.
func (b *bridgeInspector) refreshAddresses(ctx context.Context, logger *log.Logger) error {
	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()
	var last []netip.Addr
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		addresses, err := b.addresses()
		if err != nil {
			logger.Printf("mup bridge: read the host addresses: %v", err)
			continue
		}
		if slices.Equal(addresses, last) {
			continue
		}
		if err := b.dataplane.SetBridgeAddresses(addresses); err != nil {
			logger.Printf("mup bridge: write the host addresses: %v", err)
			continue
		}
		last = addresses
	}
}

// hostIPv4Addresses returns the IPv4 addresses of the host, sorted.
func hostIPv4Addresses() ([]netip.Addr, error) {
	interfaceAddresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var addresses []netip.Addr
	for _, interfaceAddress := range interfaceAddresses {
		prefix, err := netip.ParsePrefix(interfaceAddress.String())
		if err != nil || !prefix.Addr().Is4() || prefix.Addr().IsLoopback() {
			continue
		}
		addresses = append(addresses, prefix.Addr())
	}
	slices.SortFunc(addresses, netip.Addr.Compare)
	return slices.Compact(addresses), nil
}

// errForwardingOff stops a bridge on a host without IPv4 forwarding. The
// bridge program uses the FIB lookup of a forwarded packet, which fails
// there.
var errForwardingOff = errors.New("the bridge needs IPv4 forwarding: set net.ipv4.ip_forward=1")

// checkForwarding reads the IPv4 forwarding switch of the host. A host that
// does not show the switch passes.
func checkForwarding(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if strings.TrimSpace(string(content)) == "0" {
		return errForwardingOff
	}
	return nil
}

// bridgeSettings builds the dataplane settings of a bridge, with the current
// addresses of the host.
func bridgeSettings(entries []config.Bridge, addresses []netip.Addr) dataplane.BridgeSettings {
	settings := dataplane.BridgeSettings{Addresses: addresses}
	for _, entry := range entries {
		settings.Entries = append(settings.Entries, dataplane.BridgeEntry{
			Server: entry.Server,
			Ports:  entry.Port,
			Allow:  entry.Allow,
		})
	}
	return settings
}

func describeBridge(bridge config.Bridge) string {
	return fmt.Sprintf("server %s, ports %s", bridge.Server, bridge.Port)
}
