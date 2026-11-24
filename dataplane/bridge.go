package dataplane

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/xshecan/mup/config"
)

// MaxBridgeAddresses is the number of local addresses that a bridge takes
// packets on. It mirrors the size of the bridge_addresses map.
const MaxBridgeAddresses = 64

// MaxBridges is the number of entries of a bridge. It mirrors the size of the
// bridge_config map and must equal config.MaxBridges.
const MaxBridges = 8

// The array length is negative, and the build fails, when the two limits
// differ.
var _ [MaxBridges - config.MaxBridges]struct{}
var _ [config.MaxBridges - MaxBridges]struct{}

// BridgeSettings is the configuration of a bridge: its entries, and the
// addresses of the host.
type BridgeSettings struct {
	Entries   []BridgeEntry
	Addresses []netip.Addr
}

// BridgeEntry is one entry of a bridge: its server, its ports, and the extra
// sender ranges of wrapped replies.
type BridgeEntry struct {
	Server netip.Addr
	Ports  config.PortRange
	Allow  []netip.Prefix
}

// BridgeCounters counts the packets and bytes that a bridge sends in each
// direction.
type BridgeCounters struct {
	IngressPackets uint64
	IngressBytes   uint64
	EgressPackets  uint64
	EgressBytes    uint64
}

// encodeBridgeConfigs returns the bridge_config values: entry i at index i,
// and a zero value, which the program skips, at every other index.
func encodeBridgeConfigs(settings BridgeSettings) ([MaxBridges]mupBridgeConfigV1, error) {
	var configurations [MaxBridges]mupBridgeConfigV1
	if err := checkBridgeEntries(settings); err != nil {
		return configurations, err
	}
	for index, entry := range settings.Entries {
		server, err := requiredIPv4Word(entry.Server, "bridge server")
		if err != nil {
			return configurations, err
		}
		if entry.Ports.First == 0 || entry.Ports.Last < entry.Ports.First {
			return configurations, errors.New("bridge ports must be a range between 1 and 65535")
		}
		configurations[index] = mupBridgeConfigV1{ServerIp: server, PortFirst: entry.Ports.First, PortLast: entry.Ports.Last}
	}
	return configurations, nil
}

func checkBridgeEntries(settings BridgeSettings) error {
	if len(settings.Entries) == 0 {
		return errors.New("a bridge needs at least one entry")
	}
	if len(settings.Entries) > MaxBridges {
		return fmt.Errorf("a bridge has at most %d entries, not %d", MaxBridges, len(settings.Entries))
	}
	return nil
}

// bridgeSenders returns the LPM keys of the senders of wrapped replies. Each
// entry adds its server as a /32, then its allow ranges, under its own index.
// The index fills the first 32 bits of the LPM data, so a sender prefix of N
// bits has a prefix length of 32 + N.
func bridgeSenders(settings BridgeSettings) ([]mupBridgeAllowKeyV1, error) {
	if err := checkBridgeEntries(settings); err != nil {
		return nil, err
	}
	var keys []mupBridgeAllowKeyV1
	for index, entry := range settings.Entries {
		server, err := requiredIPv4Word(entry.Server, "bridge server")
		if err != nil {
			return nil, err
		}
		keys = append(keys, mupBridgeAllowKeyV1{Prefixlen: 64, Bridge: uint32(index), Address: server})
		for _, prefix := range entry.Allow {
			if !prefix.IsValid() || !prefix.Addr().Is4() {
				return nil, fmt.Errorf("bridge allow range %s is not an IPv4 CIDR", prefix)
			}
			masked := prefix.Masked()
			if masked.Bits() == 0 {
				return nil, errors.New("a bridge allow range of 0.0.0.0/0 lets any host use the bridge")
			}
			address, err := requiredIPv4Word(masked.Addr(), "bridge allow range")
			if err != nil {
				return nil, err
			}
			keys = append(keys, mupBridgeAllowKeyV1{Prefixlen: 32 + uint32(masked.Bits()), Bridge: uint32(index), Address: address})
		}
	}
	return keys, nil
}
