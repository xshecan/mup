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

// BridgeSettings is the configuration of a bridge: its server, its ports, the
// extra sender ranges of wrapped replies, and the addresses of the host.
type BridgeSettings struct {
	Server    netip.Addr
	Ports     config.PortRange
	Allow     []netip.Prefix
	Addresses []netip.Addr
}

// BridgeCounters counts the packets and bytes that a bridge sends in each
// direction.
type BridgeCounters struct {
	UpPackets   uint64
	UpBytes     uint64
	DownPackets uint64
	DownBytes   uint64
}

func encodeBridgeConfig(settings BridgeSettings) (mupBridgeConfigV1, error) {
	server, err := requiredIPv4Word(settings.Server, "bridge server")
	if err != nil {
		return mupBridgeConfigV1{}, err
	}
	if settings.Ports.First == 0 || settings.Ports.Last < settings.Ports.First {
		return mupBridgeConfigV1{}, errors.New("bridge ports must be a range between 1 and 65535")
	}
	return mupBridgeConfigV1{ServerIp: server, PortFirst: settings.Ports.First, PortLast: settings.Ports.Last}, nil
}

// bridgeSenders returns the LPM keys of the senders of wrapped replies: the
// server, then the allow ranges.
func bridgeSenders(settings BridgeSettings) ([]mupBridgeAllowKeyV1, error) {
	server, err := requiredIPv4Word(settings.Server, "bridge server")
	if err != nil {
		return nil, err
	}
	keys := []mupBridgeAllowKeyV1{{Prefixlen: 32, Address: server}}
	for _, prefix := range settings.Allow {
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
		keys = append(keys, mupBridgeAllowKeyV1{Prefixlen: uint32(masked.Bits()), Address: address})
	}
	return keys, nil
}
