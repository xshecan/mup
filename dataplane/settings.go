package dataplane

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/protocol"
)

type ClientSettings struct {
	InstanceNonce uint64
	AdvertisedIP  netip.Addr
	Generation    uint32
	HealthyMask   uint32
	Groups        []GroupSettings
	Paths         []PathSettings
	// DownPaths holds the down path slots. A nil entry is an empty slot.
	DownPaths []*DownPathSettings
}

// GroupSettings configures the peers of one listen port. PathMask holds one
// bit for each path slot of the group. DownMask holds one bit for each down
// path slot of a group with separate down paths, and DownMode is the mode that
// the server uses for them.
type GroupSettings struct {
	ListenPort uint16
	Mode       config.Mode
	PathMask   uint8
	DownMode   config.Mode
	DownMask   uint8
}

type PathSettings struct {
	DestinationIP netip.Addr
	SourceIP      netip.Addr
	Ifindex       int
	ServerPort    uint16
	Transport     protocol.TransportID
	Priority      uint8
	ReturnIP      netip.Addr
	ReturnPrefix  uint8
	Balance       config.Balance
}

type ServerSettings struct {
	Target      netip.AddrPort
	SourceIP    netip.Addr
	Ifindex     int
	ServerPorts config.PortRange
	// IngressIfindex turns on the ingress delivery of a target on this host,
	// and zero turns it off. IngressMAC is the Ethernet address of that
	// interface, which the injected packets carry as their destination.
	IngressIfindex int
	IngressMAC     net.HardwareAddr
}

func encodeClientSettings(settings ClientSettings) (
	mupClientConfigV1,
	map[uint16]mupPathGroupV1,
	[config.MaxPaths]mupPathConfigV1,
	mupPathStateV1,
	error,
) {
	var client mupClientConfigV1
	var paths [config.MaxPaths]mupPathConfigV1
	var state mupPathStateV1

	if settings.InstanceNonce == 0 {
		return client, nil, paths, state, errors.New("client instance nonce must be nonzero")
	}
	advertisedIP, err := requiredIPv4Word(settings.AdvertisedIP, "client advertised IP")
	if err != nil {
		return client, nil, paths, state, err
	}
	if len(settings.Paths) == 0 || len(settings.Paths) > config.MaxPaths {
		return client, nil, paths, state, fmt.Errorf("client requires between 1 and %d paths", config.MaxPaths)
	}
	configured := uint32(1)<<len(settings.Paths) - 1
	if settings.HealthyMask&^configured != 0 {
		return client, nil, paths, state, errors.New("healthy path mask references an unconfigured path")
	}
	if len(settings.Groups) == 0 {
		return client, nil, paths, state, errors.New("client requires at least one path group")
	}
	groups := make(map[uint16]mupPathGroupV1, len(settings.Groups))
	var assigned uint32
	for _, group := range settings.Groups {
		encoded, err := encodeGroupSettings(group)
		if err != nil {
			return client, nil, paths, state, err
		}
		if _, exists := groups[group.ListenPort]; exists {
			return client, nil, paths, state, fmt.Errorf("duplicate path group for listen port %d", group.ListenPort)
		}
		if assigned&uint32(group.PathMask) != 0 {
			return client, nil, paths, state, fmt.Errorf("path group of listen port %d shares a path with another group", group.ListenPort)
		}
		assigned |= uint32(group.PathMask)
		groups[group.ListenPort] = encoded
	}
	if assigned != configured {
		return client, nil, paths, state, errors.New("each path must belong to exactly one path group")
	}
	if len(settings.DownPaths) > MaxDownPaths {
		return client, nil, paths, state, fmt.Errorf("client accepts at most %d down paths", MaxDownPaths)
	}
	var downConfigured, downAssigned uint8
	for slot, down := range settings.DownPaths {
		if down != nil {
			downConfigured |= 1 << slot
		}
	}
	for _, group := range settings.Groups {
		if downAssigned&group.DownMask != 0 {
			return client, nil, paths, state, fmt.Errorf("path group of listen port %d shares a down path with another group", group.ListenPort)
		}
		downAssigned |= group.DownMask
	}
	if downAssigned != downConfigured {
		return client, nil, paths, state, errors.New("each down path must belong to exactly one path group")
	}
	for index, path := range settings.Paths {
		if paths[index], err = encodePathSettings(index, path); err != nil {
			return client, nil, paths, state, err
		}
	}

	client = mupClientConfigV1{
		InstanceNonce: settings.InstanceNonce,
		AdvertisedIp:  advertisedIP,
		Generation:    settings.Generation,
	}
	state = mupPathStateV1{
		Generation:  settings.Generation,
		HealthyMask: settings.HealthyMask,
	}
	return client, groups, paths, state, nil
}

func encodeGroupSettings(group GroupSettings) (mupPathGroupV1, error) {
	if group.ListenPort == 0 {
		return mupPathGroupV1{}, errors.New("path group listen port must be nonzero")
	}
	if group.Mode > config.ModeBurst {
		return mupPathGroupV1{}, fmt.Errorf("invalid mode %d for listen port %d", group.Mode, group.ListenPort)
	}
	if group.PathMask == 0 {
		return mupPathGroupV1{}, fmt.Errorf("path group of listen port %d has no paths", group.ListenPort)
	}
	if group.DownMode > config.ModeBurst {
		return mupPathGroupV1{}, fmt.Errorf("invalid down mode %d for listen port %d", group.DownMode, group.ListenPort)
	}
	encoded := mupPathGroupV1{Mode: uint8(group.Mode), PathMask: group.PathMask, DownMask: group.DownMask}
	// A downstream burst sends copies on several down paths, so the client
	// drops the later copies.
	if group.DownMask != 0 && group.DownMode == config.ModeBurst {
		encoded.Flags = groupFlagDedup
	}
	return encoded, nil
}

// groupFlagDedup mirrors MUP_GROUP_FLAG_DEDUP in bpf/include/mup_abi.h.
const groupFlagDedup uint8 = 1 << 0

// encodePathReturn encodes the return IP or return pool of a path slot. A path
// without a return IP has an empty entry.
func encodePathReturn(index int, path PathSettings) (mupPathReturnV1, error) {
	if path.ReturnPrefix != 0 {
		base, err := requiredIPv4Word(path.ReturnIP, fmt.Sprintf("path %d return pool base", index))
		if err != nil {
			return mupPathReturnV1{}, err
		}
		flags := protocol.ControlFlagReturnPool
		if path.Balance == config.BalancePerPacket {
			flags |= protocol.ControlFlagBalancePerPacket
		}
		return mupPathReturnV1{ReturnIp: base, Flags: flags, Prefix: path.ReturnPrefix}, nil
	}
	if !path.ReturnIP.IsValid() {
		return mupPathReturnV1{}, nil
	}
	returnIP, err := requiredIPv4Word(path.ReturnIP, fmt.Sprintf("path %d return IP", index))
	if err != nil {
		return mupPathReturnV1{}, err
	}
	return mupPathReturnV1{ReturnIp: returnIP, Flags: protocol.ControlFlagReturnIP}, nil
}

// encodeUpReflect encodes the reflect members of an up reflect path slot. The
// client reflects the upstream through these members. An empty list is an empty
// entry, so the client egress leaves the slot as a direct path. perPacket picks
// the per-packet balance mode, and false picks the per-peer mode.
func encodeUpReflect(members []netip.Addr, perPacket bool) (mupUpReflectV1, error) {
	var reflect mupUpReflectV1
	if len(members) > len(reflect.Members) {
		return reflect, fmt.Errorf("up reflect path has %d members, at most %d", len(members), len(reflect.Members))
	}
	for position, member := range members {
		word, err := requiredIPv4Word(member, fmt.Sprintf("up reflect member %d", position))
		if err != nil {
			return reflect, err
		}
		reflect.Members[position] = word
	}
	reflect.Count = uint32(len(members))
	if perPacket {
		reflect.Flags = protocol.ControlFlagBalancePerPacket
	}
	return reflect, nil
}

func encodePathSettings(index int, path PathSettings) (mupPathConfigV1, error) {
	if index < 0 || index >= config.MaxPaths {
		return mupPathConfigV1{}, fmt.Errorf("path slot %d is outside 0 to %d", index, config.MaxPaths-1)
	}
	destinationIP, err := requiredIPv4Word(path.DestinationIP, fmt.Sprintf("path %d destination IP", index))
	if err != nil {
		return mupPathConfigV1{}, err
	}
	sourceIP, err := requiredIPv4Word(path.SourceIP, fmt.Sprintf("path %d source IP", index))
	if err != nil {
		return mupPathConfigV1{}, err
	}
	if path.Ifindex <= 0 {
		return mupPathConfigV1{}, fmt.Errorf("path %d interface index must be positive", index)
	}
	if path.ServerPort == 0 {
		return mupPathConfigV1{}, fmt.Errorf("path %d server port must be nonzero", index)
	}
	if path.Transport > protocol.TransportICMP {
		return mupPathConfigV1{}, fmt.Errorf("path %d has invalid transport %d", index, path.Transport)
	}
	return mupPathConfigV1{
		DestinationIp: destinationIP,
		SourceIp:      sourceIP,
		Ifindex:       uint32(path.Ifindex),
		ServerPort:    path.ServerPort,
		Transport:     uint8(path.Transport),
		Priority:      path.Priority,
	}, nil
}

func encodeServerSettings(settings ServerSettings) (mupServerConfigV1, mupServerPortsV1, error) {
	var server mupServerConfigV1
	var ports mupServerPortsV1

	if !settings.Target.IsValid() || settings.Target.Port() == 0 {
		return server, ports, errors.New("server target must be a nonzero IPv4:PORT")
	}
	targetIP, err := requiredIPv4Word(settings.Target.Addr(), "server target IP")
	if err != nil {
		return server, ports, err
	}
	sourceIP, err := requiredIPv4Word(settings.SourceIP, "server target-facing source IP")
	if err != nil {
		return server, ports, err
	}
	if settings.Ifindex <= 0 {
		return server, ports, errors.New("server target-facing interface index must be positive")
	}
	if settings.ServerPorts.First == 0 || settings.ServerPorts.Last < settings.ServerPorts.First {
		return server, ports, errors.New("server ports must be a nonzero range")
	}
	return mupServerConfigV1{
		TargetIp:   targetIP,
		SourceIp:   sourceIP,
		Ifindex:    uint32(settings.Ifindex),
		TargetPort: settings.Target.Port(),
		ServerPort: settings.ServerPorts.First,
	}, mupServerPortsV1{First: settings.ServerPorts.First, Last: settings.ServerPorts.Last}, nil
}

// encodeTargetIngress encodes the ingress delivery of a target. A zero
// interface index encodes the off state.
func encodeTargetIngress(settings ServerSettings) (mupTargetIngressV1, error) {
	var ingress mupTargetIngressV1
	if settings.IngressIfindex == 0 {
		return ingress, nil
	}
	if settings.IngressIfindex < 0 {
		return ingress, errors.New("target ingress interface index must be positive")
	}
	if len(settings.IngressMAC) != 6 {
		return ingress, errors.New("target ingress interface needs a 6-byte Ethernet address")
	}
	if settings.Target.Addr() != settings.SourceIP {
		return ingress, errors.New("target ingress needs a target address on this host")
	}
	ingress.Ifindex = uint32(settings.IngressIfindex)
	copy(ingress.Mac[:], settings.IngressMAC)
	return ingress, nil
}

func requiredIPv4Word(address netip.Addr, name string) (uint32, error) {
	if !address.Is4() || address.IsUnspecified() {
		return 0, fmt.Errorf("%s must be a nonzero IPv4 address", name)
	}
	bytes := address.As4()
	return binary.NativeEndian.Uint32(bytes[:]), nil
}

// ipv4FromWord reverses requiredIPv4Word. The word holds the address bytes in
// network order.
func ipv4FromWord(word uint32) netip.Addr {
	var bytes [4]byte
	binary.NativeEndian.PutUint32(bytes[:], word)
	return netip.AddrFrom4(bytes)
}
