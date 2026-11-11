package dataplane

import (
	"encoding/binary"
	"errors"
	"fmt"
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
}

// GroupSettings configures the peers of one listen port. PathMask holds one
// bit for each path slot of the group.
type GroupSettings struct {
	ListenPort uint16
	Mode       config.Mode
	ReturnIP   netip.Addr
	PathMask   uint8
}

type PathSettings struct {
	DestinationIP netip.Addr
	SourceIP      netip.Addr
	Ifindex       int
	ServerPort    uint16
	Transport     protocol.TransportID
	Priority      uint8
}

type ServerSettings struct {
	Target     netip.AddrPort
	SourceIP   netip.Addr
	Ifindex    int
	ServerPort uint16
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
	encoded := mupPathGroupV1{Mode: uint8(group.Mode), PathMask: group.PathMask}
	if group.ReturnIP.IsValid() {
		returnIP, err := requiredIPv4Word(group.ReturnIP, "path group return IP")
		if err != nil {
			return mupPathGroupV1{}, err
		}
		encoded.ReturnIp = returnIP
		encoded.Flags = protocol.ControlFlagReturnIP
	}
	return encoded, nil
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

func encodeServerSettings(settings ServerSettings) (mupServerConfigV1, error) {
	var server mupServerConfigV1

	if !settings.Target.IsValid() || settings.Target.Port() == 0 {
		return server, errors.New("server target must be a nonzero IPv4:PORT")
	}
	targetIP, err := requiredIPv4Word(settings.Target.Addr(), "server target IP")
	if err != nil {
		return server, err
	}
	sourceIP, err := requiredIPv4Word(settings.SourceIP, "server target-facing source IP")
	if err != nil {
		return server, err
	}
	if settings.Ifindex <= 0 {
		return server, errors.New("server target-facing interface index must be positive")
	}
	if settings.ServerPort == 0 {
		return server, errors.New("server port must be nonzero")
	}
	return mupServerConfigV1{
		TargetIp:   targetIP,
		SourceIp:   sourceIP,
		Ifindex:    uint32(settings.Ifindex),
		TargetPort: settings.Target.Port(),
		ServerPort: settings.ServerPort,
	}, nil
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
