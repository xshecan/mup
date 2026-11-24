package dataplane

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/protocol"
)

// MaxEgressPaths is the number of egress path slots of a client. It mirrors the
// size of the client_down_paths map.
const MaxEgressPaths = 8

// EgressPathSettings is one egress path of a client group: the server address and
// port that send the replies, the transport, and an optional return IP or
// return pool. The client accepts replies only from these sources. A path with
// a source range takes replies from any UDP source port of SrcFirst to SrcLast,
// or ICMP replies with the tag of its slot and an identifier of the range.
type EgressPathSettings struct {
	Server       netip.Addr
	ServerPort   uint16
	Transport    protocol.TransportID
	ReturnIP     netip.Addr
	ReturnPrefix uint8
	SrcFirst     uint16
	SrcLast      uint16
}

// EgressPathFromConfig converts a configured egress path. The via of a path
// with BridgeVia applies to the leg from the server to the bridge, so the
// client expects the replies from the bridge address and gets no return IP.
func EgressPathFromConfig(path config.Path) EgressPathSettings {
	settings := EgressPathSettings{
		Server:       path.Server,
		ServerPort:   path.ServerPort,
		Transport:    path.Transport,
		ReturnIP:     path.ReturnIP,
		ReturnPrefix: path.ReturnPrefix,
		SrcFirst:     path.SrcFirst,
		SrcLast:      path.SrcLast,
	}
	if path.BridgeVia {
		settings.ReturnIP = netip.Addr{}
		settings.ReturnPrefix = 0
	}
	return settings
}

func encodeClientEgressPath(slot int, path EgressPathSettings) (mupClientDownPathV1, error) {
	if slot < 0 || slot >= MaxEgressPaths {
		return mupClientDownPathV1{}, fmt.Errorf("egress path slot %d is outside 0 to %d", slot, MaxEgressPaths-1)
	}
	server, err := requiredIPv4Word(path.Server, fmt.Sprintf("egress path %d server", slot))
	if err != nil {
		return mupClientDownPathV1{}, err
	}
	if path.ServerPort == 0 {
		return mupClientDownPathV1{}, fmt.Errorf("egress path %d server port must be nonzero", slot)
	}
	if path.Transport > protocol.TransportICMP {
		return mupClientDownPathV1{}, fmt.Errorf("egress path %d has invalid transport %d", slot, path.Transport)
	}
	encoded := mupClientDownPathV1{ServerIp: server, ServerPort: path.ServerPort, Transport: uint8(path.Transport)}
	switch {
	case path.ReturnPrefix != 0:
		if encoded.ReturnIp, err = requiredIPv4Word(path.ReturnIP, fmt.Sprintf("egress path %d return pool base", slot)); err != nil {
			return mupClientDownPathV1{}, err
		}
		encoded.Flags = protocol.ControlFlagReturnPool
		encoded.Prefix = path.ReturnPrefix
	case path.ReturnIP.IsValid():
		if encoded.ReturnIp, err = requiredIPv4Word(path.ReturnIP, fmt.Sprintf("egress path %d return IP", slot)); err != nil {
			return mupClientDownPathV1{}, err
		}
		encoded.Flags = protocol.ControlFlagReturnIP
	}
	return encoded, nil
}

// EgressPathEntry is one egress path of one client on a server. Members are the
// healthy members of a return pool, in the order the server spreads replies
// over them. A path without healthy members, or an unhealthy path, still has
// an entry, and the group mask decides whether the server uses it.
//
// A path with Bridge goes through a MUP bridge. Server is then the bridge
// address, and the server wraps each reply in a UDP packet from LocalIP to the
// bridge, out of Ifindex. With BridgeVia as well, the return IP or a pool
// member is the source of the wrapper in place of LocalIP, and the reply in it
// is the direct reply from the bridge address.
//
// A path with a source range sends each reply from a random UDP source port or
// ICMP identifier of SrcFirst to SrcLast, and the wrapper of a bridge path takes
// the same value as its source port. Zero means no range.
type EgressPathEntry struct {
	Client     ClientKey
	PathID     uint16
	Server     netip.Addr
	ServerPort uint16
	Transport  protocol.TransportID
	Ifindex    int
	ReturnIP   netip.Addr
	Pool       bool
	PerPacket  bool
	Members    []netip.Addr
	Bridge     bool
	BridgeVia  bool
	LocalIP    netip.Addr
	SrcFirst   uint16
	SrcLast    uint16
}

// EgressGroupEntry is the egress group of one listen port of a client on a
// server. ICMPMask has a bit for each egress path that uses ICMP.
type EgressGroupEntry struct {
	Client      ClientKey
	ListenPort  uint16
	Mode        config.Mode
	PathMask    uint8
	HealthyMask uint8
	ICMPMask    uint8
}

func encodeClientKey(client ClientKey) (mupClientKeyV1, error) {
	advertised, err := requiredIPv4Word(client.AdvertisedIP, "client advertised IP")
	if err != nil {
		return mupClientKeyV1{}, err
	}
	if client.InstanceNonce == 0 {
		return mupClientKeyV1{}, errors.New("client instance nonce must be nonzero")
	}
	return mupClientKeyV1{AdvertisedIp: advertised, InstanceNonce: client.InstanceNonce}, nil
}

func encodeEgressPathKey(client ClientKey, pathID uint16) (mupDownPathKeyV1, error) {
	key, err := encodeClientKey(client)
	if err != nil {
		return mupDownPathKeyV1{}, err
	}
	if pathID >= MaxEgressPaths {
		return mupDownPathKeyV1{}, fmt.Errorf("egress path ID %d is outside 0 to %d", pathID, MaxEgressPaths-1)
	}
	return mupDownPathKeyV1{Client: key, PathId: uint32(pathID)}, nil
}

func encodeEgressPathEntry(entry EgressPathEntry) (mupDownPathKeyV1, mupDownPathV1, error) {
	key, err := encodeEgressPathKey(entry.Client, entry.PathID)
	if err != nil {
		return key, mupDownPathV1{}, err
	}
	server, err := requiredIPv4Word(entry.Server, "egress path server")
	if err != nil {
		return key, mupDownPathV1{}, err
	}
	if entry.ServerPort == 0 || entry.Ifindex <= 0 || entry.Transport > protocol.TransportICMP {
		return key, mupDownPathV1{}, errors.New("egress path needs a server port, an interface, and a valid transport")
	}
	if len(entry.Members) > MaxPool {
		return key, mupDownPathV1{}, fmt.Errorf("egress path has %d members, more than %d", len(entry.Members), MaxPool)
	}
	src, err := encodePathSrc("egress path", entry.SrcFirst, entry.SrcLast)
	if err != nil {
		return key, mupDownPathV1{}, err
	}
	value := mupDownPathV1{
		ServerIp:   server,
		Ifindex:    uint32(entry.Ifindex),
		ServerPort: entry.ServerPort,
		Transport:  uint8(entry.Transport),
		SrcFirst:   src.First,
		SrcLast:    src.Last,
	}
	switch {
	case entry.Pool:
		value.Flags = protocol.ControlFlagReturnPool
		if entry.PerPacket {
			value.Flags |= protocol.ControlFlagBalancePerPacket
		}
		for index, member := range entry.Members {
			if value.Members[index], err = requiredIPv4Word(member, "egress path pool member"); err != nil {
				return key, mupDownPathV1{}, err
			}
		}
		value.Count = uint32(len(entry.Members))
	case entry.ReturnIP.IsValid():
		if value.ReturnIp, err = requiredIPv4Word(entry.ReturnIP, "egress path return IP"); err != nil {
			return key, mupDownPathV1{}, err
		}
		value.Flags = protocol.ControlFlagReturnIP
	}
	if entry.Bridge {
		if value.LocalIp, err = requiredIPv4Word(entry.LocalIP, "egress path bridge source"); err != nil {
			return key, mupDownPathV1{}, err
		}
		value.Flags |= protocol.ControlFlagBridge
	}
	if entry.BridgeVia {
		if !entry.Bridge || value.Flags&(protocol.ControlFlagReturnIP|protocol.ControlFlagReturnPool) == 0 {
			return key, mupDownPathV1{}, errors.New("egress path bridge via needs a bridge and a return IP or pool")
		}
		value.Flags |= protocol.ControlFlagBridgeVia
	}
	return key, value, nil
}

func encodeEgressGroupKey(client ClientKey, listenPort uint16) (mupDownGroupKeyV1, error) {
	key, err := encodeClientKey(client)
	if err != nil {
		return mupDownGroupKeyV1{}, err
	}
	if listenPort == 0 {
		return mupDownGroupKeyV1{}, errors.New("egress group listen port must be nonzero")
	}
	return mupDownGroupKeyV1{Client: key, ListenPort: listenPort}, nil
}

func encodeEgressGroupEntry(entry EgressGroupEntry) (mupDownGroupKeyV1, mupDownGroupV1, error) {
	key, err := encodeEgressGroupKey(entry.Client, entry.ListenPort)
	if err != nil {
		return key, mupDownGroupV1{}, err
	}
	if entry.Mode > config.ModeRepeater {
		return key, mupDownGroupV1{}, errors.New("egress group needs a valid mode")
	}
	return key, mupDownGroupV1{
		Mode:        uint8(entry.Mode),
		PathMask:    entry.PathMask,
		HealthyMask: entry.HealthyMask & entry.PathMask,
		IcmpMask:    entry.ICMPMask & entry.PathMask,
	}, nil
}
