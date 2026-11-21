package dataplane

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/protocol"
)

// MaxDownPaths is the number of down path slots of a client. It mirrors the
// size of the client_down_paths map.
const MaxDownPaths = 8

// DownPathSettings is one down path of a client group: the server address and
// port that send the replies, the transport, and an optional return IP or
// return pool. The client accepts replies only from these sources.
type DownPathSettings struct {
	Server       netip.Addr
	ServerPort   uint16
	Transport    protocol.TransportID
	ReturnIP     netip.Addr
	ReturnPrefix uint8
}

// DownPathFromConfig converts a configured down path.
func DownPathFromConfig(path config.Path) DownPathSettings {
	return DownPathSettings{
		Server:       path.Server,
		ServerPort:   path.ServerPort,
		Transport:    path.Transport,
		ReturnIP:     path.ReturnIP,
		ReturnPrefix: path.ReturnPrefix,
	}
}

func encodeClientDownPath(slot int, path DownPathSettings) (mupClientDownPathV1, error) {
	if slot < 0 || slot >= MaxDownPaths {
		return mupClientDownPathV1{}, fmt.Errorf("down path slot %d is outside 0 to %d", slot, MaxDownPaths-1)
	}
	server, err := requiredIPv4Word(path.Server, fmt.Sprintf("down path %d server", slot))
	if err != nil {
		return mupClientDownPathV1{}, err
	}
	if path.ServerPort == 0 {
		return mupClientDownPathV1{}, fmt.Errorf("down path %d server port must be nonzero", slot)
	}
	if path.Transport > protocol.TransportICMP {
		return mupClientDownPathV1{}, fmt.Errorf("down path %d has invalid transport %d", slot, path.Transport)
	}
	encoded := mupClientDownPathV1{ServerIp: server, ServerPort: path.ServerPort, Transport: uint8(path.Transport)}
	switch {
	case path.ReturnPrefix != 0:
		if encoded.ReturnIp, err = requiredIPv4Word(path.ReturnIP, fmt.Sprintf("down path %d return pool base", slot)); err != nil {
			return mupClientDownPathV1{}, err
		}
		encoded.Flags = protocol.ControlFlagReturnPool
		encoded.Prefix = path.ReturnPrefix
	case path.ReturnIP.IsValid():
		if encoded.ReturnIp, err = requiredIPv4Word(path.ReturnIP, fmt.Sprintf("down path %d return IP", slot)); err != nil {
			return mupClientDownPathV1{}, err
		}
		encoded.Flags = protocol.ControlFlagReturnIP
	}
	return encoded, nil
}

// DownPathEntry is one down path of one client on a server. Members are the
// healthy members of a return pool, in the order the server spreads replies
// over them. A path without healthy members, or an unhealthy path, still has
// an entry, and the group mask decides whether the server uses it.
//
// A path with Bridge goes through a MUP bridge. Server is then the bridge
// address, and the server wraps each reply in a UDP packet from LocalIP to the
// bridge, out of Ifindex.
type DownPathEntry struct {
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
	LocalIP    netip.Addr
}

// DownGroupEntry is the down group of one client on a server. ICMPMask has a
// bit for each down path that uses ICMP.
type DownGroupEntry struct {
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

func encodeDownPathKey(client ClientKey, pathID uint16) (mupDownPathKeyV1, error) {
	key, err := encodeClientKey(client)
	if err != nil {
		return mupDownPathKeyV1{}, err
	}
	if pathID >= MaxDownPaths {
		return mupDownPathKeyV1{}, fmt.Errorf("down path ID %d is outside 0 to %d", pathID, MaxDownPaths-1)
	}
	return mupDownPathKeyV1{Client: key, PathId: uint32(pathID)}, nil
}

func encodeDownPathEntry(entry DownPathEntry) (mupDownPathKeyV1, mupDownPathV1, error) {
	key, err := encodeDownPathKey(entry.Client, entry.PathID)
	if err != nil {
		return key, mupDownPathV1{}, err
	}
	server, err := requiredIPv4Word(entry.Server, "down path server")
	if err != nil {
		return key, mupDownPathV1{}, err
	}
	if entry.ServerPort == 0 || entry.Ifindex <= 0 || entry.Transport > protocol.TransportICMP {
		return key, mupDownPathV1{}, errors.New("down path needs a server port, an interface, and a valid transport")
	}
	if len(entry.Members) > MaxPool {
		return key, mupDownPathV1{}, fmt.Errorf("down path has %d members, more than %d", len(entry.Members), MaxPool)
	}
	value := mupDownPathV1{
		ServerIp:   server,
		Ifindex:    uint32(entry.Ifindex),
		ServerPort: entry.ServerPort,
		Transport:  uint8(entry.Transport),
	}
	switch {
	case entry.Pool:
		value.Flags = protocol.ControlFlagReturnPool
		if entry.PerPacket {
			value.Flags |= protocol.ControlFlagBalancePerPacket
		}
		for index, member := range entry.Members {
			if value.Members[index], err = requiredIPv4Word(member, "down path pool member"); err != nil {
				return key, mupDownPathV1{}, err
			}
		}
		value.Count = uint32(len(entry.Members))
	case entry.ReturnIP.IsValid():
		if value.ReturnIp, err = requiredIPv4Word(entry.ReturnIP, "down path return IP"); err != nil {
			return key, mupDownPathV1{}, err
		}
		value.Flags = protocol.ControlFlagReturnIP
	}
	if entry.Bridge {
		if value.LocalIp, err = requiredIPv4Word(entry.LocalIP, "down path bridge source"); err != nil {
			return key, mupDownPathV1{}, err
		}
		value.Flags |= protocol.ControlFlagBridge
	}
	return key, value, nil
}

func encodeDownGroupEntry(entry DownGroupEntry) (mupClientKeyV1, mupDownGroupV1, error) {
	key, err := encodeClientKey(entry.Client)
	if err != nil {
		return key, mupDownGroupV1{}, err
	}
	if entry.ListenPort == 0 || entry.Mode > config.ModeBurst {
		return key, mupDownGroupV1{}, errors.New("down group needs a listen port and a valid mode")
	}
	return key, mupDownGroupV1{
		ListenPort:  entry.ListenPort,
		Mode:        uint8(entry.Mode),
		PathMask:    entry.PathMask,
		HealthyMask: entry.HealthyMask & entry.PathMask,
		IcmpMask:    entry.ICMPMask & entry.PathMask,
	}, nil
}
