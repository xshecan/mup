package dataplane

import (
	"net/netip"
	"time"

	"github.com/xshecan/mup/protocol"
)

// ClientRoute is one WireGuard peer of a client.
type ClientRoute struct {
	Token   uint32
	Peer    netip.AddrPort
	Local   netip.AddrPort
	Ifindex int
	Idle    time.Duration
}

// ServerRoute is one peer of one client on a server.
type ServerRoute struct {
	Client       ClientKey
	Token        uint32
	TargetPort   uint16
	ServerPort   uint16
	Transport    protocol.TransportID
	PathID       uint16
	ClientSource netip.Addr
	ServerLocal  netip.Addr
	// ReturnIP is the return IP, or the pool base when ReturnPool is set.
	ReturnIP   netip.Addr
	ReturnPool bool
	Ifindex    int
	Idle       time.Duration
}

// Registration is one client registration on a server. ExpiresIn is
// negative after the lease ended.
type Registration struct {
	Client ClientKey
	// ReturnIP is the return IP, or the pool base when ReturnPool is set.
	ReturnIP   netip.Addr
	ReturnPool bool
	ListenPort uint16
	ExpiresIn  time.Duration
}

// RegisteredPath is one registered client path on a server.
type RegisteredPath struct {
	Client     ClientKey
	Source     netip.Addr
	Local      netip.Addr
	ServerPort uint16
	Transport  protocol.TransportID
	PathID     uint16
	ExpiresIn  time.Duration
	// ReturnIP is the return IP, or the pool base when ReturnPrefix is
	// nonzero.
	ReturnIP     netip.Addr
	ReturnPrefix uint8
}

// sinceNS returns how long ago a monotonic timestamp was, and zero for a
// timestamp in the future.
func sinceNS(timestampNS, nowNS uint64) time.Duration {
	if timestampNS >= nowNS {
		return 0
	}
	return time.Duration(nowNS - timestampNS)
}

func untilNS(timestampNS, nowNS uint64) time.Duration {
	return time.Duration(int64(timestampNS) - int64(nowNS))
}

func decodeClientKey(key mupClientKeyV1) ClientKey {
	return ClientKey{AdvertisedIP: ipv4FromWord(key.AdvertisedIp), InstanceNonce: key.InstanceNonce}
}

func decodeClientRoute(endpoint mupPeerEndpointKeyV1, route mupPeerTokenValueV1, reverse mupPeerEndpointValueV1, hasReverse bool, nowNS uint64) ClientRoute {
	decoded := ClientRoute{
		Token: route.PeerToken,
		Peer:  netip.AddrPortFrom(ipv4FromWord(endpoint.SourceIp), endpoint.SourcePort),
		Local: netip.AddrPortFrom(ipv4FromWord(endpoint.LocalIp), endpoint.ListenPort),
		Idle:  sinceNS(route.LastSeenNs, nowNS),
	}
	if hasReverse {
		decoded.Ifindex = int(reverse.Ifindex)
		if reverse.LastSeenNs > route.LastSeenNs {
			decoded.Idle = sinceNS(reverse.LastSeenNs, nowNS)
		}
	}
	return decoded
}

// decodeServerRoute reads the return path from the reverse entry, which the
// downstream direction uses.
func decodeServerRoute(reverse mupServerReverseValueV1, nowNS uint64) ServerRoute {
	value := reverse.RouteValue
	route := ServerRoute{
		Client:       decodeClientKey(reverse.RouteKey.Client),
		Token:        reverse.RouteKey.PeerToken,
		TargetPort:   value.TargetPort,
		ServerPort:   value.ServerPort,
		Transport:    protocol.TransportID(value.Transport),
		PathID:       value.PathId,
		ClientSource: ipv4FromWord(value.ClientSourceIp),
		ServerLocal:  ipv4FromWord(value.ServerLocalIp),
		Ifindex:      int(value.Ifindex),
		Idle:         sinceNS(value.LastSeenNs, nowNS),
	}
	route.ReturnIP, route.ReturnPool = decodeReturn(value.Flags, value.ReturnIp)
	return route
}

func decodeRegistration(key mupClientKeyV1, value mupRegistrationValueV1, nowNS uint64) Registration {
	registration := Registration{
		Client:     decodeClientKey(key),
		ListenPort: value.ListenPort,
		ExpiresIn:  untilNS(value.ExpiresAtNs, nowNS),
	}
	registration.ReturnIP, registration.ReturnPool = decodeReturn(value.Flags, value.ReturnIp)
	return registration
}

// decodeReturn reads the return IP or the pool base of a route, and whether it
// is a pool.
func decodeReturn(flags uint8, word uint32) (netip.Addr, bool) {
	switch {
	case flags&protocol.ControlFlagReturnPool != 0:
		return ipv4FromWord(word), true
	case flags&protocol.ControlFlagReturnIP != 0:
		return ipv4FromWord(word), false
	default:
		return netip.Addr{}, false
	}
}

func decodeRegisteredPath(key mupRegisteredPathKeyV1, value mupRegisteredPathValueV1, nowNS uint64) RegisteredPath {
	path := RegisteredPath{
		Client:     decodeClientKey(value.Client),
		Source:     ipv4FromWord(key.SourceIp),
		Local:      ipv4FromWord(key.LocalIp),
		ServerPort: key.ServerPort,
		Transport:  protocol.TransportID(key.Transport),
		PathID:     value.PathId,
		ExpiresIn:  untilNS(value.ExpiresAtNs, nowNS),
	}
	var pool bool
	path.ReturnIP, pool = decodeReturn(value.Flags, value.ReturnIp)
	if pool {
		path.ReturnPrefix = value.Prefix
	}
	return path
}
