package dataplane

import (
	"net/netip"
	"testing"
	"time"

	"github.com/xshecan/mup/protocol"
)

func TestIPv4WordRoundTrip(t *testing.T) {
	t.Parallel()

	address := netip.MustParseAddr("203.0.113.9")
	word, err := requiredIPv4Word(address, "test address")
	if err != nil {
		t.Fatalf("requiredIPv4Word: %v", err)
	}
	if got := ipv4FromWord(word); got != address {
		t.Fatalf("ipv4FromWord = %v, want %v", got, address)
	}
}

func TestDecodeClientRouteUsesTheNewestTimestamp(t *testing.T) {
	t.Parallel()

	peer := netip.MustParseAddr("198.51.100.4")
	local := netip.MustParseAddr("192.0.2.10")
	endpoint := mupPeerEndpointKeyV1{
		SourceIp:   mustWord(t, peer),
		LocalIp:    mustWord(t, local),
		SourcePort: 41000,
		ListenPort: 51820,
	}
	route := decodeClientRoute(
		endpoint,
		mupPeerTokenValueV1{PeerToken: 17, LastSeenNs: uint64(10 * time.Second)},
		mupPeerEndpointValueV1{Endpoint: endpoint, Ifindex: 3, LastSeenNs: uint64(12 * time.Second)},
		true,
		uint64(15*time.Second),
	)
	if route.Token != 17 || route.Peer != netip.AddrPortFrom(peer, 41000) || route.Local != netip.AddrPortFrom(local, 51820) {
		t.Fatalf("route = %#v", route)
	}
	if route.Ifindex != 3 || route.Idle != 3*time.Second {
		t.Fatalf("route interface/idle = %d/%v, want 3/3s", route.Ifindex, route.Idle)
	}
}

func TestDecodeServerRouteReadsTheReturnPath(t *testing.T) {
	t.Parallel()

	client := mupClientKeyV1{AdvertisedIp: mustWord(t, netip.MustParseAddr("192.0.2.10")), InstanceNonce: 0xabcdef}
	reverse := mupServerReverseValueV1{
		RouteKey: mupServerRouteKeyV1{Client: client, PeerToken: 9},
		RouteValue: mupServerRouteValueV1{
			TargetPort:     20001,
			ServerPort:     5000,
			Transport:      uint8(protocol.TransportICMP),
			Flags:          protocol.ControlFlagReturnIP,
			PathId:         2,
			ClientSourceIp: mustWord(t, netip.MustParseAddr("192.0.2.10")),
			ServerLocalIp:  mustWord(t, netip.MustParseAddr("203.0.113.6")),
			ReturnIp:       mustWord(t, netip.MustParseAddr("198.51.100.77")),
			Ifindex:        4,
			LastSeenNs:     uint64(time.Second),
		},
	}
	route := decodeServerRoute(reverse, uint64(3*time.Second))
	if route.Client.InstanceNonce != 0xabcdef || route.Token != 9 || route.TargetPort != 20001 {
		t.Fatalf("route identity = %#v", route)
	}
	if route.Transport != protocol.TransportICMP || route.ReturnIP != netip.MustParseAddr("198.51.100.77") || route.Idle != 2*time.Second {
		t.Fatalf("route return path = %#v", route)
	}
}

func TestDecodeRegistrationReportsTheRemainingLease(t *testing.T) {
	t.Parallel()

	key := mupClientKeyV1{AdvertisedIp: mustWord(t, netip.MustParseAddr("192.0.2.10")), InstanceNonce: 5}
	registration := decodeRegistration(key, mupRegistrationValueV1{ListenPort: 51820, ExpiresAtNs: uint64(40 * time.Second)}, uint64(30*time.Second))
	if registration.ExpiresIn != 10*time.Second || registration.ReturnIP.IsValid() || registration.ListenPort != 51820 {
		t.Fatalf("registration = %#v", registration)
	}
	expired := decodeRegistration(key, mupRegistrationValueV1{ExpiresAtNs: uint64(20 * time.Second)}, uint64(30*time.Second))
	if expired.ExpiresIn != -10*time.Second {
		t.Fatalf("expired lease = %v, want -10s", expired.ExpiresIn)
	}
}

func TestDecodeRegisteredPath(t *testing.T) {
	t.Parallel()

	client := mupClientKeyV1{AdvertisedIp: mustWord(t, netip.MustParseAddr("192.0.2.10")), InstanceNonce: 3}
	path := decodeRegisteredPath(
		mupRegisteredPathKeyV1{
			SourceIp:   mustWord(t, netip.MustParseAddr("192.0.2.10")),
			LocalIp:    mustWord(t, netip.MustParseAddr("203.0.113.5")),
			ServerPort: 5000,
			Transport:  uint8(protocol.TransportUDP),
		},
		mupRegisteredPathValueV1{Client: client, ExpiresAtNs: uint64(35 * time.Second), PathId: 1},
		uint64(30*time.Second),
	)
	if path.Local != netip.MustParseAddr("203.0.113.5") || path.PathID != 1 || path.ExpiresIn != 5*time.Second || path.Client.InstanceNonce != 3 {
		t.Fatalf("path = %#v", path)
	}
}

func mustWord(t *testing.T, address netip.Addr) uint32 {
	t.Helper()
	word, err := requiredIPv4Word(address, "test address")
	if err != nil {
		t.Fatalf("requiredIPv4Word: %v", err)
	}
	return word
}
