package dataplane

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/protocol"
)

func testClientSettings() ClientSettings {
	path := func(address string, port uint16, transport protocol.TransportID, priority uint8) PathSettings {
		return PathSettings{
			DestinationIP: netip.MustParseAddr(address),
			SourceIP:      netip.MustParseAddr("192.0.2.10"),
			Ifindex:       4,
			ServerPort:    port,
			Transport:     transport,
			Priority:      priority,
		}
	}
	return ClientSettings{
		InstanceNonce: 9,
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		Generation:    7,
		HealthyMask:   0b111,
		Groups: []GroupSettings{
			{ListenPort: 51820, Mode: config.ModeBurst, PathMask: 0b011},
			{ListenPort: 51821, Mode: config.ModeFallback, PathMask: 0b100},
		},
		Paths: []PathSettings{
			path("198.51.100.5", 5000, protocol.TransportICMP, 0),
			path("198.51.100.6", 5000, protocol.TransportUDP, 1),
			path("203.0.113.5", 6000, protocol.TransportUDP, 2),
		},
	}
}

func TestEncodeClientSettings(t *testing.T) {
	t.Parallel()

	client, groups, paths, state, err := encodeClientSettings(testClientSettings())
	if err != nil {
		t.Fatalf("encodeClientSettings: %v", err)
	}
	if client.InstanceNonce != 9 || client.Generation != 7 {
		t.Fatalf("client config = %#v", client)
	}
	if got := nativeIPv4Bytes(client.AdvertisedIp); got != [4]byte{192, 0, 2, 10} {
		t.Fatalf("advertised IP bytes = %v", got)
	}
	first := groups[51820]
	if first.Mode != uint8(config.ModeBurst) || first.PathMask != 0b011 {
		t.Fatalf("first group = %#v", first)
	}
	second := groups[51821]
	if second.Mode != uint8(config.ModeFallback) || second.Flags != 0 || second.PathMask != 0b100 || second.ReturnIp != 0 {
		t.Fatalf("second group = %#v", second)
	}
	if len(paths) != 8 || paths[0].Ifindex != 4 ||
		paths[0].Transport != uint8(protocol.TransportICMP) ||
		paths[2].ServerPort != 6000 || state.HealthyMask != 0b111 {
		t.Fatalf("paths/state = %#v / %#v", paths, state)
	}
}

func TestEncodeClientSettingsRejectsInvalidGroups(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*ClientSettings){
		"no groups":        func(s *ClientSettings) { s.Groups = nil },
		"zero listen port": func(s *ClientSettings) { s.Groups[0].ListenPort = 0 },
		"duplicate port":   func(s *ClientSettings) { s.Groups[1].ListenPort = s.Groups[0].ListenPort },
		"invalid mode":     func(s *ClientSettings) { s.Groups[0].Mode = config.ModeBurst + 1 },
		"empty mask":       func(s *ClientSettings) { s.Groups[1].PathMask = 0 },
		"shared path":      func(s *ClientSettings) { s.Groups[1].PathMask = 0b110 },
		"path in no group": func(s *ClientSettings) { s.Groups[0].PathMask = 0b001 },
		"unconfigured bit": func(s *ClientSettings) { s.Groups[1].PathMask = 0b1100 },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			settings := testClientSettings()
			change(&settings)
			if _, _, _, _, err := encodeClientSettings(settings); err == nil {
				t.Fatal("encodeClientSettings unexpectedly succeeded")
			}
		})
	}
}

func TestEncodeServerSettings(t *testing.T) {
	t.Parallel()

	encoded, err := encodeServerSettings(ServerSettings{
		Target:     netip.MustParseAddrPort("193.24.210.185:51820"),
		SourceIP:   netip.MustParseAddr("192.0.2.5"),
		Ifindex:    3,
		ServerPort: 5000,
	})
	if err != nil {
		t.Fatalf("encodeServerSettings: %v", err)
	}
	if encoded.Ifindex != 3 || encoded.TargetPort != 51820 || encoded.ServerPort != 5000 {
		t.Fatalf("server config = %#v", encoded)
	}
	if got := nativeIPv4Bytes(encoded.TargetIp); got != [4]byte{193, 24, 210, 185} {
		t.Fatalf("target IP bytes = %v", got)
	}
}

func TestSettingsRejectInvalidValues(t *testing.T) {
	t.Parallel()

	if _, _, _, _, err := encodeClientSettings(ClientSettings{}); err == nil {
		t.Fatal("empty client settings unexpectedly accepted")
	}
	if _, err := encodeServerSettings(ServerSettings{}); err == nil {
		t.Fatal("empty server settings unexpectedly accepted")
	}
}

func nativeIPv4Bytes(value uint32) [4]byte {
	var bytes [4]byte
	binary.NativeEndian.PutUint32(bytes[:], value)
	return bytes
}
