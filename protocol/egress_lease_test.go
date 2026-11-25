package protocol

import (
	"encoding/hex"
	"net/netip"
	"testing"
)

func TestPackEgressLease(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		seconds  uint8
		settings EgressSettings
		want     uint32
	}{
		"no settings":     {30, EgressSettings{}, 30},
		"prefer latency":  {30, EgressSettings{PreferLatency: true}, 0x0000011e},
		"tolerance 5%":    {30, EgressSettings{ToleranceTenths: 50}, 0x0032001e},
		"tolerance 0.1%":  {30, EgressSettings{ToleranceTenths: 1}, 0x0001001e},
		"tolerance 100%":  {30, EgressSettings{ToleranceTenths: 1000}, 0x03e8001e},
		"both":            {30, EgressSettings{ToleranceTenths: 125, PreferLatency: true}, 0x007d011e},
		"limit too large": {30, EgressSettings{ToleranceTenths: 1001}, 30},
		"withdraw":        {0, EgressSettings{ToleranceTenths: 50, PreferLatency: true}, 0},
	} {
		t.Run(name, func(t *testing.T) {
			if got := PackEgressLease(tt.seconds, tt.settings); got != tt.want {
				t.Fatalf("PackEgressLease = %#x, want %#x", got, tt.want)
			}
		})
	}
}

func TestUnpackEgressLease(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		field    uint32
		seconds  uint8
		settings EgressSettings
	}{
		"old frame":       {30, 30, EgressSettings{}},
		"withdraw":        {0, 0, EgressSettings{}},
		"both":            {0x007d011e, 30, EgressSettings{ToleranceTenths: 125, PreferLatency: true}},
		"limit too large": {0x03e9001e, 30, EgressSettings{}},
		"unknown bits":    {0x0032fe1e, 30, EgressSettings{ToleranceTenths: 50}},
	} {
		t.Run(name, func(t *testing.T) {
			seconds, settings := UnpackEgressLease(tt.field)
			if seconds != tt.seconds || settings != tt.settings {
				t.Fatalf("UnpackEgressLease(%#x) = %d, %+v, want %d, %+v", tt.field, seconds, settings, tt.seconds, tt.settings)
			}
		})
	}
	for _, settings := range []EgressSettings{{}, {PreferLatency: true}, {ToleranceTenths: 1}, {ToleranceTenths: 1000, PreferLatency: true}} {
		seconds, got := UnpackEgressLease(PackEgressLease(30, settings))
		if seconds != 30 || got != settings {
			t.Fatalf("round trip of %+v = %d, %+v", settings, seconds, got)
		}
	}
}

// TestEgressRegisterWithoutSettingsKeepsItsBytes holds the bytes of a
// EGRESS_REGISTER of v0.5.3, so a frame without settings stays the same for
// an older server.
func TestEgressRegisterWithoutSettingsKeepsItsBytes(t *testing.T) {
	t.Parallel()

	frame := ControlFrame{
		Type:          ControlEgressRegister,
		Transport:     TransportUDP,
		PathID:        1,
		Sequence:      7,
		ListenPort:    51825,
		ServerPort:    9000,
		LeaseSeconds:  PackEgressLease(30, EgressSettings{}),
		InstanceNonce: 0x0102030405060708,
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		EgressServer:  netip.MustParseAddr("198.51.100.1"),
	}
	buf := make([]byte, ControlFrameLength)
	if err := EncodeControlFrame(buf, frame); err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
	}
	const want = "4d55504301070000003000000001ca7123280000c000020a00000000010203040506070800000007" + "0000001e" + "c6336401"
	if got := hex.EncodeToString(buf); got != want {
		t.Fatalf("encoded frame = %s, want %s", got, want)
	}
}
