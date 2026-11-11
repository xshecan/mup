package dataplane

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/xshecan/mup/protocol"
)

func TestEncodeRegistrationSettings(t *testing.T) {
	t.Parallel()

	key, value, pathKey, pathValue, err := encodeRegistrationSettings(RegistrationSettings{
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		InstanceNonce: 99,
		ReturnIP:      netip.MustParseAddr("1.1.1.1"),
		ListenPort:    51820,
		PathCount:     2,
		ExpiresAtNS:   123456,
		Path: RegisteredPathSettings{
			SourceIP:   netip.MustParseAddr("192.0.2.10"),
			LocalIP:    netip.MustParseAddr("198.51.100.1"),
			ServerPort: 5000,
			Transport:  protocol.TransportICMP,
			PathID:     1,
		},
	})
	if err != nil {
		t.Fatalf("encodeRegistrationSettings: %v", err)
	}
	if key.InstanceNonce != 99 || value.ListenPort != 51820 ||
		value.Flags != protocol.ControlFlagReturnIP || value.PathCount != 2 ||
		value.ExpiresAtNs != 123456 {
		t.Fatalf("registration = %#v / %#v", key, value)
	}
	if pathValue.Client != key || pathValue.PathId != 1 ||
		pathValue.ExpiresAtNs != 123456 || pathKey.ServerPort != 5000 ||
		pathKey.Transport != uint8(protocol.TransportICMP) {
		t.Fatalf("path = %#v / %#v", pathKey, pathValue)
	}
	var source [4]byte
	binary.NativeEndian.PutUint32(source[:], pathKey.SourceIp)
	if source != [4]byte{192, 0, 2, 10} {
		t.Fatalf("source bytes = %v", source)
	}
}

func TestEncodeRegistrationRejectsSourceMismatch(t *testing.T) {
	t.Parallel()

	_, _, _, _, err := encodeRegistrationSettings(RegistrationSettings{
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		InstanceNonce: 1,
		ListenPort:    51820,
		ExpiresAtNS:   1,
		Path: RegisteredPathSettings{
			SourceIP:   netip.MustParseAddr("192.0.2.11"),
			LocalIP:    netip.MustParseAddr("198.51.100.1"),
			ServerPort: 5000,
			Transport:  protocol.TransportUDP,
		},
	})
	if err == nil {
		t.Fatal("source mismatch unexpectedly accepted")
	}
}
