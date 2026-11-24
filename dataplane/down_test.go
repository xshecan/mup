package dataplane

import (
	"net/netip"
	"testing"

	"github.com/xshecan/mup/config"
)

func TestEncodeEgressGroupEntryKeysTheGroupByClientAndListenPort(t *testing.T) {
	t.Parallel()

	client := ClientKey{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), InstanceNonce: 7}
	key, value, err := encodeEgressGroupEntry(EgressGroupEntry{
		Client: client, ListenPort: 51822, Mode: config.ModeRepeater,
		PathMask: 0b11, HealthyMask: 0b111, ICMPMask: 0b110,
	})
	if err != nil {
		t.Fatalf("encodeEgressGroupEntry: %v", err)
	}
	want := mupDownGroupKeyV1{
		Client:     mupClientKeyV1{AdvertisedIp: mustWord(t, client.AdvertisedIP), InstanceNonce: 7},
		ListenPort: 51822,
	}
	if key != want {
		t.Fatalf("key = %#v, want %#v", key, want)
	}
	if value.Mode != uint8(config.ModeRepeater) || value.PathMask != 0b11 || value.HealthyMask != 0b11 || value.IcmpMask != 0b10 {
		t.Fatalf("value = %#v, want the masks cut to the path mask", value)
	}
	other, _, err := encodeEgressGroupEntry(EgressGroupEntry{Client: client, ListenPort: 51823, PathMask: 1})
	if err != nil {
		t.Fatalf("encodeEgressGroupEntry: %v", err)
	}
	if other == key {
		t.Fatal("two listen ports of one client share a group key")
	}
}

func TestEncodeEgressGroupRefusesAZeroListenPort(t *testing.T) {
	t.Parallel()

	client := ClientKey{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), InstanceNonce: 7}
	if _, _, err := encodeEgressGroupEntry(EgressGroupEntry{Client: client, PathMask: 1}); err == nil {
		t.Fatal("encodeEgressGroupEntry accepted listen port 0")
	}
	if _, err := encodeEgressGroupKey(client, 0); err == nil {
		t.Fatal("encodeEgressGroupKey accepted listen port 0")
	}
	if _, _, err := encodeEgressGroupEntry(EgressGroupEntry{Client: client, ListenPort: 51820, Mode: config.ModeRepeater + 1}); err == nil {
		t.Fatal("encodeEgressGroupEntry accepted an invalid mode")
	}
}
