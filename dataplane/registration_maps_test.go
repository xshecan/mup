package dataplane

import (
	"net/netip"
	"testing"
)

type recordingDeleteMap struct {
	key interface{}
}

func (m *recordingDeleteMap) Delete(key interface{}) error {
	m.key = key
	return nil
}

func TestRevokeRegistrationDeletesClientKey(t *testing.T) {
	t.Parallel()

	target := &recordingDeleteMap{}
	err := revokeRegistration(target, ClientKey{
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		InstanceNonce: 99,
	})
	if err != nil {
		t.Fatalf("revokeRegistration: %v", err)
	}
	key, ok := target.key.(mupClientKeyV1)
	if !ok || key.InstanceNonce != 99 {
		t.Fatalf("deleted key = %#v", target.key)
	}
	if got := nativeIPv4Bytes(key.AdvertisedIp); got != [4]byte{192, 0, 2, 10} {
		t.Fatalf("advertised IP bytes = %v", got)
	}
}
