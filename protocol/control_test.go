package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func TestControlFrameRoundTrip(t *testing.T) {
	t.Parallel()

	want := ControlFrame{
		Type:          ControlRegister,
		Transport:     TransportICMP,
		Flags:         ControlFlagReturnIP,
		PathID:        3,
		ListenPort:    51820,
		ServerPort:    5000,
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		ReturnIP:      netip.MustParseAddr("198.51.100.8"),
		InstanceNonce: 0x0102030405060708,
		Sequence:      42,
		LeaseSeconds:  30,
	}
	buf := make([]byte, ControlFrameLength)
	if err := EncodeControlFrame(buf, want); err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
	}
	if got := binary.BigEndian.Uint32(buf[0:4]); got != ControlMagic {
		t.Fatalf("magic = %#x, want %#x", got, ControlMagic)
	}
	if got := len(buf); got != 48 {
		t.Fatalf("encoded length = %d, want 48", got)
	}
	got, err := DecodeControlFrame(buf)
	if err != nil {
		t.Fatalf("DecodeControlFrame: %v", err)
	}
	if got != want {
		t.Fatalf("decoded frame = %#v, want %#v", got, want)
	}
}

func TestDecodeControlFrameRejectsReservedBytes(t *testing.T) {
	t.Parallel()

	buf := make([]byte, ControlFrameLength)
	frame := ControlFrame{
		Type:          ControlProbe,
		Transport:     TransportUDP,
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		InstanceNonce: 1,
	}
	if err := EncodeControlFrame(buf, frame); err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
	}
	buf[19] = 1
	if _, err := DecodeControlFrame(buf); !errors.Is(err, ErrControlReserved) {
		t.Fatalf("DecodeControlFrame error = %v, want %v", err, ErrControlReserved)
	}
}

func TestGenerateInstanceNonceRejectsZero(t *testing.T) {
	t.Parallel()

	if _, err := GenerateInstanceNonce(bytes.NewReader(make([]byte, 16))); !errors.Is(err, ErrZeroInstanceNonce) {
		t.Fatalf("GenerateInstanceNonce error = %v, want %v", err, ErrZeroInstanceNonce)
	}
	nonce, err := GenerateInstanceNonce(bytes.NewReader([]byte{0, 0, 0, 0, 0, 0, 0, 9}))
	if err != nil {
		t.Fatalf("GenerateInstanceNonce: %v", err)
	}
	if nonce != 9 {
		t.Fatalf("nonce = %d, want 9", nonce)
	}
}

func TestRandomInstanceNonceIsNonzero(t *testing.T) {
	t.Parallel()

	nonce, err := RandomInstanceNonce()
	if err != nil {
		t.Fatalf("RandomInstanceNonce: %v", err)
	}
	if nonce == 0 {
		t.Fatal("RandomInstanceNonce returned zero")
	}
}

func TestEncodeControlFrameRejectsInvalidPolicy(t *testing.T) {
	t.Parallel()

	base := ControlFrame{
		Type:          ControlRegister,
		Transport:     TransportUDP,
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		InstanceNonce: 1,
	}
	tests := []struct {
		name  string
		alter func(*ControlFrame)
		err   error
	}{
		{name: "path ID", alter: func(frame *ControlFrame) { frame.PathID = MaxPathID + 1 }, err: ErrControlPathID},
		{name: "return IP without flag", alter: func(frame *ControlFrame) { frame.ReturnIP = netip.MustParseAddr("198.51.100.1") }, err: ErrControlFlags},
		{name: "flag without return IP", alter: func(frame *ControlFrame) { frame.Flags = ControlFlagReturnIP }, err: ErrControlAddress},
		{name: "unknown status", alter: func(frame *ControlFrame) { frame.Status = ControlStatusCapacityExhausted + 1 }, err: ErrControlStatus},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := base
			tt.alter(&frame)
			err := EncodeControlFrame(make([]byte, ControlFrameLength), frame)
			if !errors.Is(err, tt.err) {
				t.Fatalf("EncodeControlFrame error = %v, want %v", err, tt.err)
			}
		})
	}
}
