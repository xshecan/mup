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

func TestUpReflectRoundTrip(t *testing.T) {
	t.Parallel()

	want := ControlFrame{
		Type:          ControlRegister,
		Transport:     TransportICMP,
		Flags:         ControlFlagUpReflect | ControlFlagReturnPool | ControlFlagBalancePerPacket,
		PathID:        2,
		ListenPort:    51820,
		ServerPort:    9000,
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		ReturnIP:      netip.MustParseAddr("87.107.117.192"),
		ReturnPrefix:  28,
		InstanceNonce: 0x1122334455667788,
		Sequence:      7,
		LeaseSeconds:  30,
	}
	buf := make([]byte, ControlFrameLength)
	if err := EncodeControlFrame(buf, want); err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
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
		{name: "unknown status", alter: func(frame *ControlFrame) { frame.Status = ControlStatusNoReflector + 1 }, err: ErrControlStatus},
		{name: "up reflect without return", alter: func(frame *ControlFrame) { frame.Flags = ControlFlagUpReflect }, err: ErrControlFlags},
		{name: "up reflect on a probe", alter: func(frame *ControlFrame) {
			frame.Type = ControlProbe
			frame.Flags = ControlFlagUpReflect | ControlFlagReturnIP
			frame.ReturnIP = netip.MustParseAddr("198.51.100.1")
		}, err: ErrControlFlags},
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

func TestDownRegisterRoundTrip(t *testing.T) {
	t.Parallel()

	want := ControlFrame{
		Type:          ControlDownRegister,
		Transport:     TransportICMP,
		Flags:         ControlFlagReturnPool | ControlFlagBalancePerPacket,
		PathID:        2,
		ListenPort:    51820,
		ServerPort:    9200,
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		ReturnIP:      netip.MustParseAddr("198.51.100.0"),
		ReturnPrefix:  28,
		InstanceNonce: 7,
		Sequence:      3,
		LeaseSeconds:  30,
		DownMode:      2,
		DownServer:    netip.MustParseAddr("203.0.113.5"),
	}
	buf := make([]byte, ControlFrameLength)
	if err := EncodeControlFrame(buf, want); err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
	}
	if buf[18] != 2 || !bytes.Equal(buf[44:48], []byte{203, 0, 113, 5}) {
		t.Fatalf("down mode byte = %d, server bytes = %v", buf[18], buf[44:48])
	}
	got, err := DecodeControlFrame(buf)
	if err != nil {
		t.Fatalf("DecodeControlFrame: %v", err)
	}
	if got != want {
		t.Fatalf("decoded frame = %#v, want %#v", got, want)
	}
}

// A server before v0.4.0 must ignore a DOWN_REGISTER. Its decoder rejects the
// type and the reserved bytes, so the frame never reaches its registry.
func TestDownFieldsStayReservedInOtherFrames(t *testing.T) {
	t.Parallel()

	frame := ControlFrame{
		Type:          ControlRegister,
		Transport:     TransportUDP,
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		InstanceNonce: 1,
		DownServer:    netip.MustParseAddr("203.0.113.5"),
	}
	if err := EncodeControlFrame(make([]byte, ControlFrameLength), frame); !errors.Is(err, ErrControlReserved) {
		t.Fatalf("EncodeControlFrame error = %v, want %v", err, ErrControlReserved)
	}
	frame.DownServer = netip.Addr{}
	buf := make([]byte, ControlFrameLength)
	if err := EncodeControlFrame(buf, frame); err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
	}
	buf[44] = 1
	if _, err := DecodeControlFrame(buf); !errors.Is(err, ErrControlReserved) {
		t.Fatalf("DecodeControlFrame error = %v, want %v", err, ErrControlReserved)
	}
}

func TestDownPathFlagAndModeRules(t *testing.T) {
	t.Parallel()

	base := ControlFrame{
		Type:          ControlDownRegister,
		Transport:     TransportUDP,
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		InstanceNonce: 1,
		DownServer:    netip.MustParseAddr("203.0.113.5"),
	}
	tests := []struct {
		name  string
		alter func(*ControlFrame)
		err   error
	}{
		{name: "no down server", alter: func(frame *ControlFrame) { frame.DownServer = netip.Addr{} }, err: ErrControlAddress},
		{name: "unknown down mode", alter: func(frame *ControlFrame) { frame.DownMode = MaxDownMode + 1 }, err: ErrControlMode},
		{name: "down flag on a register", alter: func(frame *ControlFrame) {
			frame.Type = ControlRegister
			frame.DownServer = netip.Addr{}
			frame.Flags = ControlFlagDownPath
		}, err: ErrControlFlags},
		{name: "down flag on a probe", alter: func(frame *ControlFrame) {
			frame.Type = ControlProbe
			frame.DownServer = netip.Addr{}
			frame.Flags = ControlFlagDownPath
		}},
		{name: "bridge flag on a down register", alter: func(frame *ControlFrame) {
			frame.Flags = ControlFlagBridge | ControlFlagReturnIP
			frame.ReturnIP = netip.MustParseAddr("198.51.100.7")
		}},
		{name: "bridge flag on a register", alter: func(frame *ControlFrame) {
			frame.Type = ControlRegister
			frame.DownServer = netip.Addr{}
			frame.Flags = ControlFlagBridge
		}, err: ErrControlFlags},
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
