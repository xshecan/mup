package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
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

func TestIngressReflectRoundTrip(t *testing.T) {
	t.Parallel()

	want := ControlFrame{
		Type:          ControlRegister,
		Transport:     TransportICMP,
		Flags:         ControlFlagIngressReflect | ControlFlagReturnPool | ControlFlagBalancePerPacket,
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
		{name: "ingress reflect without return", alter: func(frame *ControlFrame) { frame.Flags = ControlFlagIngressReflect }, err: ErrControlFlags},
		{name: "ingress reflect on a probe", alter: func(frame *ControlFrame) {
			frame.Type = ControlProbe
			frame.Flags = ControlFlagIngressReflect | ControlFlagReturnIP
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

func TestEgressRegisterRoundTrip(t *testing.T) {
	t.Parallel()

	want := ControlFrame{
		Type:          ControlEgressRegister,
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
		EgressMode:    2,
		EgressServer:  netip.MustParseAddr("203.0.113.5"),
	}
	buf := make([]byte, ControlFrameLength)
	if err := EncodeControlFrame(buf, want); err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
	}
	if buf[18] != 2 || !bytes.Equal(buf[44:48], []byte{203, 0, 113, 5}) {
		t.Fatalf("egress mode byte = %d, server bytes = %v", buf[18], buf[44:48])
	}
	got, err := DecodeControlFrame(buf)
	if err != nil {
		t.Fatalf("DecodeControlFrame: %v", err)
	}
	if got != want {
		t.Fatalf("decoded frame = %#v, want %#v", got, want)
	}
}

// A server before v0.4.0 must ignore a EGRESS_REGISTER. Its decoder rejects the
// type and the reserved bytes, so the frame never reaches its registry.
func TestEgressFieldsStayReservedInOtherFrames(t *testing.T) {
	t.Parallel()

	frame := ControlFrame{
		Type:          ControlRegister,
		Transport:     TransportUDP,
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		InstanceNonce: 1,
		EgressServer:  netip.MustParseAddr("203.0.113.5"),
	}
	if err := EncodeControlFrame(make([]byte, ControlFrameLength), frame); !errors.Is(err, ErrControlReserved) {
		t.Fatalf("EncodeControlFrame error = %v, want %v", err, ErrControlReserved)
	}
	frame.EgressServer = netip.Addr{}
	buf := make([]byte, ControlFrameLength)
	if err := EncodeControlFrame(buf, frame); err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
	}
	buf[44] = 1
	if _, err := DecodeControlFrame(buf); !errors.Is(err, ErrControlReserved) {
		t.Fatalf("DecodeControlFrame error = %v, want %v", err, ErrControlReserved)
	}
}

func TestEgressPathFlagAndModeRules(t *testing.T) {
	t.Parallel()

	base := ControlFrame{
		Type:          ControlEgressRegister,
		Transport:     TransportUDP,
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		InstanceNonce: 1,
		EgressServer:  netip.MustParseAddr("203.0.113.5"),
	}
	tests := []struct {
		name  string
		alter func(*ControlFrame)
		err   error
	}{
		{name: "no egress server", alter: func(frame *ControlFrame) { frame.EgressServer = netip.Addr{} }, err: ErrControlAddress},
		{name: "unknown egress mode", alter: func(frame *ControlFrame) { frame.EgressMode = MaxEgressMode + 1 }, err: ErrControlMode},
		{name: "egress flag on a register", alter: func(frame *ControlFrame) {
			frame.Type = ControlRegister
			frame.EgressServer = netip.Addr{}
			frame.Flags = ControlFlagEgressPath
		}, err: ErrControlFlags},
		{name: "egress flag on a probe", alter: func(frame *ControlFrame) {
			frame.Type = ControlProbe
			frame.EgressServer = netip.Addr{}
			frame.Flags = ControlFlagEgressPath
		}},
		{name: "bridge flag on an egress register", alter: func(frame *ControlFrame) {
			frame.Flags = ControlFlagBridge | ControlFlagReturnIP
			frame.ReturnIP = netip.MustParseAddr("198.51.100.7")
		}},
		{name: "bridge flag on a register", alter: func(frame *ControlFrame) {
			frame.Type = ControlRegister
			frame.EgressServer = netip.Addr{}
			frame.Flags = ControlFlagBridge
		}, err: ErrControlFlags},
		{name: "bridge via with a return IP", alter: func(frame *ControlFrame) {
			frame.Flags = ControlFlagBridge | ControlFlagBridgeVia | ControlFlagReturnIP
			frame.ReturnIP = netip.MustParseAddr("198.51.100.7")
		}},
		{name: "bridge via with a return pool", alter: func(frame *ControlFrame) {
			frame.Flags = ControlFlagBridge | ControlFlagBridgeVia | ControlFlagReturnPool | ControlFlagBalancePerPacket
			frame.ReturnIP = netip.MustParseAddr("198.51.100.0")
			frame.ReturnPrefix = 28
		}},
		{name: "bridge via without the bridge flag", alter: func(frame *ControlFrame) {
			frame.Flags = ControlFlagBridgeVia | ControlFlagReturnIP
			frame.ReturnIP = netip.MustParseAddr("198.51.100.7")
		}, err: ErrControlFlags},
		{name: "bridge via without a return IP or pool", alter: func(frame *ControlFrame) {
			frame.Flags = ControlFlagBridge | ControlFlagBridgeVia
		}, err: ErrControlFlags},
		{name: "bridge via on a register", alter: func(frame *ControlFrame) {
			frame.Type = ControlRegister
			frame.EgressServer = netip.Addr{}
			frame.Flags = ControlFlagBridgeVia | ControlFlagReturnIP
			frame.ReturnIP = netip.MustParseAddr("198.51.100.7")
		}, err: ErrControlFlags},
		{name: "bridge via on a probe", alter: func(frame *ControlFrame) {
			frame.Type = ControlProbe
			frame.EgressServer = netip.Addr{}
			frame.Flags = ControlFlagBridge | ControlFlagBridgeVia | ControlFlagReturnIP
			frame.ReturnIP = netip.MustParseAddr("198.51.100.7")
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

func TestBridgeViaEgressRegisterRoundTrip(t *testing.T) {
	t.Parallel()

	want := ControlFrame{
		Type:          ControlEgressRegister,
		Transport:     TransportUDP,
		Flags:         ControlFlagBridge | ControlFlagBridgeVia | ControlFlagReturnIP,
		PathID:        1,
		ListenPort:    51820,
		ServerPort:    9300,
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		ReturnIP:      netip.MustParseAddr("198.51.100.7"),
		InstanceNonce: 7,
		Sequence:      4,
		LeaseSeconds:  30,
		EgressServer:  netip.MustParseAddr("192.0.2.80"),
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

// The server puts the member that answers an egress path in the return IP of
// its PROBE, and the client echoes it in the PROBE_REPLY.
func TestEgressProbeWithAReturnIPRoundTrips(t *testing.T) {
	t.Parallel()

	for _, frameType := range []ControlType{ControlProbe, ControlProbeReply} {
		want := ControlFrame{
			Type:          frameType,
			Transport:     TransportICMP,
			Flags:         ControlFlagEgressPath | ControlFlagReturnIP,
			PathID:        2,
			ListenPort:    51820,
			ServerPort:    9300,
			AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
			ReturnIP:      netip.MustParseAddr("198.51.100.40"),
			InstanceNonce: 7,
			Sequence:      5,
		}
		buf := make([]byte, ControlFrameLength)
		if err := EncodeControlFrame(buf, want); err != nil {
			t.Fatalf("type %d: EncodeControlFrame: %v", frameType, err)
		}
		got, err := DecodeControlFrame(buf)
		if err != nil {
			t.Fatalf("type %d: DecodeControlFrame: %v", frameType, err)
		}
		if got != want {
			t.Fatalf("type %d: decoded frame = %#v, want %#v", frameType, got, want)
		}
	}
}

func sourceRangeRegister() ControlFrame {
	return ControlFrame{
		Type:          ControlRegister,
		Transport:     TransportUDP,
		Flags:         ControlFlagSourceRange,
		PathID:        1,
		ListenPort:    51820,
		ServerPort:    5000,
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		InstanceNonce: 0x0102030405060708,
		Sequence:      42,
		LeaseSeconds:  30,
		SrcFirst:      20000,
		SrcLast:       29999,
	}
}

func sourceRangeEgressRegister() ControlFrame {
	return ControlFrame{
		Type:          ControlEgressRegister,
		Transport:     TransportUDP,
		Flags:         ControlFlagSourceRange,
		PathID:        2,
		ListenPort:    51825,
		ServerPort:    5000,
		LeaseSeconds:  30,
		InstanceNonce: 0x0102030405060708,
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		EgressMode:    1,
		EgressServer:  netip.MustParseAddr("203.0.113.7"),
		SrcFirst:      5000,
		SrcLast:       50000,
	}
}

func TestSourceRangeRegisterRoundTrip(t *testing.T) {
	t.Parallel()

	returnPool := sourceRangeRegister()
	returnPool.Flags |= ControlFlagReturnPool | ControlFlagBalancePerPacket
	returnPool.ReturnIP = netip.MustParseAddr("87.107.117.192")
	returnPool.ReturnPrefix = 28
	reflect := sourceRangeRegister()
	reflect.Flags |= ControlFlagIngressReflect | ControlFlagReturnIP
	reflect.ReturnIP = netip.MustParseAddr("178.160.228.1")
	single := sourceRangeRegister()
	single.SrcFirst, single.SrcLast = 6000, 6000
	icmp := sourceRangeRegister()
	icmp.Transport = TransportICMP
	for name, want := range map[string]ControlFrame{
		"plain": sourceRangeRegister(), "pool": returnPool, "ingress reflect": reflect,
		"range of one": single, "icmp": icmp,
	} {
		t.Run(name, func(t *testing.T) {
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
		})
	}
}

func TestSourceRangeEgressRegisterRoundTrip(t *testing.T) {
	t.Parallel()

	pool := sourceRangeEgressRegister()
	pool.Flags |= ControlFlagReturnPool | ControlFlagBalancePerPacket
	pool.ReturnIP = netip.MustParseAddr("87.107.117.192")
	pool.ReturnPrefix = 28
	bridge := sourceRangeEgressRegister()
	bridge.Flags |= ControlFlagBridge
	via := sourceRangeEgressRegister()
	via.Flags |= ControlFlagBridge | ControlFlagBridgeVia | ControlFlagReturnIP
	via.ReturnIP = netip.MustParseAddr("178.160.228.1")
	icmp := sourceRangeEgressRegister()
	icmp.Transport = TransportICMP
	for name, want := range map[string]ControlFrame{
		"plain": sourceRangeEgressRegister(), "pool": pool, "bridge": bridge,
		"bridge via": via, "icmp": icmp,
	} {
		t.Run(name, func(t *testing.T) {
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
		})
	}
}

func TestSourceRangeByteOffsets(t *testing.T) {
	t.Parallel()

	register := make([]byte, ControlFrameLength)
	if err := EncodeControlFrame(register, sourceRangeRegister()); err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
	}
	if got := binary.BigEndian.Uint16(register[44:46]); got != 20000 {
		t.Fatalf("REGISTER first = %d, want 20000", got)
	}
	if got := binary.BigEndian.Uint16(register[46:48]); got != 29999 {
		t.Fatalf("REGISTER last = %d, want 29999", got)
	}
	if got := binary.BigEndian.Uint32(register[36:40]); got != 42 {
		t.Fatalf("REGISTER sequence = %d, want 42", got)
	}
	if register[7]&ControlFlagSourceRange == 0 {
		t.Fatal("REGISTER lacks the source range flag")
	}
	egress := make([]byte, ControlFrameLength)
	if err := EncodeControlFrame(egress, sourceRangeEgressRegister()); err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
	}
	if got := binary.BigEndian.Uint16(egress[36:38]); got != 5000 {
		t.Fatalf("EGRESS_REGISTER first = %d, want 5000", got)
	}
	if got := binary.BigEndian.Uint16(egress[38:40]); got != 50000 {
		t.Fatalf("EGRESS_REGISTER last = %d, want 50000", got)
	}
	if want := []byte{203, 0, 113, 7}; !bytes.Equal(egress[44:48], want) {
		t.Fatalf("EGRESS_REGISTER server bytes = %v, want %v", egress[44:48], want)
	}
}

func TestSourceRangeRegisterLooksReservedToAnOldDecoder(t *testing.T) {
	t.Parallel()

	buf := make([]byte, ControlFrameLength)
	if err := EncodeControlFrame(buf, sourceRangeRegister()); err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
	}
	if buf[44] == 0 && buf[45] == 0 && buf[46] == 0 && buf[47] == 0 {
		t.Fatal("bytes 44 to 47 of a ranged REGISTER are all zero")
	}
	// Without the flag, the decoder still requires the bytes to be zero.
	buf[7] &^= ControlFlagSourceRange
	if _, err := DecodeControlFrame(buf); !errors.Is(err, ErrControlReserved) {
		t.Fatalf("DecodeControlFrame error = %v, want %v", err, ErrControlReserved)
	}
}

func TestFramesWithoutASourceRangeKeepTheirBytes(t *testing.T) {
	t.Parallel()

	register := ControlFrame{
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
	egress := sourceRangeEgressRegister()
	egress.Flags, egress.SrcFirst, egress.SrcLast = 0, 0, 0
	egress.Sequence = 9
	for name, tt := range map[string]struct {
		frame ControlFrame
		want  string
	}{
		"register": {register, "4d555043010101" + "01" + "0030" + "0000" + "0003" + "ca6c" + "1388" + "0000" +
			"c000020a" + "c6336408" + "0102030405060708" + "0000002a" + "0000001e" + "00000000"},
		"egress register": {egress, "4d555043010700" + "00" + "0030" + "0000" + "0002" + "ca71" + "1388" + "0100" +
			"c000020a" + "00000000" + "0102030405060708" + "00000009" + "0000001e" + "cb007107"},
	} {
		t.Run(name, func(t *testing.T) {
			buf := make([]byte, ControlFrameLength)
			if err := EncodeControlFrame(buf, tt.frame); err != nil {
				t.Fatalf("EncodeControlFrame: %v", err)
			}
			if got := hex.EncodeToString(buf); got != tt.want {
				t.Fatalf("encoded frame = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestSourceRangeRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		base  func() ControlFrame
		alter func(*ControlFrame)
		err   error
	}{
		{name: "zero first", base: sourceRangeRegister, alter: func(f *ControlFrame) { f.SrcFirst = 0 }, err: ErrControlSourceRange},
		{name: "reversed", base: sourceRangeRegister, alter: func(f *ControlFrame) { f.SrcFirst, f.SrcLast = 9, 8 }, err: ErrControlSourceRange},
		{name: "zero last", base: sourceRangeRegister, alter: func(f *ControlFrame) { f.SrcLast = 0 }, err: ErrControlSourceRange},
		{name: "egress zero first", base: sourceRangeEgressRegister, alter: func(f *ControlFrame) { f.SrcFirst = 0 }, err: ErrControlSourceRange},
		{name: "egress reversed", base: sourceRangeEgressRegister, alter: func(f *ControlFrame) { f.SrcFirst, f.SrcLast = 9, 8 }, err: ErrControlSourceRange},
		{name: "egress with a sequence", base: sourceRangeEgressRegister, alter: func(f *ControlFrame) { f.Sequence = 1 }, err: ErrControlReserved},
		{name: "range without flag", base: sourceRangeRegister, alter: func(f *ControlFrame) { f.Flags = 0 }, err: ErrControlFlags},
		{name: "egress range without flag", base: sourceRangeEgressRegister, alter: func(f *ControlFrame) { f.Flags = 0 }, err: ErrControlFlags},
		{name: "first without flag", base: sourceRangeRegister, alter: func(f *ControlFrame) { f.Flags, f.SrcLast = 0, 0 }, err: ErrControlFlags},
		{name: "ACK", base: sourceRangeRegister, alter: func(f *ControlFrame) { f.Type = ControlRegisterACK }, err: ErrControlFlags},
		{name: "probe", base: sourceRangeRegister, alter: func(f *ControlFrame) { f.Type = ControlProbe }, err: ErrControlFlags},
		{name: "probe reply", base: sourceRangeRegister, alter: func(f *ControlFrame) { f.Type = ControlProbeReply }, err: ErrControlFlags},
		{name: "deregister", base: sourceRangeRegister, alter: func(f *ControlFrame) { f.Type = ControlDeregister }, err: ErrControlFlags},
		{name: "error", base: sourceRangeRegister, alter: func(f *ControlFrame) { f.Type = ControlError }, err: ErrControlFlags},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := tt.base()
			tt.alter(&frame)
			err := EncodeControlFrame(make([]byte, ControlFrameLength), frame)
			if !errors.Is(err, tt.err) {
				t.Fatalf("EncodeControlFrame error = %v, want %v", err, tt.err)
			}
		})
	}
}

func TestDecodeRejectsAnInvalidSourceRange(t *testing.T) {
	t.Parallel()

	buf := make([]byte, ControlFrameLength)
	if err := EncodeControlFrame(buf, sourceRangeRegister()); err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
	}
	reversed := bytes.Clone(buf)
	binary.BigEndian.PutUint16(reversed[44:46], 9)
	binary.BigEndian.PutUint16(reversed[46:48], 8)
	if _, err := DecodeControlFrame(reversed); !errors.Is(err, ErrControlSourceRange) {
		t.Fatalf("DecodeControlFrame error = %v, want %v", err, ErrControlSourceRange)
	}
	zero := bytes.Clone(buf)
	clear(zero[44:48])
	if _, err := DecodeControlFrame(zero); !errors.Is(err, ErrControlSourceRange) {
		t.Fatalf("DecodeControlFrame error = %v, want %v", err, ErrControlSourceRange)
	}
	// An ACK with the flag carries the bytes only in a REGISTER, so it is reserved.
	ack := bytes.Clone(buf)
	ack[5] = byte(ControlRegisterACK)
	if _, err := DecodeControlFrame(ack); !errors.Is(err, ErrControlReserved) {
		t.Fatalf("DecodeControlFrame error = %v, want %v", err, ErrControlReserved)
	}
}
