package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"testing"
)

func egressLimitFrame() ControlFrame {
	return ControlFrame{
		Type:          ControlEgressLimit,
		Transport:     TransportICMP,
		PathID:        2,
		ListenPort:    51820,
		ServerPort:    9300,
		InstanceNonce: 0x0102030405060708,
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		LimitKbps:     10_000,
		LimitFlags:    EgressLimitPerMember,
	}
}

func TestEgressLimitRoundTrip(t *testing.T) {
	t.Parallel()

	plain := egressLimitFrame()
	plain.LimitFlags = 0
	removal := egressLimitFrame()
	removal.LimitKbps, removal.LimitFlags = 0, 0
	largest := egressLimitFrame()
	largest.Transport, largest.LimitKbps = TransportUDP, MaxEgressLimitKbps
	smallest := egressLimitFrame()
	smallest.LimitKbps = MinEgressLimitKbps
	for name, want := range map[string]ControlFrame{
		"per member": egressLimitFrame(),
		"plain":      plain,
		"removal":    removal,
		"largest":    largest,
		"smallest":   smallest,
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

func TestEgressLimitByteOffsets(t *testing.T) {
	t.Parallel()

	buf := make([]byte, ControlFrameLength)
	if err := EncodeControlFrame(buf, egressLimitFrame()); err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
	}
	want := "4d555043010a0100" + "0030" + "0000" + "0002" + "ca6c" + "2454" + "0000" +
		"c000020a" + "00000000" + "0102030405060708" + "00002710" + "00000001" + "00000000"
	if got := hex.EncodeToString(buf); got != want {
		t.Fatalf("encoded frame = %s, want %s", got, want)
	}
}

// TestEgressLimitSharesTheHeadOfTheEgressRegister checks that the first 36
// bytes of an EGRESS_LIMIT are those of the EGRESS_REGISTER of the same path
// without its flags, its mode and its return IP.
func TestEgressLimitSharesTheHeadOfTheEgressRegister(t *testing.T) {
	t.Parallel()

	limit := egressLimitFrame()
	register := ControlFrame{
		Type:          ControlEgressRegister,
		Transport:     limit.Transport,
		PathID:        limit.PathID,
		ListenPort:    limit.ListenPort,
		ServerPort:    limit.ServerPort,
		Sequence:      9,
		LeaseSeconds:  30,
		InstanceNonce: limit.InstanceNonce,
		AdvertisedIP:  limit.AdvertisedIP,
		EgressServer:  netip.MustParseAddr("198.51.100.1"),
	}
	limitBytes := make([]byte, ControlFrameLength)
	registerBytes := make([]byte, ControlFrameLength)
	if err := EncodeControlFrame(limitBytes, limit); err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
	}
	if err := EncodeControlFrame(registerBytes, register); err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
	}
	registerBytes[5] = byte(ControlEgressLimit)
	if !bytes.Equal(limitBytes[:36], registerBytes[:36]) {
		t.Fatalf("head = %x, want %x", limitBytes[:36], registerBytes[:36])
	}
}

func TestEgressLimitRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		alter func(*ControlFrame)
		err   error
	}{
		{name: "a frame flag", alter: func(f *ControlFrame) { f.Flags = ControlFlagBridge }, err: ErrControlFlags},
		{name: "a return IP", alter: func(f *ControlFrame) {
			f.Flags, f.ReturnIP = ControlFlagReturnIP, netip.MustParseAddr("203.0.113.9")
		}, err: ErrControlFlags},
		{name: "an unknown limit flag", alter: func(f *ControlFrame) { f.LimitFlags = 2 }, err: ErrControlFlags},
		{name: "per member without a rate", alter: func(f *ControlFrame) { f.LimitKbps = 0 }, err: ErrControlFlags},
		{name: "a rate below 8 kbit", alter: func(f *ControlFrame) { f.LimitKbps = MinEgressLimitKbps - 1 }, err: ErrControlRate},
		{name: "a rate above 100 gbit", alter: func(f *ControlFrame) { f.LimitKbps = MaxEgressLimitKbps + 1 }, err: ErrControlRate},
		{name: "a sequence", alter: func(f *ControlFrame) { f.Sequence = 1 }, err: ErrControlReserved},
		{name: "a lease", alter: func(f *ControlFrame) { f.LeaseSeconds = 30 }, err: ErrControlReserved},
		{name: "an egress mode", alter: func(f *ControlFrame) { f.EgressMode = 1 }, err: ErrControlReserved},
		{name: "an egress server", alter: func(f *ControlFrame) { f.EgressServer = netip.MustParseAddr("198.51.100.1") }, err: ErrControlReserved},
		{name: "a source range", alter: func(f *ControlFrame) {
			f.Flags, f.SrcFirst, f.SrcLast = ControlFlagSourceRange, 1, 2
		}, err: ErrControlFlags},
		{name: "a rate in an EGRESS_REGISTER", alter: func(f *ControlFrame) {
			f.Type, f.EgressServer, f.LimitFlags = ControlEgressRegister, netip.MustParseAddr("198.51.100.1"), 0
		}, err: ErrControlReserved},
		{name: "limit flags in a REGISTER", alter: func(f *ControlFrame) { f.Type, f.LimitKbps = ControlRegister, 0 }, err: ErrControlReserved},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := egressLimitFrame()
			tt.alter(&frame)
			if err := EncodeControlFrame(make([]byte, ControlFrameLength), frame); !errors.Is(err, tt.err) {
				t.Fatalf("EncodeControlFrame error = %v, want %v", err, tt.err)
			}
		})
	}
}

func TestDecodeChecksTheEgressLimitBytes(t *testing.T) {
	t.Parallel()

	buf := make([]byte, ControlFrameLength)
	if err := EncodeControlFrame(buf, egressLimitFrame()); err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
	}
	for offset, want := range map[int]error{
		7:  ErrControlFlags,
		18: ErrControlReserved,
		19: ErrControlReserved,
		24: ErrControlReserved,
		43: ErrControlFlags,
		44: ErrControlReserved,
		47: ErrControlReserved,
	} {
		changed := bytes.Clone(buf)
		changed[offset] |= 0x02
		if _, err := DecodeControlFrame(changed); !errors.Is(err, want) {
			t.Fatalf("offset %d: DecodeControlFrame error = %v, want %v", offset, err, want)
		}
	}
	tooFast := bytes.Clone(buf)
	binary.BigEndian.PutUint32(tooFast[36:40], MaxEgressLimitKbps+1)
	if _, err := DecodeControlFrame(tooFast); !errors.Is(err, ErrControlRate) {
		t.Fatalf("DecodeControlFrame error = %v, want %v", err, ErrControlRate)
	}
	// The rate and its flags never show as a sequence or a lease.
	frame, err := DecodeControlFrame(buf)
	if err != nil || frame.Sequence != 0 || frame.LeaseSeconds != 0 || frame.LimitKbps != 10_000 || frame.LimitFlags != EgressLimitPerMember {
		t.Fatalf("DecodeControlFrame = %#v, %v", frame, err)
	}
	unknown := bytes.Clone(buf)
	unknown[5] = byte(ControlEgressLimit + 1)
	if _, err := DecodeControlFrame(unknown); !errors.Is(err, ErrControlType) {
		t.Fatalf("DecodeControlFrame error = %v, want %v", err, ErrControlType)
	}
}
