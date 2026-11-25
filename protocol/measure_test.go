package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"testing"
)

func measureFrame() ControlFrame {
	return ControlFrame{
		Type:          ControlMeasure,
		Transport:     TransportUDP,
		PathID:        3,
		Sequence:      11,
		ListenPort:    51820,
		ServerPort:    9000,
		LeaseSeconds:  0x01020304,
		InstanceNonce: 0x0102030405060708,
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
	}
}

func reflectMeasureFrame() ControlFrame {
	frame := measureFrame()
	frame.Transport = TransportICMP
	frame.Flags = ControlFlagIngressReflect | ControlFlagReturnIP
	frame.ReturnIP = netip.MustParseAddr("203.0.113.9")
	return frame
}

func TestMeasureFramesRoundTrip(t *testing.T) {
	t.Parallel()

	reply := measureFrame()
	reply.Type = ControlMeasureReply
	reply.PeerCount = 0xfffffffe
	reflectReply := reflectMeasureFrame()
	reflectReply.Type = ControlMeasureReply
	reflectReply.PeerCount = 1
	for name, want := range map[string]ControlFrame{
		"measure":               measureFrame(),
		"reflect measure":       reflectMeasureFrame(),
		"measure reply":         reply,
		"reflect measure reply": reflectReply,
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

func TestMeasureFrameByteOffsets(t *testing.T) {
	t.Parallel()

	frame := measureFrame()
	frame.Type = ControlMeasureReply
	frame.PeerCount = 0x0a0b0c0d
	buf := make([]byte, ControlFrameLength)
	if err := EncodeControlFrame(buf, frame); err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
	}
	want := "4d555043010900" + "00" + "0030" + "0000" + "0003" + "ca6c" + "2328" + "0000" +
		"c000020a" + "00000000" + "0102030405060708" + "0000000b" + "01020304" + "0a0b0c0d"
	if got := hex.EncodeToString(buf); got != want {
		t.Fatalf("encoded frame = %s, want %s", got, want)
	}
	// A MEASURE is the same frame with type 8 and zero at offset 44.
	frame.Type, frame.PeerCount = ControlMeasure, 0
	if err := EncodeControlFrame(buf, frame); err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
	}
	if buf[5] != 8 || binary.BigEndian.Uint32(buf[40:44]) != 0x01020304 || binary.BigEndian.Uint32(buf[44:48]) != 0 {
		t.Fatalf("encoded MEASURE = %x", buf)
	}
}

func TestMeasureFrameRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		base  func() ControlFrame
		alter func(*ControlFrame)
		err   error
	}{
		{name: "measure with a peer count", base: measureFrame, alter: func(f *ControlFrame) { f.PeerCount = 1 }, err: ErrControlReserved},
		{name: "return IP alone", base: measureFrame, alter: func(f *ControlFrame) {
			f.Flags, f.ReturnIP = ControlFlagReturnIP, netip.MustParseAddr("203.0.113.9")
		}, err: ErrControlFlags},
		{name: "egress path flag", base: measureFrame, alter: func(f *ControlFrame) { f.Flags = ControlFlagEgressPath }, err: ErrControlFlags},
		{name: "reflect pool", base: reflectMeasureFrame, alter: func(f *ControlFrame) {
			f.Flags, f.ReturnPrefix = ControlFlagIngressReflect|ControlFlagReturnPool, 28
		}, err: ErrControlFlags},
		{name: "reflect without return IP", base: measureFrame, alter: func(f *ControlFrame) { f.Flags = ControlFlagIngressReflect }, err: ErrControlFlags},
		{name: "source range", base: reflectMeasureFrame, alter: func(f *ControlFrame) {
			f.Flags |= ControlFlagSourceRange
			f.SrcFirst, f.SrcLast = 1, 2
		}, err: ErrControlFlags},
		{name: "peer count in a probe reply", base: measureFrame, alter: func(f *ControlFrame) {
			f.Type, f.PeerCount = ControlProbeReply, 1
		}, err: ErrControlReserved},
		{name: "peer count in an ACK", base: measureFrame, alter: func(f *ControlFrame) {
			f.Type, f.PeerCount = ControlRegisterACK, 1
		}, err: ErrControlReserved},
		{name: "unknown type", base: measureFrame, alter: func(f *ControlFrame) { f.Type = ControlEgressLimit + 1 }, err: ErrControlType},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := tt.base()
			tt.alter(&frame)
			if err := EncodeControlFrame(make([]byte, ControlFrameLength), frame); !errors.Is(err, tt.err) {
				t.Fatalf("EncodeControlFrame error = %v, want %v", err, tt.err)
			}
		})
	}
}

func TestDecodeKeepsTheMeasureTailZero(t *testing.T) {
	t.Parallel()

	buf := make([]byte, ControlFrameLength)
	if err := EncodeControlFrame(buf, reflectMeasureFrame()); err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
	}
	for _, offset := range []int{18, 44, 47} {
		changed := bytes.Clone(buf)
		changed[offset] = 1
		if _, err := DecodeControlFrame(changed); !errors.Is(err, ErrControlReserved) {
			t.Fatalf("offset %d: DecodeControlFrame error = %v, want %v", offset, err, ErrControlReserved)
		}
	}
	// A reply carries its peer count there, but offset 18 stays reserved.
	reply := bytes.Clone(buf)
	reply[5] = byte(ControlMeasureReply)
	reply[47] = 5
	frame, err := DecodeControlFrame(reply)
	if err != nil || frame.PeerCount != 5 {
		t.Fatalf("DecodeControlFrame = %#v, %v, want peer count 5", frame, err)
	}
	reply[18] = 1
	if _, err := DecodeControlFrame(reply); !errors.Is(err, ErrControlReserved) {
		t.Fatalf("DecodeControlFrame error = %v, want %v", err, ErrControlReserved)
	}
	unknown := bytes.Clone(buf)
	unknown[5] = byte(ControlEgressLimit + 1)
	if _, err := DecodeControlFrame(unknown); !errors.Is(err, ErrControlType) {
		t.Fatalf("DecodeControlFrame error = %v, want %v", err, ErrControlType)
	}
}

// TestOlderFramesKeepTheirBytes holds bytes that the codec of v0.5.2 encoded,
// so the frames that older peers read stay the same. A PROBE and a PROBE_REPLY
// of an egress path carry a count code in the lease field, which an older
// decoder accepts.
func TestOlderFramesKeepTheirBytes(t *testing.T) {
	t.Parallel()

	advertised := netip.MustParseAddr("192.0.2.10")
	for name, tt := range map[string]struct {
		frame ControlFrame
		want  string
	}{
		"probe": {ControlFrame{
			Type: ControlProbe, Transport: TransportICMP, Flags: ControlFlagEgressPath, PathID: 2, Sequence: 77,
			ListenPort: 51820, ServerPort: 9200, LeaseSeconds: 0x00012346, InstanceNonce: 0x0102030405060708, AdvertisedIP: advertised,
		}, "4d55504301030108003000000002ca6c23f00000c000020a0000000001020304050607080000004d0001234600000000"},
		"probe reply": {ControlFrame{
			Type: ControlProbeReply, Transport: TransportUDP, Flags: ControlFlagEgressPath | ControlFlagReturnIP, PathID: 1, Sequence: 78,
			ListenPort: 51820, ServerPort: 9300, LeaseSeconds: 0xfffffffe, InstanceNonce: 0x0102030405060708, AdvertisedIP: advertised,
			ReturnIP: netip.MustParseAddr("203.0.113.4"),
		}, "4d55504301040009003000000001ca6c24540000c000020acb00710401020304050607080000004efffffffe00000000"},
		"reflect ack": {ControlFrame{
			Type: ControlRegisterACK, Transport: TransportUDP, Flags: ControlFlagIngressReflect | ControlFlagReturnIP, PathID: 4, Sequence: 5,
			ListenPort: 51820, ServerPort: 9000, LeaseSeconds: 30, InstanceNonce: 0x0102030405060708, AdvertisedIP: advertised,
			ReturnIP: netip.MustParseAddr("203.0.113.9"),
		}, "4d55504301020021003000000004ca6c23280000c000020acb0071090102030405060708000000050000001e00000000"},
	} {
		t.Run(name, func(t *testing.T) {
			buf := make([]byte, ControlFrameLength)
			if err := EncodeControlFrame(buf, tt.frame); err != nil {
				t.Fatalf("EncodeControlFrame: %v", err)
			}
			if got := hex.EncodeToString(buf); got != tt.want {
				t.Fatalf("encoded frame = %s, want %s", got, tt.want)
			}
			decoded, err := DecodeControlFrame(buf)
			if err != nil || decoded != tt.frame {
				t.Fatalf("DecodeControlFrame = %#v, %v, want %#v", decoded, err, tt.frame)
			}
		})
	}
}
