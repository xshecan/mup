package protocol

import (
	"errors"
	"net/netip"
	"testing"
)

func TestControlFramePoolRoundTrip(t *testing.T) {
	t.Parallel()
	frame := ControlFrame{
		Type:          ControlRegister,
		Transport:     TransportICMP,
		Flags:         ControlFlagReturnPool | ControlFlagBalancePerPacket,
		PathID:        2,
		ServerPort:    5300,
		ListenPort:    51899,
		InstanceNonce: 0x1122334455667788,
		AdvertisedIP:  netip.MustParseAddr("203.0.113.5"),
		ReturnIP:      netip.MustParseAddr("194.225.72.0"),
		ReturnPrefix:  24,
	}
	buffer := make([]byte, ControlFrameLength)
	if err := EncodeControlFrame(buffer, frame); err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeControlFrame(buffer)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded != frame {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", decoded, frame)
	}
}

func TestControlFramePoolValidation(t *testing.T) {
	t.Parallel()
	base := func() ControlFrame {
		return ControlFrame{
			Type:          ControlRegister,
			Transport:     TransportICMP,
			ServerPort:    5300,
			ListenPort:    51899,
			InstanceNonce: 1,
			AdvertisedIP:  netip.MustParseAddr("203.0.113.5"),
		}
	}
	tests := []struct {
		name  string
		build func(ControlFrame) ControlFrame
		want  error
	}{
		{"pool and ip together", func(f ControlFrame) ControlFrame {
			f.Flags = ControlFlagReturnIP | ControlFlagReturnPool
			f.ReturnIP = netip.MustParseAddr("194.225.72.0")
			f.ReturnPrefix = 24
			return f
		}, ErrControlFlags},
		{"balance without pool", func(f ControlFrame) ControlFrame {
			f.Flags = ControlFlagReturnIP | ControlFlagBalancePerPacket
			f.ReturnIP = netip.MustParseAddr("194.225.72.10")
			return f
		}, ErrControlFlags},
		{"pool prefix zero", func(f ControlFrame) ControlFrame {
			f.Flags = ControlFlagReturnPool
			f.ReturnIP = netip.MustParseAddr("194.225.72.0")
			f.ReturnPrefix = 0
			return f
		}, ErrControlPrefix},
		{"pool prefix 32", func(f ControlFrame) ControlFrame {
			f.Flags = ControlFlagReturnPool
			f.ReturnIP = netip.MustParseAddr("194.225.72.10")
			f.ReturnPrefix = 32
			return f
		}, ErrControlPrefix},
		{"prefix without pool", func(f ControlFrame) ControlFrame {
			f.ReturnPrefix = 24
			return f
		}, ErrControlFlags},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buffer := make([]byte, ControlFrameLength)
			err := EncodeControlFrame(buffer, tt.build(base()))
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
}

// TestControlFrameSingleReturnStillValid guards the existing single return IP.
func TestControlFrameSingleReturnStillValid(t *testing.T) {
	t.Parallel()
	frame := ControlFrame{
		Type:          ControlRegister,
		Transport:     TransportUDP,
		Flags:         ControlFlagReturnIP,
		ServerPort:    5300,
		ListenPort:    51899,
		InstanceNonce: 1,
		AdvertisedIP:  netip.MustParseAddr("203.0.113.5"),
		ReturnIP:      netip.MustParseAddr("194.225.72.10"),
	}
	buffer := make([]byte, ControlFrameLength)
	if err := EncodeControlFrame(buffer, frame); err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeControlFrame(buffer)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded != frame {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", decoded, frame)
	}
}
