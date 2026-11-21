package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func TestWrapForBridgeRoundTrip(t *testing.T) {
	t.Parallel()

	client, member := netip.MustParseAddr("160.119.74.74"), netip.MustParseAddr("87.107.117.193")
	server, bridge := netip.MustParseAddr("46.102.130.95"), netip.MustParseAddr("5.6.7.8")
	echo := []byte{8, 0, 0, 0, 0x23, 0xf0, 0, 9, 4, 0, 0, 9, 1, 2, 3, 4}
	inner := make([]byte, 20+len(echo))
	inner[0] = 0x45
	binary.BigEndian.PutUint16(inner[2:4], uint16(len(inner)))
	inner[8] = 64
	inner[9] = IPProtocolICMP
	copy(inner[12:16], client.AsSlice())
	copy(inner[16:20], member.AsSlice())
	binary.BigEndian.PutUint16(inner[10:12], ipv4HeaderChecksum(inner[:20]))
	copy(inner[20:], echo)

	wrapped := WrapForBridge(inner, server, bridge, 9200)
	if len(wrapped) != len(inner)+BridgeOverhead || wrapped[9] != 17 {
		t.Fatalf("wrapped length %d, protocol %d", len(wrapped), wrapped[9])
	}
	if !bytes.Equal(wrapped[12:16], server.AsSlice()) || !bytes.Equal(wrapped[16:20], bridge.AsSlice()) {
		t.Fatalf("outer addresses %v to %v", wrapped[12:16], wrapped[16:20])
	}
	if binary.BigEndian.Uint16(wrapped[20:22]) != 9200 || binary.BigEndian.Uint16(wrapped[22:24]) != 9200 ||
		binary.BigEndian.Uint16(wrapped[24:26]) != uint16(len(inner)) || binary.BigEndian.Uint16(wrapped[26:28]) != 0 {
		t.Fatalf("outer UDP header %x", wrapped[20:28])
	}
	if !bytes.Equal(wrapped[28:32], []byte{0x4d, 0x42, 1, IPProtocolICMP}) {
		t.Fatalf("bridge header %x", wrapped[28:40])
	}
	if ipv4HeaderChecksum(wrapped[:20]) != binary.BigEndian.Uint16(wrapped[10:12]) {
		t.Fatal("outer IPv4 checksum is invalid")
	}
	unwrapped, err := UnwrapBridge(wrapped)
	if err != nil {
		t.Fatalf("UnwrapBridge: %v", err)
	}
	if !bytes.Equal(unwrapped, inner) {
		t.Fatalf("unwrapped = %x, want %x", unwrapped, inner)
	}
	wrapped[28] = 0
	if _, err := UnwrapBridge(wrapped); !errors.Is(err, ErrBridgeWrapper) {
		t.Fatalf("UnwrapBridge with a bad magic: %v", err)
	}
}

func TestBridgeDropReasonNames(t *testing.T) {
	t.Parallel()

	for reason, want := range map[DropReason]string{
		DropBridgeSource: "BRIDGE_SOURCE",
		DropBridgePacket: "BRIDGE_PACKET",
		DropBridgeSize:   "BRIDGE_SIZE",
	} {
		if got := reason.String(); got != want {
			t.Fatalf("%d.String() = %q, want %q", reason, got, want)
		}
	}
	if DropBridgeSize != 25 {
		t.Fatalf("DropBridgeSize = %d, want 25 as in mup_abi.h", DropBridgeSize)
	}
}
