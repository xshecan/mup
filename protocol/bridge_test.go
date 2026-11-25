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

// echoReplyPacket builds an IPv4 ICMP Echo Reply from source to destination
// with a valid ICMP checksum.
func echoReplyPacket(source, destination netip.Addr, identifier, sequence uint16, payload []byte) []byte {
	packet := make([]byte, 20+8+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:6], 0x1234)
	packet[6] = 0x40
	packet[8] = 61
	packet[9] = IPProtocolICMP
	copy(packet[12:16], source.AsSlice())
	copy(packet[16:20], destination.AsSlice())
	binary.BigEndian.PutUint16(packet[10:12], ipv4HeaderChecksum(packet[:20]))
	icmp := packet[20:]
	binary.BigEndian.PutUint16(icmp[4:6], identifier)
	binary.BigEndian.PutUint16(icmp[6:8], sequence)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], internetChecksum(icmp))
	return packet
}

func TestWrapForBridgeEchoRoundTrip(t *testing.T) {
	t.Parallel()

	client, bridge := netip.MustParseAddr("160.119.74.74"), netip.MustParseAddr("5.6.7.8")
	member := netip.MustParseAddr("87.107.117.193")
	for _, length := range []int{32, 33, 148} {
		payload := make([]byte, length)
		for index := range payload {
			payload[index] = byte(index*7 + 3)
		}
		payload[0], payload[1], payload[2], payload[3] = 4, 0, 0, 9
		inner := echoReplyPacket(bridge, client, 9300, 9, payload)

		wrapped := WrapForBridgeEcho(inner, bridge, member, 9300, 9417)
		if len(wrapped) != len(inner)+BridgeOverhead || int(binary.BigEndian.Uint16(wrapped[2:4])) != len(wrapped) {
			t.Fatalf("length %d: wrapped length %d, total length %d", length, len(wrapped), binary.BigEndian.Uint16(wrapped[2:4]))
		}
		if wrapped[0] != 0x45 || wrapped[9] != IPProtocolICMP || !bytes.Equal(wrapped[4:9], inner[4:9]) {
			t.Fatalf("length %d: outer header %x, want ICMP with the other fields of %x", length, wrapped[:20], inner[:20])
		}
		if !bytes.Equal(wrapped[12:16], bridge.AsSlice()) || !bytes.Equal(wrapped[16:20], member.AsSlice()) {
			t.Fatalf("length %d: outer addresses %v to %v, want the bridge to the member", length, wrapped[12:16], wrapped[16:20])
		}
		if ipv4HeaderChecksum(wrapped[:20]) != binary.BigEndian.Uint16(wrapped[10:12]) {
			t.Fatalf("length %d: outer IPv4 checksum is invalid", length)
		}
		icmp := wrapped[20:]
		if icmp[0] != 8 || icmp[1] != 0 || binary.BigEndian.Uint16(icmp[4:6]) != 9300 || binary.BigEndian.Uint16(icmp[6:8]) != 9417 {
			t.Fatalf("length %d: Echo header %x, want an Echo Request with identifier 9300 and sequence 9417", length, icmp[:8])
		}
		if !bytes.Equal(icmp[8:12], []byte{0x4d, 0x42, 1, IPProtocolICMP}) ||
			!bytes.Equal(icmp[12:16], bridge.AsSlice()) || !bytes.Equal(icmp[16:20], client.AsSlice()) {
			t.Fatalf("length %d: bridge header %x", length, icmp[8:20])
		}
		if !bytes.Equal(icmp[BridgeOverhead:], inner[20:]) {
			t.Fatalf("length %d: the inner message moved or changed", length)
		}
		// The whole ICMP message sums to 0xffff.
		if sum := checksumFold(sumWords(icmp, 0)); sum != 0xffff {
			t.Fatalf("length %d: ICMP sum = %#04x, want 0xffff", length, sum)
		}
		// The inner message has a valid checksum, so the checksum of the 20
		// wrapper bytes alone is the checksum of the whole message, as the
		// dataplane computes it.
		header := bytes.Clone(icmp[:BridgeOverhead])
		header[2], header[3] = 0, 0
		if shortcut := internetChecksum(header); shortcut != binary.BigEndian.Uint16(icmp[2:4]) {
			t.Fatalf("length %d: header-only checksum %#04x, full checksum %#04x", length, shortcut, binary.BigEndian.Uint16(icmp[2:4]))
		}

		unwrapped, err := UnwrapBridge(wrapped)
		if err != nil {
			t.Fatalf("length %d: UnwrapBridge of the Echo Request: %v", length, err)
		}
		if !bytes.Equal(unwrapped, inner) {
			t.Fatalf("length %d: unwrapped = %x, want %x", length, unwrapped, inner)
		}

		// The member answers with an Echo Reply to the bridge, with the same
		// identifier, sequence and payload, and the bridge unwraps it.
		reply := bytes.Clone(wrapped)
		copy(reply[12:16], member.AsSlice())
		copy(reply[16:20], bridge.AsSlice())
		binary.BigEndian.PutUint16(reply[10:12], ipv4HeaderChecksum(reply[:20]))
		reply[20] = 0
		reply[22], reply[23] = 0, 0
		binary.BigEndian.PutUint16(reply[22:24], internetChecksum(reply[20:]))
		unwrapped, err = UnwrapBridge(reply)
		if err != nil {
			t.Fatalf("length %d: UnwrapBridge of the Echo Reply: %v", length, err)
		}
		if !bytes.Equal(unwrapped, inner) {
			t.Fatalf("length %d: unwrapped reply = %x, want %x", length, unwrapped, inner)
		}
	}
}

func TestUnwrapBridgeRejectsOtherICMPAndProtocols(t *testing.T) {
	t.Parallel()

	client, bridge := netip.MustParseAddr("160.119.74.74"), netip.MustParseAddr("5.6.7.8")
	member := netip.MustParseAddr("87.107.117.193")
	inner := echoReplyPacket(bridge, client, 9300, 9, []byte{4, 0, 0, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	wrapped := WrapForBridgeEcho(inner, bridge, member, 9300, 9300)
	for name, change := range map[string]func([]byte){
		"destination unreachable": func(packet []byte) { packet[20] = 3 },
		"nonzero code":            func(packet []byte) { packet[21] = 1 },
		"TCP":                     func(packet []byte) { packet[9] = 6 },
		"bad magic":               func(packet []byte) { packet[28] = 0 },
	} {
		packet := bytes.Clone(wrapped)
		change(packet)
		if _, err := UnwrapBridge(packet); !errors.Is(err, ErrBridgeWrapper) {
			t.Fatalf("%s: UnwrapBridge error = %v, want ErrBridgeWrapper", name, err)
		}
	}
}
