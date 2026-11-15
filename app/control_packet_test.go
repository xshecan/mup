package app

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/xshecan/mup/protocol"
)

func TestICMPEchoRoundTrip(t *testing.T) {
	t.Parallel()

	payload := bytes.Repeat([]byte{0x5a}, 48)
	packet := marshalICMPEcho(icmpEchoRequest, 5000, 7, payload)
	echo, err := parseICMPEcho(packet)
	if err != nil {
		t.Fatalf("parseICMPEcho: %v", err)
	}
	if echo.echoType != icmpEchoRequest || echo.identifier != 5000 || echo.sequence != 7 ||
		!bytes.Equal(echo.payload, payload) {
		t.Fatalf("echo = %#v", echo)
	}

	packet[2] ^= 0xff
	if _, err := parseICMPEcho(packet); err == nil {
		t.Fatal("corrupted checksum unexpectedly accepted")
	}
}

func TestRegistrationACKRejectsStaleSequence(t *testing.T) {
	t.Parallel()

	packet := make([]byte, protocol.ControlFrameLength)
	err := protocol.EncodeControlFrame(packet, protocol.ControlFrame{
		Type:          protocol.ControlRegisterACK,
		Transport:     protocol.TransportICMP,
		PathID:        2,
		Sequence:      7,
		ListenPort:    51820,
		ServerPort:    5000,
		LeaseSeconds:  30,
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		InstanceNonce: 99,
	})
	if err != nil {
		t.Fatalf("EncodeControlFrame: %v", err)
	}
	if err := validateRegistrationACK(packet, 99, 2, 7); err != nil {
		t.Fatalf("validateRegistrationACK: %v", err)
	}
	if err := validateRegistrationACK(packet, 99, 2, 8); err == nil {
		t.Fatal("stale ACK sequence unexpectedly accepted")
	}
}

func TestRegistrationACKResultReadsTheStatus(t *testing.T) {
	t.Parallel()

	ack := func(status protocol.ControlStatus) []byte {
		packet := make([]byte, protocol.ControlFrameLength)
		err := protocol.EncodeControlFrame(packet, protocol.ControlFrame{
			Type:          protocol.ControlRegisterACK,
			Transport:     protocol.TransportUDP,
			Status:        status,
			PathID:        4,
			Sequence:      3,
			ListenPort:    51821,
			ServerPort:    9002,
			LeaseSeconds:  30,
			AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
			InstanceNonce: 99,
		})
		if err != nil {
			t.Fatalf("EncodeControlFrame: %v", err)
		}
		return packet
	}
	if result, ok := registrationACKResult(ack(protocol.ControlStatusOK), 99, 4, 3); !ok || result != registerAcked {
		t.Fatalf("OK ACK = %v %v, want acked", result, ok)
	}
	if result, ok := registrationACKResult(ack(protocol.ControlStatusNoReflector), 99, 4, 3); !ok || result != registerNoReflector {
		t.Fatalf("no-reflector ACK = %v %v, want no reflector", result, ok)
	}
	if err := validateRegistrationACK(ack(protocol.ControlStatusNoReflector), 99, 4, 3); err == nil {
		t.Fatal("a no-reflector ACK validated as a healthy ACK")
	}
	// A status that the client does not act on is not an answer.
	if _, ok := registrationACKResult(ack(protocol.ControlStatusMalformed), 99, 4, 3); ok {
		t.Fatal("a malformed-status ACK was taken as an answer")
	}
	if _, ok := registrationACKResult(ack(protocol.ControlStatusNoReflector), 99, 4, 2); ok {
		t.Fatal("an ACK of another sequence was taken as an answer")
	}
}
