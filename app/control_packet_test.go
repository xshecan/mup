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
