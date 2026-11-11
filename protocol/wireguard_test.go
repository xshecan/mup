package protocol

import (
	"errors"
	"testing"
)

func TestValidateWireGuardLengths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		typeID  byte
		length  int
		wantErr error
	}{
		{name: "initiation", typeID: MessageHandshakeInitiation, length: HandshakeInitiationLength},
		{name: "response", typeID: MessageHandshakeResponse, length: HandshakeResponseLength},
		{name: "cookie", typeID: MessageCookieReply, length: CookieReplyLength},
		{name: "keepalive", typeID: MessageTransportData, length: TransportDataMinLength},
		{name: "transport payload", typeID: MessageTransportData, length: TransportDataMinLength + 32},
		{name: "short initiation", typeID: MessageHandshakeInitiation, length: HandshakeInitiationLength - 1, wantErr: ErrWireGuardLength},
		{name: "unpadded transport", typeID: MessageTransportData, length: 95},
		{name: "short transport", typeID: MessageTransportData, length: TransportDataMinLength - 1, wantErr: ErrWireGuardLength},
		{name: "unknown type", typeID: 9, length: HandshakeInitiationLength, wantErr: ErrWireGuardType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := makeWireGuardPacket(tt.typeID, tt.length)
			err := ValidateWireGuard(packet, false)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ValidateWireGuard() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateWireGuardReservedBoundary(t *testing.T) {
	t.Parallel()

	packet := makeWireGuardPacket(MessageHandshakeResponse, HandshakeResponseLength)
	packet[3] = 1
	if err := ValidateWireGuard(packet, false); !errors.Is(err, ErrWireGuardReserved) {
		t.Fatalf("local validation error = %v, want %v", err, ErrWireGuardReserved)
	}
	if err := ValidateWireGuard(packet, true); err != nil {
		t.Fatalf("MUP validation rejected valid peer token: %v", err)
	}
	packet[2] = 0x10
	if err := ValidateWireGuard(packet, true); !errors.Is(err, ErrPeerTokenRange) {
		t.Fatalf("MUP validation error = %v, want %v", err, ErrPeerTokenRange)
	}
}

func makeWireGuardPacket(typeID byte, length int) []byte {
	packet := make([]byte, length)
	if len(packet) > 0 {
		packet[0] = typeID
	}
	return packet
}
