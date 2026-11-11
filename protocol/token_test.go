package protocol

import (
	"bytes"
	"testing"
)

func TestEncodeDecodePeerToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		token   uint32
		want    [3]byte
		wantErr bool
	}{
		{name: "zero", token: 0, wantErr: true},
		{name: "first", token: 1, want: [3]byte{0, 0, 1}},
		{name: "last", token: MaxPeerToken, want: [3]byte{0, 0x0f, 0xff}},
		{name: "above v1 range", token: MaxPeerToken + 1, wantErr: true},
		{name: "wire maximum is reserved", token: 0x00ffffff, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := EncodePeerToken(tt.token)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("EncodePeerToken(%d) unexpectedly succeeded", tt.token)
				}
				return
			}
			if err != nil {
				t.Fatalf("EncodePeerToken(%d): %v", tt.token, err)
			}
			if encoded != tt.want {
				t.Fatalf("EncodePeerToken(%d) = %v, want %v", tt.token, encoded, tt.want)
			}
			decoded, err := DecodePeerToken(encoded)
			if err != nil {
				t.Fatalf("DecodePeerToken(%v): %v", encoded, err)
			}
			if decoded != tt.token {
				t.Fatalf("DecodePeerToken(%v) = %d, want %d", encoded, decoded, tt.token)
			}
		})
	}
}

func TestInsertAndClearPeerToken(t *testing.T) {
	t.Parallel()

	packet := makeWireGuardPacket(MessageHandshakeInitiation, HandshakeInitiationLength)
	original := append([]byte(nil), packet...)
	if err := InsertPeerToken(packet, 17); err != nil {
		t.Fatalf("InsertPeerToken: %v", err)
	}
	if !bytes.Equal(packet[4:], original[4:]) {
		t.Fatal("InsertPeerToken modified authenticated WireGuard bytes")
	}
	if got, err := PeerToken(packet); err != nil || got != 17 {
		t.Fatalf("PeerToken = %d, %v; want 17, nil", got, err)
	}
	if err := ClearPeerToken(packet); err != nil {
		t.Fatalf("ClearPeerToken: %v", err)
	}
	if !bytes.Equal(packet, original) {
		t.Fatal("clear did not restore original WireGuard packet")
	}
}
