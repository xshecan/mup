package transport

import (
	"testing"

	"github.com/xshecan/mup/protocol"
)

func TestParsePortSpec(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input      string
		serverPort uint16
		transport  protocol.TransportID
		wantErr    bool
	}{
		{input: "5000/udp", serverPort: 5000, transport: protocol.TransportUDP},
		{input: "5000/icmp", serverPort: 5000, transport: protocol.TransportICMP},
		{input: "0/udp", wantErr: true},
		{input: "65536/udp", wantErr: true},
		{input: "5000/tcp", wantErr: true},
		{input: "5000", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			serverPort, transport, err := ParsePortSpec(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParsePortSpec(%q) unexpectedly succeeded", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePortSpec(%q): %v", tt.input, err)
			}
			if serverPort != tt.serverPort || transport != tt.transport {
				t.Fatalf("ParsePortSpec(%q) = (%d, %d), want (%d, %d)", tt.input, serverPort, transport, tt.serverPort, tt.transport)
			}
		})
	}
}
