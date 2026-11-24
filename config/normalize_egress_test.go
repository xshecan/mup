package config

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/xshecan/mup/protocol"
)

func TestNormalizeEgressPathAppliesTheRulesOfTheFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		raw         string
		bridgeEntry bool
		want        Path
	}{
		{
			name: "route with a bridge suffix",
			raw:  "203.0.113.5:9000/udp via 194.225.152.10 bridge 46.38.142.66",
			want: Path{
				Server: netip.MustParseAddr("46.38.142.66"), ServerPort: 9000, Transport: protocol.TransportUDP,
				ReturnIP: netip.MustParseAddr("194.225.152.10"), Bridge: true,
				NamedServer: netip.MustParseAddr("203.0.113.5"),
			},
		},
		{
			name:        "bridge entry with a via",
			raw:         "46.38.142.66:9001/icmp via 194.225.28.192/28 per-packet",
			bridgeEntry: true,
			want: Path{
				Server: netip.MustParseAddr("46.38.142.66"), ServerPort: 9001, Transport: protocol.TransportICMP,
				ReturnIP: netip.MustParseAddr("194.225.28.192"), ReturnPrefix: 28, Balance: BalancePerPacket,
				Bridge: true, BridgeVia: true,
			},
		},
		{
			name:        "bridge entry without a via",
			raw:         "46.38.142.66:9002/udp",
			bridgeEntry: true,
			want:        Path{Server: netip.MustParseAddr("46.38.142.66"), ServerPort: 9002, Bridge: true},
		},
		{
			name: "plain route",
			raw:  "203.0.113.5:9003/udp via 194.225.152.10",
			want: Path{Server: netip.MustParseAddr("203.0.113.5"), ServerPort: 9003, ReturnIP: netip.MustParseAddr("194.225.152.10")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			parsed, err := ParsePath(tt.raw)
			if err != nil {
				t.Fatalf("ParsePath: %v", err)
			}
			got, err := NormalizeEgressPath(parsed, tt.bridgeEntry)
			if err != nil {
				t.Fatalf("NormalizeEgressPath: %v", err)
			}
			if got != tt.want {
				t.Fatalf("path = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestNormalizeEgressPathRefusesABridgeSuffixWithoutAVia(t *testing.T) {
	t.Parallel()

	parsed, err := ParsePath("203.0.113.5:9000/udp bridge 46.38.142.66")
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	_, err = NormalizeEgressPath(parsed, false)
	if err == nil || !strings.Contains(err.Error(), "needs a via") || !strings.Contains(err.Error(), "bridges") {
		t.Fatalf("error = %v", err)
	}
}

func TestNormalizeEgressPathGivesTheSamePathsAsTheFile(t *testing.T) {
	t.Parallel()

	groups := loadClientGroups(t, `
    - port: 51820
      ingress:
        routes: [203.0.113.5:9000/udp]
      egress:
        routes:
          - 203.0.113.5:9000/udp via 194.225.152.10 bridge 46.38.142.66
        bridges:
          - 46.38.142.66:9001/icmp via 194.225.28.192/28
          - 46.38.142.67:9002/udp`)
	inputs := []struct {
		raw         string
		bridgeEntry bool
	}{
		{"203.0.113.5:9000/udp via 194.225.152.10 bridge 46.38.142.66", false},
		{"46.38.142.66:9001/icmp via 194.225.28.192/28", true},
		{"46.38.142.67:9002/udp", true},
	}
	paths := groups[0].EgressPaths
	if len(paths) != len(inputs) {
		t.Fatalf("egress paths = %#v", paths)
	}
	for index, input := range inputs {
		parsed, err := ParsePath(input.raw)
		if err != nil {
			t.Fatalf("ParsePath(%q): %v", input.raw, err)
		}
		got, err := NormalizeEgressPath(parsed, input.bridgeEntry)
		if err != nil {
			t.Fatalf("NormalizeEgressPath(%q): %v", input.raw, err)
		}
		if got != paths[index] {
			t.Fatalf("path %d = %#v, the file gives %#v", index, got, paths[index])
		}
	}
}
