package config

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/xshecan/mup/protocol"
)

func TestLoadClientWithSeparateDirections(t *testing.T) {
	t.Parallel()

	app, err := Load(writeFile(t, `
client:
  advertise: 192.0.2.10
  servers:
    - port: 51820
      upstream:
        mode: balancer
        routes:
          - 203.0.113.5:9000-9099/udp
          - 203.0.113.5%eth1:9100/icmp
      downstream:
        mode: burst
        routes:
          - 203.0.113.5:9200/icmp via 198.51.100.0/28 balance per-packet
          - 203.0.113.6:9300/udp
    - port: 51821
      routes:
        - 198.51.100.20:6000/udp via 1.1.1.1
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	split := app.Client.Groups[0]
	if !split.Split() || split.Mode != ModeBalancer || split.DownMode != ModeBurst {
		t.Fatalf("split group = %#v", split)
	}
	if len(split.Paths) != 2 || split.Paths[0].LastPort != 9099 || split.Paths[1].Interface != "eth1" {
		t.Fatalf("up paths = %#v", split.Paths)
	}
	if len(split.DownPaths) != 2 {
		t.Fatalf("down paths = %#v", split.DownPaths)
	}
	pool := split.DownPaths[0]
	if pool.Transport != protocol.TransportICMP || pool.ServerPort != 9200 ||
		pool.ReturnIP != netip.MustParseAddr("198.51.100.0") || pool.ReturnPrefix != 28 || pool.Balance != BalancePerPacket {
		t.Fatalf("pool down path = %#v", pool)
	}
	if direct := split.DownPaths[1]; direct.Transport != protocol.TransportUDP || direct.ReturnIP.IsValid() {
		t.Fatalf("direct down path = %#v", direct)
	}
	if paired := app.Client.Groups[1]; paired.Split() || len(paired.Paths) != 1 {
		t.Fatalf("paired group = %#v", paired)
	}
}

func TestLoadClientRejectsBadDirections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		group string
		want  string
	}{
		{
			name: "both forms",
			group: `
      routes:
        - 203.0.113.5:9000/udp
      upstream:
        routes:
          - 203.0.113.5:9000/udp
      downstream:
        routes:
          - 203.0.113.5:9200/udp`,
			want: "not both",
		},
		{
			name: "upstream alone",
			group: `
      upstream:
        routes:
          - 203.0.113.5:9000/udp`,
			want: "go together",
		},
		{
			name: "empty downstream",
			group: `
      upstream:
        routes:
          - 203.0.113.5:9000/udp
      downstream:
        mode: burst`,
			want: "at least one route",
		},
		{
			name: "via on an up bridge",
			group: `
      upstream:
        bridges:
          - 203.0.113.5:9000/udp via 198.51.100.1
      downstream:
        routes:
          - 203.0.113.5:9200/udp`,
			want: "has no via",
		},
		{
			name: "interface on a down route",
			group: `
      upstream:
        routes:
          - 203.0.113.5:9000/udp
      downstream:
        routes:
          - 203.0.113.5%eth0:9200/udp`,
			want: "no interface",
		},
		{
			name: "port range on a down route",
			group: `
      upstream:
        routes:
          - 203.0.113.5:9000/udp
      downstream:
        routes:
          - 203.0.113.5:9200-9210/udp`,
			want: "one server port",
		},
		{
			name: "same down route twice",
			group: `
      upstream:
        routes:
          - 203.0.113.5:9000/udp
      downstream:
        routes:
          - 203.0.113.5:9200/udp
          - 203.0.113.5:9200/udp via 198.51.100.1`,
			want: "twice",
		},
		{
			name: "unknown key in a block",
			group: `
      upstream:
        routes:
          - 203.0.113.5:9000/udp
      downstream:
        paths:
          - 203.0.113.5:9200/udp`,
			want: "paths",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeFile(t, `
client:
  advertise: 192.0.2.10
  servers:
    - port: 51820`+tt.group+"\n"))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load error = %v, want one with %q", err, tt.want)
			}
		})
	}
}

func TestUpRouteReflectParses(t *testing.T) {
	t.Parallel()

	cfg, err := Load(writeFile(t, `
client:
  advertise: 192.0.2.10
  servers:
    - port: 51820
      upstream:
        routes:
          - 203.0.113.5:9000/icmp via 198.51.100.1
          - 203.0.113.5:9100/icmp via 87.107.117.192/28 balance per-packet
          - 203.0.113.5:9200/udp via 194.225.72.10
      downstream:
        routes:
          - 203.0.113.5:9300/udp
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	group := cfg.Client.Groups[0]
	if len(group.Paths) != 3 {
		t.Fatalf("up paths = %d, want 3", len(group.Paths))
	}
	for index, path := range group.Paths {
		if !path.UpReflect(group.Split()) {
			t.Fatalf("up path %d UpReflect = false, want true (%s)", index, path)
		}
	}
	if path := group.Paths[1]; !path.IsPool() || path.Balance != BalancePerPacket {
		t.Fatalf("pool up path = %#v, want a per-packet pool", path)
	}
}

func TestSymmetricRouteIsNotUpReflect(t *testing.T) {
	t.Parallel()

	path := mustPath(t, "203.0.113.5:9000/icmp via 198.51.100.1")
	if path.UpReflect(false) {
		t.Fatalf("a symmetric route must not be an up reflect path: %s", path)
	}
}

func TestClientAcceptsEightDownPaths(t *testing.T) {
	t.Parallel()

	group := Group{ListenPort: 51820, Paths: []Path{mustPath(t, "203.0.113.5:9000/udp")}}
	for port := 9200; port < 9209; port++ {
		group.DownPaths = append(group.DownPaths, Path{
			Server: netip.MustParseAddr("203.0.113.5"), ServerPort: uint16(port), Transport: protocol.TransportUDP,
		})
	}
	client := Client{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), Groups: []Group{group}}
	if err := client.Validate(); err == nil || !strings.Contains(err.Error(), "at most 8 down routes") {
		t.Fatalf("Validate error = %v, want the down route limit", err)
	}
	client.Groups[0].DownPaths = client.Groups[0].DownPaths[:8]
	if err := client.Validate(); err != nil {
		t.Fatalf("Validate with 8 down routes: %v", err)
	}
}

func mustPath(t *testing.T, raw string) Path {
	t.Helper()
	path, err := ParsePath(raw)
	if err != nil {
		t.Fatalf("ParsePath(%q): %v", raw, err)
	}
	return path
}
