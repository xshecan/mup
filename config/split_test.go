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
      ingress:
        mode: balancer
        routes:
          - 203.0.113.5:9000-9099/udp
          - 203.0.113.5%eth1:9100/icmp
      egress:
        mode: repeater
        routes:
          - 203.0.113.5:9200/icmp via 198.51.100.0/28 per-packet
          - 203.0.113.6:9300/udp
    - port: 51821
      routes:
        - 198.51.100.20:6000/udp via 1.1.1.1
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	split := app.Client.Groups[0]
	if !split.Split() || split.Mode != ModeBalancer || split.EgressMode != ModeRepeater {
		t.Fatalf("split group = %#v", split)
	}
	if len(split.Paths) != 2 || split.Paths[0].LastPort != 9099 || split.Paths[1].Interface != "eth1" {
		t.Fatalf("ingress paths = %#v", split.Paths)
	}
	if len(split.EgressPaths) != 2 {
		t.Fatalf("egress paths = %#v", split.EgressPaths)
	}
	pool := split.EgressPaths[0]
	if pool.Transport != protocol.TransportICMP || pool.ServerPort != 9200 ||
		pool.ReturnIP != netip.MustParseAddr("198.51.100.0") || pool.ReturnPrefix != 28 || pool.Balance != BalancePerPacket {
		t.Fatalf("pool egress path = %#v", pool)
	}
	if direct := split.EgressPaths[1]; direct.Transport != protocol.TransportUDP || direct.ReturnIP.IsValid() {
		t.Fatalf("direct egress path = %#v", direct)
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
      ingress:
        routes:
          - 203.0.113.5:9000/udp
      egress:
        routes:
          - 203.0.113.5:9200/udp`,
			want: "not both",
		},
		{
			name: "ingress alone",
			group: `
      ingress:
        routes:
          - 203.0.113.5:9000/udp`,
			want: "go together",
		},
		{
			name: "empty egress",
			group: `
      ingress:
        routes:
          - 203.0.113.5:9000/udp
      egress:
        mode: repeater`,
			want: "at least one route",
		},
		{
			name: "via on an ingress bridge",
			group: `
      ingress:
        bridges:
          - 203.0.113.5:9000/udp via 198.51.100.1
      egress:
        routes:
          - 203.0.113.5:9200/udp`,
			want: "has no via",
		},
		{
			name: "interface on an egress route",
			group: `
      ingress:
        routes:
          - 203.0.113.5:9000/udp
      egress:
        routes:
          - 203.0.113.5%eth0:9200/udp`,
			want: "no interface",
		},
		{
			name: "port range on an egress route",
			group: `
      ingress:
        routes:
          - 203.0.113.5:9000/udp
      egress:
        routes:
          - 203.0.113.5:9200-9210/udp`,
			want: "one server port",
		},
		{
			name: "same egress route twice",
			group: `
      ingress:
        routes:
          - 203.0.113.5:9000/udp
      egress:
        routes:
          - 203.0.113.5:9200/udp
          - 203.0.113.5:9200/udp via 198.51.100.1`,
			want: "twice",
		},
		{
			name: "unknown key in a block",
			group: `
      ingress:
        routes:
          - 203.0.113.5:9000/udp
      egress:
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

func TestIngressRouteReflectParses(t *testing.T) {
	t.Parallel()

	cfg, err := Load(writeFile(t, `
client:
  advertise: 192.0.2.10
  servers:
    - port: 51820
      ingress:
        routes:
          - 203.0.113.5:9000/icmp via 198.51.100.1
          - 203.0.113.5:9100/icmp via 87.107.117.192/28 per-packet
          - 203.0.113.5:9200/udp via 194.225.72.10
      egress:
        routes:
          - 203.0.113.5:9300/udp
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	group := cfg.Client.Groups[0]
	if len(group.Paths) != 3 {
		t.Fatalf("ingress paths = %d, want 3", len(group.Paths))
	}
	for index, path := range group.Paths {
		if !path.IngressReflect(group.Split()) {
			t.Fatalf("ingress path %d IngressReflect = false, want true (%s)", index, path)
		}
	}
	if path := group.Paths[1]; !path.IsPool() || path.Balance != BalancePerPacket {
		t.Fatalf("pool ingress path = %#v, want a per-packet pool", path)
	}
}

func TestSymmetricRouteIsNotIngressReflect(t *testing.T) {
	t.Parallel()

	path := mustPath(t, "203.0.113.5:9000/icmp via 198.51.100.1")
	if path.IngressReflect(false) {
		t.Fatalf("a symmetric route must not be an ingress reflect path: %s", path)
	}
}

func TestClientAcceptsEightEgressPaths(t *testing.T) {
	t.Parallel()

	group := Group{ListenPort: 51820, Paths: []Path{mustPath(t, "203.0.113.5:9000/udp")}}
	for port := 9200; port < 9209; port++ {
		group.EgressPaths = append(group.EgressPaths, Path{
			Server: netip.MustParseAddr("203.0.113.5"), ServerPort: uint16(port), Transport: protocol.TransportUDP,
		})
	}
	client := Client{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), Groups: []Group{group}}
	if err := client.Validate(); err == nil || !strings.Contains(err.Error(), "at most 8 egress routes") {
		t.Fatalf("Validate error = %v, want the egress route limit", err)
	}
	client.Groups[0].EgressPaths = client.Groups[0].EgressPaths[:8]
	if err := client.Validate(); err != nil {
		t.Fatalf("Validate with 8 egress routes: %v", err)
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

// TestLoadClientRejectsRemovedNames checks that the names from before the
// ingress and egress rename, and the old mode names, do not load.
func TestLoadClientRejectsRemovedNames(t *testing.T) {
	t.Parallel()

	const head = `
client:
  advertise: 192.0.2.10
  servers:
    - port: 51820
`
	const routes = `
        routes:
          - 203.0.113.5:9000/udp
`
	for name, body := range map[string]string{
		"upstream":   "      upstream:" + routes + "      egress:" + routes,
		"downstream": "      ingress:" + routes + "      downstream:" + routes,
		"fallback":   "      mode: fallback\n      routes:\n        - 203.0.113.5:9000/udp\n",
		"burst":      "      mode: burst\n      routes:\n        - 203.0.113.5:9000/udp\n",
		"balance":    "      mode: balance\n      routes:\n        - 203.0.113.5:9000/udp\n",
	} {
		if _, err := Load(writeFile(t, head+body)); err == nil || !strings.Contains(err.Error(), name) {
			t.Fatalf("%s: err = %v, want an error that names it", name, err)
		}
	}
}
