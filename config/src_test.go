package config

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/xshecan/mup/protocol"
)

func TestParsePathReadsASourceRangeInEveryForm(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		raw          string
		first, last  uint16
		print        string
		pool, bridge bool
	}{
		{raw: "203.0.113.5:9000/udp src 20000-29999", first: 20000, last: 29999, print: "203.0.113.5:9000/udp src 20000-29999"},
		{raw: "203.0.113.5:9000/icmp src 6000", first: 6000, last: 6000, print: "203.0.113.5:9000/icmp src 6000"},
		{raw: "203.0.113.5:9000/udp src 7-7", first: 7, last: 7, print: "203.0.113.5:9000/udp src 7"},
		{raw: "203.0.113.5%eth1:9000/udp src 1-65535", first: 1, last: 65535, print: "203.0.113.5%eth1:9000/udp src 1-65535"},
		{raw: "203.0.113.5:9000-9099/udp src 5000-6000", first: 5000, last: 6000, print: "203.0.113.5:9000-9099/udp src 5000-6000"},
		{raw: "203.0.113.5:9000/udp via 198.51.100.1 src 5000-50000", first: 5000, last: 50000, print: "203.0.113.5:9000/udp via 198.51.100.1 src 5000-50000"},
		{raw: "203.0.113.5:9000/icmp via 87.107.117.192/28 src 20000-29999", first: 20000, last: 29999, pool: true, print: "203.0.113.5:9000/icmp via 87.107.117.192/28 per-peer src 20000-29999"},
		{raw: "203.0.113.5:9000/icmp via 87.107.117.192/28 per-packet src 20000-29999", first: 20000, last: 29999, pool: true, print: "203.0.113.5:9000/icmp via 87.107.117.192/28 per-packet src 20000-29999"},
		{raw: "203.0.113.5:9000/udp via 198.51.100.1 src 5000-6000 bridge 46.38.142.66", first: 5000, last: 6000, bridge: true, print: "203.0.113.5:9000/udp via 198.51.100.1 src 5000-6000 bridge 46.38.142.66"},
		{raw: "203.0.113.5:9000/udp via 87.107.117.192/28 per-packet src 5000 bridge 46.38.142.66", first: 5000, last: 5000, pool: true, bridge: true, print: "203.0.113.5:9000/udp via 87.107.117.192/28 per-packet src 5000 bridge 46.38.142.66"},
	} {
		path := mustParsePath(t, test.raw)
		if !path.HasSrc() || path.SrcFirst != test.first || path.SrcLast != test.last {
			t.Fatalf("%q: source range = %d-%d", test.raw, path.SrcFirst, path.SrcLast)
		}
		if path.IsPool() != test.pool || path.ProxyBridge.IsValid() != test.bridge {
			t.Fatalf("%q: path = %#v", test.raw, path)
		}
		if got := path.String(); got != test.print {
			t.Fatalf("%q: String = %q, want %q", test.raw, got, test.print)
		}
		if again := mustParsePath(t, path.String()); again != path {
			t.Fatalf("%q: reparsed path = %#v, want %#v", test.raw, again, path)
		}
	}
}

func TestParsePathWithoutASourceRangeHasNone(t *testing.T) {
	t.Parallel()

	path := mustParsePath(t, "203.0.113.5:9000/udp via 198.51.100.1")
	if path.HasSrc() || path.SrcFirst != 0 || path.SrcLast != 0 {
		t.Fatalf("path = %#v", path)
	}
	if strings.Contains(path.String(), "src") {
		t.Fatalf("String = %q", path.String())
	}
}

func TestParsePathRejectsABadSourceRange(t *testing.T) {
	t.Parallel()

	for raw, want := range map[string]string{
		"203.0.113.5:9000/udp src":                                          "src needs a value",
		"203.0.113.5:9000/udp via 198.51.100.1 src":                         "src needs a value",
		"203.0.113.5:9000/udp src 0":                                        "invalid source range",
		"203.0.113.5:9000/udp src 0-5":                                      "invalid source range",
		"203.0.113.5:9000/udp src 65536":                                    "invalid source range",
		"203.0.113.5:9000/udp src 5-65536":                                  "invalid source range",
		"203.0.113.5:9000/udp src 9-8":                                      "invalid source range",
		"203.0.113.5:9000/udp src 5-0":                                      "invalid source range",
		"203.0.113.5:9000/udp src abc":                                      "invalid source range",
		"203.0.113.5:9000/udp src 5-":                                       "invalid source range",
		"203.0.113.5:9000/udp src -5":                                       "invalid source range",
		"203.0.113.5:9000/udp src 1-2-3":                                    "invalid source range",
		"203.0.113.5:9000/udp src 1-2 src 3-4":                              "src once",
		"203.0.113.5:9000/udp src 1-2 via 198.51.100.1":                     "path must use",
		"203.0.113.5:9000/udp src 1-2 per-packet":                           "path must use",
		"203.0.113.5:9000/udp via 198.51.100.1 bridge 46.38.142.66 src 1-2": "path must use",
		"203.0.113.5:9000/udp src 1-2 3-4":                                  "path must use",
		"203.0.113.5:9000/udp via 198.51.100.1 per-packet src 1-2":          "per-peer and per-packet apply only to a return pool",
	} {
		_, err := ParsePath(raw)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("ParsePath(%q) error = %v, want %q", raw, err, want)
		}
	}
}

func TestNormalizeEgressPathKeepsTheSourceRange(t *testing.T) {
	t.Parallel()

	route, err := NormalizeEgressPath(mustParsePath(t, "203.0.113.5:9000/udp via 194.225.152.10 src 5000-6000 bridge 46.38.142.66"), false)
	if err != nil {
		t.Fatalf("NormalizeEgressPath: %v", err)
	}
	if route.SrcFirst != 5000 || route.SrcLast != 6000 || !route.Bridge || route.Server != netip.MustParseAddr("46.38.142.66") {
		t.Fatalf("route = %#v", route)
	}
	if got, want := route.String(), "203.0.113.5:9000/udp via 194.225.152.10 src 5000-6000 bridge 46.38.142.66"; got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
	entry, err := NormalizeEgressPath(mustParsePath(t, "46.38.142.66:9000/udp via 194.225.152.10 src 7"), true)
	if err != nil {
		t.Fatalf("NormalizeEgressPath: %v", err)
	}
	if !entry.BridgeVia || entry.SrcFirst != 7 || entry.SrcLast != 7 {
		t.Fatalf("entry = %#v", entry)
	}
	if got, want := entry.String(), "46.38.142.66:9000/udp via 194.225.152.10 src 7"; got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
	plain, err := NormalizeEgressPath(mustParsePath(t, "203.0.113.5:9000/icmp src 7-8"), false)
	if err != nil || plain.SrcFirst != 7 || plain.SrcLast != 8 {
		t.Fatalf("plain = %#v, err = %v", plain, err)
	}
}

func TestLoadClientWithSourceRanges(t *testing.T) {
	t.Parallel()

	app, err := Load(writeFile(t, `
client:
  advertise: 79.175.167.5
  servers:
    - port: 51820
      mode: failover
      routes:
        - 160.119.74.99:9000/icmp via 87.107.117.192/28 per-packet src 20000-29999
    - port: 51825
      ingress:
        mode: failover
        routes:
          - 178.160.229.46:5000/udp via 178.160.228.1 src 5000-50000
      egress:
        mode: failover
        bridges:
          - 91.216.217.188:5000/udp via 178.160.228.1 src 5000-50000
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	groups := app.Client.Groups
	if len(groups) != 2 {
		t.Fatalf("groups = %#v", groups)
	}
	paired := groups[0]
	if paired.Split() || paired.ListenPort != 51820 || paired.Mode != ModeFailover || len(paired.Paths) != 1 {
		t.Fatalf("paired group = %#v", paired)
	}
	pool := paired.Paths[0]
	if pool.Server != netip.MustParseAddr("160.119.74.99") || pool.ServerPort != 9000 || pool.Transport != protocol.TransportICMP ||
		pool.ReturnIP != netip.MustParseAddr("87.107.117.192") || pool.ReturnPrefix != 28 || pool.Balance != BalancePerPacket ||
		pool.SrcFirst != 20000 || pool.SrcLast != 29999 || !pool.HasSrc() {
		t.Fatalf("pool path = %#v", pool)
	}
	split := groups[1]
	if !split.Split() || split.ListenPort != 51825 || split.Mode != ModeFailover || split.EgressMode != ModeFailover {
		t.Fatalf("split group = %#v", split)
	}
	if len(split.Paths) != 1 {
		t.Fatalf("ingress paths = %#v", split.Paths)
	}
	ingress := split.Paths[0]
	if ingress.Server != netip.MustParseAddr("178.160.229.46") || ingress.ServerPort != 5000 || ingress.Transport != protocol.TransportUDP ||
		ingress.ReturnIP != netip.MustParseAddr("178.160.228.1") || ingress.IsPool() || ingress.Bridge ||
		ingress.SrcFirst != 5000 || ingress.SrcLast != 50000 || !ingress.IngressReflect(true) {
		t.Fatalf("ingress path = %#v", ingress)
	}
	if len(split.EgressPaths) != 1 {
		t.Fatalf("egress paths = %#v", split.EgressPaths)
	}
	egress := split.EgressPaths[0]
	if egress.Server != netip.MustParseAddr("91.216.217.188") || egress.ServerPort != 5000 || egress.Transport != protocol.TransportUDP ||
		egress.ReturnIP != netip.MustParseAddr("178.160.228.1") || !egress.Bridge || !egress.BridgeVia ||
		egress.SrcFirst != 5000 || egress.SrcLast != 50000 {
		t.Fatalf("egress path = %#v", egress)
	}
}

func TestLoadClientAcceptsASourceRangeOnEveryKindOfRoute(t *testing.T) {
	t.Parallel()

	groups := loadClientGroups(t, `
    - port: 51820
      ingress:
        routes:
          - 203.0.113.5:9000-9099/udp src 5000-6000
          - 203.0.113.6:9000/icmp via 198.51.100.1 src 7000-8000 bridge 46.38.142.66
        bridges:
          - 5.6.7.8:9300/udp src 9000-9100
      egress:
        routes:
          - 203.0.113.5:9200/icmp src 10-20
          - 203.0.113.7:9300/udp via 198.51.100.0/28 per-packet src 100-200
          - 203.0.113.8:9400/udp via 194.225.152.10 src 300-400 bridge 46.38.142.67
        bridges:
          - 5.6.7.9:9500/udp src 500-600
          - 5.6.7.10:9600/icmp via 198.51.100.1 src 700-800`)
	group := groups[0]
	for index, path := range append(append([]Path{}, group.Paths...), group.EgressPaths...) {
		if !path.HasSrc() {
			t.Fatalf("path %d has no source range: %#v", index, path)
		}
	}
	if len(group.Paths) != 3 || len(group.EgressPaths) != 5 {
		t.Fatalf("paths = %d ingress, %d egress", len(group.Paths), len(group.EgressPaths))
	}
	if !group.Paths[0].HasPortRange() || group.Paths[0].LastPort != 9099 {
		t.Fatalf("port range was lost: %#v", group.Paths[0])
	}
	if group.EgressPaths[2].NamedServer != netip.MustParseAddr("203.0.113.8") || group.EgressPaths[2].SrcFirst != 300 {
		t.Fatalf("suffix egress path = %#v", group.EgressPaths[2])
	}
}

func TestLoadClientRejectsABadSourceRange(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct {
		servers string
		want    string
	}{
		"icmp ingress bridge": {`
    - port: 51820
      ingress:
        bridges: [5.6.7.8:9000/icmp src 100-200]
      egress:
        routes: [203.0.113.5:9200/udp]`, "ICMP ingress bridge has no source range"},
		"reversed": {`
    - port: 51820
      routes: [203.0.113.5:9000/udp src 9-8]`, "invalid source range"},
		"missing value": {`
    - port: 51820
      routes: [203.0.113.5:9000/udp src]`, "src needs a value"},
		"twice": {`
    - port: 51820
      routes: [203.0.113.5:9000/udp src 1-2 src 3-4]`, "src once"},
		"overlapping ranges": {`
    - port: 51820
      ingress:
        routes: [203.0.113.5:9000/udp]
      egress:
        routes:
          - 203.0.113.5:9200/udp src 5000-6000
          - 203.0.113.5:9300/udp src 6000-7000`, "overlapping source ranges"},
		"range over a fixed port": {`
    - port: 51820
      ingress:
        routes: [203.0.113.5:9000/udp]
      egress:
        routes:
          - 203.0.113.5:9300/udp
          - 203.0.113.5:9200/udp src 9250-9400`, "contains the fixed port"},
		"fixed port under a range, in another group": {`
    - port: 51820
      ingress:
        routes: [203.0.113.5:9000/udp]
      egress:
        routes: [203.0.113.5:9200/udp src 9100-9300]
    - port: 51821
      ingress:
        routes: [203.0.113.5:9001/udp]
      egress:
        bridges: [203.0.113.5:9250/udp]`, "contains the fixed port"},
	} {
		_, err := Load(writeFile(t, "client:\n  advertise: 192.0.2.10\n  servers:"+test.servers+"\n"))
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("%s: error = %v, want %q", name, err, test.want)
		}
	}
}

func TestEgressSourceRangesOfDifferentSendersOrIcmpDoNotCollide(t *testing.T) {
	t.Parallel()

	loadClientGroups(t, `
    - port: 51820
      ingress:
        routes: [203.0.113.5:9000/udp]
      egress:
        routes:
          - 203.0.113.5:9200/udp src 5000-6000
          - 203.0.113.6:9200/udp src 5000-6000
          - 203.0.113.5:9300/udp src 7000-8000
          - 203.0.113.5:6500/icmp src 5000-6000
          - 203.0.113.5:6600/icmp src 5500-6500
          - 203.0.113.5:7500/icmp
          - 203.0.113.7:6500/udp`)
}

func TestSourceRangeKeepsThePortRangeOfARoute(t *testing.T) {
	t.Parallel()

	path := mustParsePath(t, "203.0.113.5:9000-9009/udp src 5000-6000")
	if !path.HasPortRange() || path.Ports() != (PortRange{First: 9000, Last: 9009}) || path.SrcFirst != 5000 || path.SrcLast != 6000 {
		t.Fatalf("path = %#v", path)
	}
	if moved := path.AtPort(9004); moved.SrcFirst != 5000 || moved.SrcLast != 6000 || moved.HasPortRange() {
		t.Fatalf("moved path = %#v", moved)
	}
}
