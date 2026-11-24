package config

import (
	"net/netip"
	"strings"
	"testing"
)

func loadClientGroups(t *testing.T, servers string) []Group {
	t.Helper()
	app, err := Load(writeFile(t, "client:\n  advertise: 192.0.2.10\n  servers:"+servers+"\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return app.Client.Groups
}

func TestLoadEgressRouteWithBridgeSuffixBecomesABridgePath(t *testing.T) {
	t.Parallel()

	groups := loadClientGroups(t, `
    - port: 51820
      ingress:
        routes: [203.0.113.5:9000/udp]
      egress:
        routes:
          - 203.0.113.5:9000/udp via 194.225.152.10 bridge 46.38.142.66`)
	paths := groups[0].EgressPaths
	if len(paths) != 1 {
		t.Fatalf("egress paths = %#v", paths)
	}
	path := paths[0]
	if path.Server != netip.MustParseAddr("46.38.142.66") || !path.Bridge || path.BridgeVia || path.ProxyBridge.IsValid() {
		t.Fatalf("path = %#v", path)
	}
	if path.NamedServer != netip.MustParseAddr("203.0.113.5") || path.ServerPort != 9000 || path.ReturnIP != netip.MustParseAddr("194.225.152.10") {
		t.Fatalf("path = %#v", path)
	}
	if got, want := path.String(), "203.0.113.5:9000/udp via 194.225.152.10 bridge 46.38.142.66"; got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
}

func TestLoadEgressRouteWithBridgeSuffixAndPool(t *testing.T) {
	t.Parallel()

	groups := loadClientGroups(t, `
    - port: 51820
      ingress:
        routes: [203.0.113.5:9000/udp]
      egress:
        routes:
          - 203.0.113.5:9001/icmp via 194.225.28.192/28 per-packet bridge 94.184.34.237`)
	path := groups[0].EgressPaths[0]
	if path.Server != netip.MustParseAddr("94.184.34.237") || !path.Bridge || path.BridgeVia {
		t.Fatalf("path = %#v", path)
	}
	if !path.IsPool() || path.ReturnPrefix != 28 || path.Balance != BalancePerPacket {
		t.Fatalf("pool = %#v", path)
	}
	if got, want := path.String(), "203.0.113.5:9001/icmp via 194.225.28.192/28 per-packet bridge 94.184.34.237"; got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
}

func TestLoadEgressRouteWithBridgeSuffixNeedsAVia(t *testing.T) {
	t.Parallel()

	_, err := Load(writeFile(t, `
client:
  advertise: 192.0.2.10
  servers:
    - port: 51820
      ingress:
        routes: [203.0.113.5:9000/udp]
      egress:
        routes: [203.0.113.5:9000/udp bridge 46.38.142.66]
`))
	if err == nil || !strings.Contains(err.Error(), "needs a via") || !strings.Contains(err.Error(), "bridges") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadEgressBridgeEntryWithAViaSetsBridgeVia(t *testing.T) {
	t.Parallel()

	groups := loadClientGroups(t, `
    - port: 51820
      ingress:
        routes: [203.0.113.5:9000/udp]
      egress:
        bridges:
          - 91.216.217.188:5000/udp via 178.160.228.1
          - 91.216.217.188:5001/udp via 178.160.228.0/28 per-packet
          - 91.216.217.188:5002/udp`)
	paths := groups[0].EgressPaths
	if len(paths) != 3 {
		t.Fatalf("egress paths = %#v", paths)
	}
	for index, wantVia := range []bool{true, true, false} {
		if !paths[index].Bridge || paths[index].BridgeVia != wantVia || paths[index].NamedServer.IsValid() {
			t.Fatalf("path %d = %#v, want BridgeVia %v", index, paths[index], wantVia)
		}
	}
	if got, want := paths[0].String(), "91.216.217.188:5000/udp via 178.160.228.1"; got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
}

func TestLoadIngressBridgeEntryKeepsNoVia(t *testing.T) {
	t.Parallel()

	groups := loadClientGroups(t, `
    - port: 51820
      ingress:
        bridges: [5.6.7.8:9000/udp]
        routes: [203.0.113.5:9001/udp via 1.1.1.1 bridge 5.6.7.9]
      egress:
        routes: [203.0.113.5:9200/udp]`)
	ingress := groups[0].Paths
	if len(ingress) != 2 || ingress[0].BridgeVia || ingress[1].BridgeVia {
		t.Fatalf("ingress paths = %#v", ingress)
	}
	if reflect := ingress[0]; !reflect.BridgeReflect() || reflect.ProxyBridge != netip.MustParseAddr("5.6.7.9") || reflect.Bridge || reflect.NamedServer.IsValid() {
		t.Fatalf("ingress reflect route = %#v", reflect)
	}
	if got, want := ingress[0].String(), "203.0.113.5:9001/udp via 1.1.1.1 bridge 5.6.7.9"; got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
}

func TestLoadEgressKeepsRoutesBeforeBridgeEntries(t *testing.T) {
	t.Parallel()

	groups := loadClientGroups(t, `
    - port: 51820
      ingress:
        routes: [203.0.113.5:9000/udp]
      egress:
        bridges:
          - 91.216.217.188:5000/udp via 178.160.228.1
        routes:
          - 203.0.113.5:9200/udp
          - 203.0.113.5:9201/udp via 194.225.152.10 bridge 46.38.142.66`)
	paths := groups[0].EgressPaths
	if len(paths) != 3 {
		t.Fatalf("egress paths = %#v", paths)
	}
	if paths[0].Server != netip.MustParseAddr("203.0.113.5") || paths[0].Bridge {
		t.Fatalf("path 0 = %#v, want the plain route", paths[0])
	}
	if paths[1].Server != netip.MustParseAddr("46.38.142.66") || paths[1].NamedServer != netip.MustParseAddr("203.0.113.5") || paths[1].ServerPort != 9201 {
		t.Fatalf("path 1 = %#v, want the suffix route", paths[1])
	}
	if paths[2].Server != netip.MustParseAddr("91.216.217.188") || !paths[2].BridgeVia || paths[2].NamedServer.IsValid() {
		t.Fatalf("path 2 = %#v, want the bridge entry", paths[2])
	}
}

func TestLoadEgressSuffixRouteCollidesWithABridgeEntry(t *testing.T) {
	t.Parallel()

	_, err := Load(writeFile(t, `
client:
  advertise: 192.0.2.10
  servers:
    - port: 51820
      ingress:
        routes: [203.0.113.5:9000/udp]
      egress:
        routes: [203.0.113.5:9200/udp via 194.225.152.10 bridge 46.38.142.66]
        bridges: [46.38.142.66:9200/udp]
`))
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadEgressSuffixRouteStillRefusesARange(t *testing.T) {
	t.Parallel()

	_, err := Load(writeFile(t, `
client:
  advertise: 192.0.2.10
  servers:
    - port: 51820
      ingress:
        routes: [203.0.113.5:9000/udp]
      egress:
        routes: [203.0.113.5:9200-9210/udp via 194.225.152.10 bridge 46.38.142.66]
`))
	if err == nil || !strings.Contains(err.Error(), "one server port") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadClientWithBridgeReflectOnBothDirections(t *testing.T) {
	t.Parallel()

	groups := loadClientGroups(t, `
    - port: 51820
      ingress:
        mode: failover
        routes:
          - 46.102.130.95:9000/icmp via 194.225.28.192/28 per-packet
          - 46.102.130.95:9001/icmp via 87.107.117.192/28 per-packet
      egress:
        mode: failover
        routes:
          - 46.102.130.95:9000/udp via 194.225.152.10 bridge 46.38.142.66
          - 46.102.130.95:9001/udp via 194.225.28.192/28 per-packet bridge 94.184.34.237
    - port: 51825
      ingress:
        mode: failover
        routes:
          - 178.160.229.46:5000/udp via 178.160.228.1
      egress:
        mode: failover
        bridges:
          - 91.216.217.188:5000/udp via 178.160.228.1`)
	if len(groups) != 2 {
		t.Fatalf("groups = %d", len(groups))
	}
	first := groups[0]
	if first.ListenPort != 51820 || len(first.Paths) != 2 || len(first.EgressPaths) != 2 {
		t.Fatalf("first group = %#v", first)
	}
	for _, path := range first.Paths {
		if path.Bridge || path.BridgeVia || path.ProxyBridge.IsValid() || !path.IsPool() {
			t.Fatalf("ingress path = %#v", path)
		}
	}
	wantServers := []string{"46.38.142.66", "94.184.34.237"}
	wantText := []string{
		"46.102.130.95:9000/udp via 194.225.152.10 bridge 46.38.142.66",
		"46.102.130.95:9001/udp via 194.225.28.192/28 per-packet bridge 94.184.34.237",
	}
	for index, path := range first.EgressPaths {
		if path.Server != netip.MustParseAddr(wantServers[index]) || !path.Bridge || path.BridgeVia || path.NamedServer != netip.MustParseAddr("46.102.130.95") {
			t.Fatalf("egress path %d = %#v", index, path)
		}
		if path.String() != wantText[index] {
			t.Fatalf("egress path %d String = %q, want %q", index, path.String(), wantText[index])
		}
	}
	second := groups[1]
	if second.ListenPort != 51825 || len(second.Paths) != 1 || len(second.EgressPaths) != 1 {
		t.Fatalf("second group = %#v", second)
	}
	bridge := second.EgressPaths[0]
	if bridge.Server != netip.MustParseAddr("91.216.217.188") || !bridge.Bridge || !bridge.BridgeVia || bridge.ReturnIP != netip.MustParseAddr("178.160.228.1") || bridge.NamedServer.IsValid() {
		t.Fatalf("egress bridge = %#v", bridge)
	}
}
