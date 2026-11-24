package config

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/xshecan/mup/api"
)

func TestLoadClientWithBridges(t *testing.T) {
	t.Parallel()

	app, err := Load(writeFile(t, `
client:
  advertise: 160.119.74.74
  servers:
    - port: 51820
      ingress:
        routes:
          - 46.102.130.95:9000/icmp
        bridges:
          - 5.6.7.8%eth1:9100-9199/udp
      egress:
        bridges:
          - 5.6.7.8:9200/icmp via 87.107.117.192/28
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	group := app.Client.Groups[0]
	if len(group.Paths) != 2 || group.Paths[0].Bridge || !group.Paths[1].Bridge {
		t.Fatalf("ingress paths = %#v, want the route and then the bridge", group.Paths)
	}
	if ingress := group.Paths[1]; ingress.Server != netip.MustParseAddr("5.6.7.8") || ingress.Interface != "eth1" || ingress.LastPort != 9199 {
		t.Fatalf("ingress bridge = %#v", ingress)
	}
	if len(group.EgressPaths) != 1 || !group.EgressPaths[0].Bridge || group.EgressPaths[0].ReturnPrefix != 28 {
		t.Fatalf("egress paths = %#v", group.EgressPaths)
	}
	if kind := group.EgressPaths[0].Kind(); kind != "bridge" {
		t.Fatalf("Kind = %q, want bridge", kind)
	}
}

func TestLoadClientRejectsBadBridges(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct {
		servers string
		want    string
	}{
		"ingress bridge with via": {`
    - port: 51820
      ingress:
        bridges: [5.6.7.8:9000/udp via 1.1.1.1]
      egress:
        routes: [203.0.113.5:9200/udp]`, "no via"},
		"egress bridge with a range": {`
    - port: 51820
      ingress:
        routes: [203.0.113.5:9000/udp]
      egress:
        bridges: [5.6.7.8:9200-9210/udp]`, "one server port"},
		"no egress": {`
    - port: 51820
      ingress:
        bridges: [5.6.7.8:9000/udp]
      egress:
        mode: repeater`, "at least one route or bridge"},
	} {
		_, err := Load(writeFile(t, "client:\n  advertise: 192.0.2.10\n  servers:"+test.servers+"\n"))
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("%s: error = %v, want %q", name, err, test.want)
		}
	}
}

func TestGroupRejectsABridgeWithoutEgressPaths(t *testing.T) {
	t.Parallel()

	path, err := ParsePath("5.6.7.8:9000/udp")
	if err != nil {
		t.Fatal(err)
	}
	path.Bridge = true
	client := Client{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), Groups: []Group{{ListenPort: 51820, Paths: []Path{path}}}}
	if err := client.Validate(); err == nil || !strings.Contains(err.Error(), "ingress and egress") {
		t.Fatalf("Validate error = %v", err)
	}
}

func TestLoadBridge(t *testing.T) {
	t.Parallel()

	app, err := Load(writeFile(t, `
bridge:
  server: 46.102.130.95
  port: 9000-9399
  allow:
    - 46.102.130.0/24
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	bridge := app.Bridge
	if bridge == nil || bridge.Server != netip.MustParseAddr("46.102.130.95") || bridge.Port != (PortRange{First: 9000, Last: 9399}) {
		t.Fatalf("bridge = %#v", bridge)
	}
	if len(bridge.Allow) != 1 || bridge.Allow[0] != netip.MustParsePrefix("46.102.130.0/24") {
		t.Fatalf("allow = %v", bridge.Allow)
	}
	if bridge.ControlSocket != api.DefaultBridgeSocket {
		t.Fatalf("control socket = %q", bridge.ControlSocket)
	}
}

func TestBridgeValidate(t *testing.T) {
	t.Parallel()

	good := Bridge{Server: netip.MustParseAddr("46.102.130.95"), Port: PortRange{First: 9000, Last: 9399}}
	if err := good.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for name, change := range map[string]func(*Bridge){
		"no server": func(b *Bridge) { b.Server = netip.Addr{} },
		"no port":   func(b *Bridge) { b.Port = PortRange{} },
		"open":      func(b *Bridge) { b.Allow = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")} },
		"ipv6":      func(b *Bridge) { b.Allow = []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")} },
	} {
		bridge := good
		change(&bridge)
		if err := bridge.Validate(); err == nil {
			t.Fatalf("%s: Validate succeeded", name)
		}
	}
	if err := (App{Bridge: &good, Server: &Server{}}).Validate(); err == nil {
		t.Fatal("App with a bridge and a server is valid")
	}
}

const bridgesExample = `
bridges:
  - server: 160.119.74.33
    port: 9000-9999
    allow:
      - 79.175.167.5/32
      - 46.102.130.95/32
  - server: 178.160.229.46
    port: 5000-5005
    allow:
      - 79.175.167.5/32
      - 178.160.228.0/24
`

func TestLoadBridgeWithSeveralEntries(t *testing.T) {
	t.Parallel()

	app, err := Load(writeFile(t, bridgesExample))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	entries := app.BridgeEntries()
	if app.Bridge != nil || len(entries) != 2 {
		t.Fatalf("entries = %#v", entries)
	}
	first, second := entries[0], entries[1]
	if first.Server != netip.MustParseAddr("160.119.74.33") || first.Port != (PortRange{First: 9000, Last: 9999}) || len(first.Allow) != 2 ||
		first.Allow[1] != netip.MustParsePrefix("46.102.130.95/32") {
		t.Fatalf("first entry = %#v", first)
	}
	if second.Server != netip.MustParseAddr("178.160.229.46") || second.Port != (PortRange{First: 5000, Last: 5005}) || len(second.Allow) != 2 ||
		second.Allow[1] != netip.MustParsePrefix("178.160.228.0/24") {
		t.Fatalf("second entry = %#v", second)
	}
	if socket := app.BridgeControlSocket(); socket != api.DefaultBridgeSocket {
		t.Fatalf("control socket = %q, want the default", socket)
	}
}

func TestBridgeEntriesOfEachForm(t *testing.T) {
	t.Parallel()

	one := Bridge{Server: netip.MustParseAddr("46.102.130.95"), Port: SinglePort(9000), ControlSocket: "/tmp/one.sock"}
	if entries := (App{Bridge: &one}).BridgeEntries(); len(entries) != 1 || entries[0].Server != one.Server {
		t.Fatalf("entries of bridge = %#v", entries)
	}
	if socket := (App{Bridge: &one}).BridgeControlSocket(); socket != "/tmp/one.sock" {
		t.Fatalf("control socket of bridge = %q", socket)
	}
	two := Bridge{Server: netip.MustParseAddr("178.160.229.46"), Port: SinglePort(5000), ControlSocket: api.DefaultBridgeSocket}
	list := App{Bridges: []Bridge{one, two}}
	if entries := list.BridgeEntries(); len(entries) != 2 || entries[1].Server != two.Server {
		t.Fatalf("entries of bridges = %#v", entries)
	}
	if socket := list.BridgeControlSocket(); socket != "/tmp/one.sock" {
		t.Fatalf("control socket of bridges = %q, want the socket of the first entry", socket)
	}
	for name, app := range map[string]App{"client": {Client: &Client{}}, "empty list": {Bridges: []Bridge{}}, "nothing": {}} {
		if entries := app.BridgeEntries(); entries != nil {
			t.Fatalf("%s: entries = %#v, want nil", name, entries)
		}
		if socket := app.BridgeControlSocket(); socket != "" {
			t.Fatalf("%s: control socket = %q, want none", name, socket)
		}
	}
}

func TestLoadBridgeRefusesBothKeys(t *testing.T) {
	t.Parallel()

	_, err := Load(writeFile(t, `
bridge:
  server: 46.102.130.95
  port: 9000-9399
`+bridgesExample))
	if err == nil || !strings.Contains(err.Error(), "bridge or bridges, not both") {
		t.Fatalf("Load error = %v", err)
	}
}

func TestLoadBridgeRefusesMoreThanEightEntries(t *testing.T) {
	t.Parallel()

	var content strings.Builder
	content.WriteString("bridges:\n")
	for index := range MaxBridges + 1 {
		fmt.Fprintf(&content, "  - server: 160.119.74.33\n    port: %d\n", 9000+index)
	}
	_, err := Load(writeFile(t, content.String()))
	if err == nil || !strings.Contains(err.Error(), "bridges has 9 entries, and a bridge takes at most 8") {
		t.Fatalf("Load error = %v", err)
	}
	content.Reset()
	content.WriteString("bridges:\n")
	for index := range MaxBridges {
		fmt.Fprintf(&content, "  - server: 160.119.74.33\n    port: %d\n", 9000+index)
	}
	if _, err := Load(writeFile(t, content.String())); err != nil {
		t.Fatalf("Load of %d entries: %v", MaxBridges, err)
	}
}

func TestLoadBridgeRefusesAnEmptyListAsNoRole(t *testing.T) {
	t.Parallel()

	_, err := Load(writeFile(t, "bridges: []\n"))
	if err == nil || !strings.Contains(err.Error(), "exactly one of client, server, and bridge") {
		t.Fatalf("Load error = %v", err)
	}
}

func TestBridgeEntriesMustNotShareAPort(t *testing.T) {
	t.Parallel()

	entry := func(server string, first, last uint16) Bridge {
		return Bridge{Server: netip.MustParseAddr(server), Port: PortRange{First: first, Last: last}, ControlSocket: api.DefaultBridgeSocket}
	}
	overlap := App{Bridges: []Bridge{entry("160.119.74.33", 9000, 9999), entry("178.160.229.46", 5000, 5005), entry("178.160.229.46", 9999, 10005)}}
	err := overlap.Validate()
	if err == nil || err.Error() != "the ports 9000-9999 of bridge entry 1 overlap the ports 9999-10005 of bridge entry 3" {
		t.Fatalf("Validate of overlapping entries = %v", err)
	}
	touching := App{Bridges: []Bridge{entry("160.119.74.33", 9000, 9999), entry("160.119.74.33", 10000, 10005)}}
	if err := touching.Validate(); err != nil {
		t.Fatalf("Validate of touching entries with the same server: %v", err)
	}
	invalid := App{Bridges: []Bridge{entry("160.119.74.33", 9000, 9999), {Port: SinglePort(5000)}}}
	if err := invalid.Validate(); err == nil || err.Error() != "bridge entry 2: bridge server must be a nonzero IPv4 address" {
		t.Fatalf("Validate of an invalid entry = %v", err)
	}
}

func TestLoadBridgeTakesTheControlSocketOfTheFirstEntry(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct {
		second string
		want   string
	}{
		"the default on a later entry": {second: "", want: "/run/mup/first.sock"},
		"the same socket":              {second: "    control_socket: /run/mup/first.sock\n", want: "/run/mup/first.sock"},
		"the default written out":      {second: "    control_socket: " + api.DefaultBridgeSocket + "\n", want: "/run/mup/first.sock"},
	} {
		app, err := Load(writeFile(t, `
bridges:
  - server: 160.119.74.33
    port: 9000-9999
    control_socket: /run/mup/first.sock
  - server: 178.160.229.46
    port: 5000-5005
`+test.second))
		if err != nil {
			t.Fatalf("%s: Load: %v", name, err)
		}
		if socket := app.BridgeControlSocket(); socket != test.want {
			t.Fatalf("%s: control socket = %q, want %q", name, socket, test.want)
		}
	}

	_, err := Load(writeFile(t, `
bridges:
  - server: 160.119.74.33
    port: 9000-9999
  - server: 178.160.229.46
    port: 5000-5005
    control_socket: /run/mup/second.sock
`))
	if err == nil || !strings.Contains(err.Error(), `bridge entry 2: control_socket "/run/mup/second.sock" differs from the first entry: set control_socket on the first entry only`) {
		t.Fatalf("Load error = %v", err)
	}
}
