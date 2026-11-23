package config

import (
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
        mode: burst`, "at least one route or bridge"},
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
