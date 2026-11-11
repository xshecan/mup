package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xshecan/mup/api"
	"github.com/xshecan/mup/protocol"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mup.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return path
}

func TestLoadServer(t *testing.T) {
	t.Parallel()

	app, err := Load(writeFile(t, `
server:
  port: 5000
  target: 198.51.100.7:51820
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if app.Client != nil || app.Server == nil {
		t.Fatalf("role = %#v", app)
	}
	if app.Server.Port != 5000 || app.Server.Target != netip.MustParseAddrPort("198.51.100.7:51820") {
		t.Fatalf("server = %#v", app.Server)
	}
	if app.Server.ControlSocket != api.DefaultServerSocket {
		t.Fatalf("control socket = %q, want the default", app.Server.ControlSocket)
	}
}

func TestLoadClient(t *testing.T) {
	t.Parallel()

	app, err := Load(writeFile(t, `
client:
  advertised_ip: 192.0.2.10
  control_socket: ""
  groups:
    - listen_port: 51820
      mode: burst
      return_ip: 1.1.1.1
      paths:
        - 203.0.113.5:5000/udp
        - 203.0.113.6%eth1:5000/icmp
    - listen_port: 51821
      paths:
        - 198.51.100.20:6000/udp
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	client := app.Client
	if client == nil || app.Server != nil {
		t.Fatalf("role = %#v", app)
	}
	if client.AdvertisedIP != netip.MustParseAddr("192.0.2.10") || len(client.Groups) != 2 {
		t.Fatalf("client = %#v", client)
	}
	if client.ControlSocket != "" {
		t.Fatalf("control socket = %q, want it turned off", client.ControlSocket)
	}
	first, second := client.Groups[0], client.Groups[1]
	if first.ListenPort != 51820 || first.Mode != ModeBurst || first.ReturnIP != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("first group = %#v", first)
	}
	want := Path{Server: netip.MustParseAddr("203.0.113.6"), ServerPort: 5000, Transport: protocol.TransportICMP, Interface: "eth1"}
	if len(first.Paths) != 2 || first.Paths[1] != want {
		t.Fatalf("first group paths = %#v", first.Paths)
	}
	if second.ListenPort != 51821 || second.Mode != ModeFallback || second.ReturnIP.IsValid() || second.Paths[0].ServerPort != 6000 {
		t.Fatalf("second group = %#v", second)
	}
}

func TestLoadClientDefaultControlSocket(t *testing.T) {
	t.Parallel()

	app, err := Load(writeFile(t, `
client:
  advertised_ip: 192.0.2.10
  groups:
    - listen_port: 51820
      paths: [203.0.113.5:5000/udp]
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if app.Client.ControlSocket != api.DefaultClientSocket {
		t.Fatalf("control socket = %q, want the default", app.Client.ControlSocket)
	}
}

func TestLoadExpandsEnvironmentVariables(t *testing.T) {
	t.Setenv("MUP_TEST_TARGET", "198.51.100.7:51820")
	app, err := Load(writeFile(t, `
server:
  port: ${MUP_TEST_PORT:5000}
  target: ${MUP_TEST_TARGET}
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if app.Server.Port != 5000 || app.Server.Target != netip.MustParseAddrPort("198.51.100.7:51820") {
		t.Fatalf("server = %#v", app.Server)
	}
}

func TestLoadRejectsInvalidFiles(t *testing.T) {
	t.Parallel()

	const client = "client:\n  advertised_ip: 192.0.2.10\n  groups:\n    - listen_port: 51820\n"
	const server = "server:\n  port: 5000\n  target: 198.51.100.7:51820\n"
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"empty", "", "exactly one"},
		{"both roles", client + "      paths: [203.0.113.5:5000/udp]\n" + server, "exactly one"},
		{"unknown key", server + "  tartget: 198.51.100.7:51820\n", "tartget"},
		{"unknown top-level key", server + "extra: 1\n", "extra"},
		{"bad mode", client + "      mode: sideways\n      paths: [203.0.113.5:5000/udp]\n", "sideways"},
		{"bad path", client + "      paths: [203.0.113.5:5000/tcp]\n", "203.0.113.5:5000/tcp"},
		{"null path", client + "      paths: [~]\n", "group 51820: path 0"},
		{"no paths", client, "at least one path"},
		{"no groups", "client:\n  advertised_ip: 192.0.2.10\n", "at least one group"},
		{"unknown group key", client + "      paths: [203.0.113.5:5000/udp]\n      moode: burst\n", "moode"},
		{"port overflow", "server:\n  port: 70000\n  target: 198.51.100.7:51820\n", "70000"},
		{"zero port", "server:\n  port: 0\n  target: 198.51.100.7:51820\n", "server port"},
		{"IPv6 target", "server:\n  port: 5000\n  target: \"[2001:db8::1]:51820\"\n", "server target"},
		{"missing variable", "server:\n  port: 5000\n  target: ${MUP_TEST_MISSING}\n", "MUP_TEST_MISSING"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Load(writeFile(t, test.content))
			if err == nil {
				t.Fatal("Load unexpectedly succeeded")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load error = %v, want it to mention %q", err, test.want)
			}
		})
	}
}

func TestLoadAcceptsTheExampleFiles(t *testing.T) {
	t.Parallel()

	client, err := Load(filepath.Join("..", "configs", "client.yaml"))
	if err != nil {
		t.Fatalf("Load client example: %v", err)
	}
	if len(client.Client.Groups) != 2 {
		t.Fatalf("client example groups = %#v", client.Client.Groups)
	}
	if _, err := Load(filepath.Join("..", "configs", "server.yaml")); err != nil {
		t.Fatalf("Load server example: %v", err)
	}
}

func TestLoadReportsAMissingFile(t *testing.T) {
	t.Parallel()

	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("Load of a missing file unexpectedly succeeded")
	}
}
