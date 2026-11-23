package main

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xshecan/mup/api"
	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/protocol"
)

func TestParseArgsClientExamples(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		transport string
		wantID    protocol.TransportID
		reflected bool
	}{
		{name: "udp direct", transport: "udp", wantID: protocol.TransportUDP},
		{name: "udp reflected", transport: "udp", wantID: protocol.TransportUDP, reflected: true},
		{name: "icmp direct", transport: "icmp", wantID: protocol.TransportICMP},
		{name: "icmp reflected", transport: "icmp", wantID: protocol.TransportICMP, reflected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{
				"client", "-p", "51820",
				"-u", "160.119.74.6:5000/" + tt.transport,
				"-u", "160.119.74.7:5000/" + tt.transport,
				"-s", "192.0.2.10",
			}
			if tt.reflected {
				args = append(args, "-r", "1.1.1.1")
			}

			app, err := parseArgs(args)
			if err != nil {
				t.Fatalf("parseArgs: %v", err)
			}
			if app.Server != nil || app.Client == nil {
				t.Fatalf("unexpected app mode: %#v", app)
			}
			client := app.Client
			if client.AdvertisedIP != netip.MustParseAddr("192.0.2.10") || len(client.Groups) != 1 {
				t.Fatalf("unexpected client: %#v", client)
			}
			group := client.Groups[0]
			if group.ListenPort != 51820 || group.Mode != config.ModeFallback || len(group.Paths) != 2 {
				t.Fatalf("unexpected group: %#v", group)
			}
			for _, path := range group.Paths {
				if path.ServerPort != 5000 || path.Transport != tt.wantID {
					t.Fatalf("unexpected path: %#v", path)
				}
			}
			for _, path := range group.Paths {
				if tt.reflected && path.ReturnIP != netip.MustParseAddr("1.1.1.1") {
					t.Fatalf("return IP = %v", path.ReturnIP)
				}
				if !tt.reflected && path.ReturnIP.IsValid() {
					t.Fatalf("unexpected return IP = %v", path.ReturnIP)
				}
			}
		})
	}
}

func TestParseArgsClientAcceptsPathsWithDifferentPorts(t *testing.T) {
	t.Parallel()

	app, err := parseArgs([]string{
		"client", "-p", "51820",
		"-u", "192.0.2.1:5000/udp",
		"-u", "192.0.2.2:5001/icmp",
		"-s", "192.0.2.10",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if got := app.Client.Groups[0].Paths[1].ServerPort; got != 5001 {
		t.Fatalf("second path port = %d, want 5001", got)
	}
}

func TestParseArgsClientMixedPathsAndInterface(t *testing.T) {
	t.Parallel()

	app, err := parseArgs([]string{
		"client", "-p", "51820",
		"-u", "192.0.2.1%eth0:5000/udp",
		"-u", "198.51.100.1:5000/icmp",
		"-s", "203.0.113.10",
		"--mode", "burst",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if group := app.Client.Groups[0]; group.Mode != config.ModeBurst || group.Paths[0].Interface != "eth0" {
		t.Fatalf("unexpected client config: %#v", app.Client)
	}
	if app.Client.ControlSocket != api.DefaultClientSocket {
		t.Fatalf("control socket = %q, want %q", app.Client.ControlSocket, api.DefaultClientSocket)
	}
}

func TestParseArgsControlSocket(t *testing.T) {
	t.Parallel()

	app, err := parseArgs([]string{"server", "-p", "5000", "-r", "192.0.2.1:51820", "--control-socket", "/tmp/mup.sock"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if app.Server.ControlSocket != "/tmp/mup.sock" {
		t.Fatalf("server control socket = %q", app.Server.ControlSocket)
	}
	app, err = parseArgs([]string{"server", "-p", "5000", "-r", "192.0.2.1:51820", "--control-socket="})
	if err != nil {
		t.Fatalf("parseArgs with an empty socket: %v", err)
	}
	if app.Server.ControlSocket != "" {
		t.Fatalf("disabled control socket = %q", app.Server.ControlSocket)
	}
}

func TestParseArgsServerExample(t *testing.T) {
	t.Parallel()

	app, err := parseArgs([]string{"server", "-p", "5000", "-r", "193.24.210.185:51820"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if app.Client != nil || app.Server == nil {
		t.Fatalf("unexpected app mode: %#v", app)
	}
	if app.Server.Port != config.SinglePort(5000) || app.Server.Target != netip.MustParseAddrPort("193.24.210.185:51820") {
		t.Fatalf("unexpected server config: %#v", app.Server)
	}
	if app.Server.TargetIngress {
		t.Fatal("target ingress is on without its flag")
	}
	app, err = parseArgs([]string{"server", "-p", "9000-9999", "-r", "160.119.74.6:51820", "--target-ingress"})
	if err != nil || !app.Server.TargetIngress {
		t.Fatalf("parseArgs with --target-ingress = %#v, %v", app.Server, err)
	}
}

func TestParseArgsRejectsInvalidContracts(t *testing.T) {
	t.Parallel()

	tests := [][]string{
		nil,
		{"client", "-p", "51820", "-u", "192.0.2.1:5000/udp"},
		{"client", "-p", "51820", "-s", "192.0.2.10"},
		{"client", "-p", "51820", "-u", "192.0.2.1:5000/udp", "-u", "192.0.2.1:5000/udp", "-s", "192.0.2.10"},
		{"server", "-p", "5000"},
		{"unknown", "-p", "5000"},
	}
	for _, args := range tests {
		if _, err := parseArgs(args); err == nil {
			t.Fatalf("parseArgs(%q) unexpectedly succeeded", args)
		}
	}
}

func TestParseArgsConfigurationFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "mup.yaml")
	content := "server:\n  port: 5000\n  target: 193.24.210.185:51820\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	for _, args := range [][]string{{"--config", path}, {"-c", path}, {"--config=" + path}} {
		app, err := parseArgs(args)
		if err != nil {
			t.Fatalf("parseArgs(%q): %v", args, err)
		}
		if app.Server == nil || app.Server.Port != config.SinglePort(5000) {
			t.Fatalf("parseArgs(%q) = %#v", args, app)
		}
	}
	for _, args := range [][]string{{"--config"}, {"--config", path, "extra"}, {"--unknown"}, {"--config", path + ".missing"}} {
		if _, err := parseArgs(args); err == nil {
			t.Fatalf("parseArgs(%q) unexpectedly succeeded", args)
		}
	}
}

func TestRunPrintsUsageOnlyForUsageErrors(t *testing.T) {
	t.Parallel()

	noApplication := func(context.Context, config.App) error { return nil }
	var stderr strings.Builder
	if got := run(context.Background(), []string{"--config", "/missing/mup.yaml"}, &stderr, noApplication); got != 2 {
		t.Fatalf("exit code = %d, want 2", got)
	}
	if strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("a file error printed the usage text: %s", stderr.String())
	}
	stderr.Reset()
	if got := run(context.Background(), []string{"sideways"}, &stderr, noApplication); got != 2 {
		t.Fatalf("exit code = %d, want 2", got)
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("a usage error did not print the usage text: %s", stderr.String())
	}
}

func TestRunParsesClientAndInvokesApplication(t *testing.T) {
	t.Parallel()

	called := false
	exitCode := run(context.Background(), []string{
		"client", "-p", "51820",
		"-u", "192.0.2.1:5000/udp",
		"-s", "198.51.100.10",
	}, io.Discard, func(_ context.Context, app config.App) error {
		called = true
		if app.Client == nil || app.Server != nil {
			t.Fatalf("unexpected application config: %#v", app)
		}
		return nil
	})
	if exitCode != 0 || !called {
		t.Fatalf("run exitCode/called = %d/%v, want 0/true", exitCode, called)
	}
}

func TestRunExitCodes(t *testing.T) {
	t.Parallel()

	called := false
	if got := run(context.Background(), []string{"server", "-p", "5000"}, io.Discard, func(context.Context, config.App) error {
		called = true
		return nil
	}); got != 2 || called {
		t.Fatalf("invalid CLI exitCode/called = %d/%v, want 2/false", got, called)
	}

	want := errors.New("dataplane failed")
	if got := run(context.Background(), []string{
		"server", "-p", "5000", "-r", "192.0.2.1:51820",
	}, io.Discard, func(context.Context, config.App) error {
		return want
	}); got != 1 {
		t.Fatalf("application failure exitCode = %d, want 1", got)
	}
}

func TestParseArgsClientSplitPaths(t *testing.T) {
	appConfig, err := parseArgs([]string{
		"client", "-p", "51820", "-s", "192.0.2.10",
		"--ingress", "203.0.113.5:9000/udp", "--ingress", "203.0.113.5:9100/icmp",
		"--egress", "203.0.113.5:9200/icmp via 198.51.100.0/28",
		"--ingress-mode", "balancer", "--egress-mode", "burst",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	group := appConfig.Client.Groups[0]
	if len(group.Paths) != 2 || len(group.EgressPaths) != 1 ||
		group.Mode != config.ModeBalancer || group.EgressMode != config.ModeBurst {
		t.Fatalf("group = %#v", group)
	}
}

func TestParseArgsClientOldSplitFlags(t *testing.T) {
	appConfig, err := parseArgs([]string{
		"client", "-p", "51820", "-s", "192.0.2.10",
		"--up", "203.0.113.5:9000/udp", "--down", "203.0.113.5:9200/icmp via 198.51.100.0/28",
		"--up-mode", "balancer", "--down-mode", "burst",
	})
	if err != nil {
		t.Fatalf("parseArgs with the old flags: %v", err)
	}
	group := appConfig.Client.Groups[0]
	if len(group.Paths) != 1 || len(group.EgressPaths) != 1 ||
		group.Mode != config.ModeBalancer || group.EgressMode != config.ModeBurst {
		t.Fatalf("group = %#v", group)
	}
}

func TestParseArgsClientRejectsMixedForms(t *testing.T) {
	for _, args := range [][]string{
		{"client", "-p", "51820", "-s", "192.0.2.10", "-u", "203.0.113.5:9000/udp", "--egress", "203.0.113.5:9200/udp"},
		{"client", "-p", "51820", "-s", "192.0.2.10", "--ingress", "203.0.113.5:9000/udp"},
		{"client", "-p", "51820", "-s", "192.0.2.10", "--ingress", "203.0.113.5:9000/udp", "--egress", "203.0.113.5:9200/udp", "--mode", "burst"},
	} {
		if _, err := parseArgs(args); err == nil {
			t.Fatalf("parseArgs(%q) succeeded", args)
		}
	}
}

func TestParseArgsClientBridges(t *testing.T) {
	appConfig, err := parseArgs([]string{
		"client", "-p", "51820", "-s", "160.119.74.74",
		"--ingress", "46.102.130.95:9000/icmp", "--ingress-bridge", "5.6.7.8:9100/udp",
		"--egress-bridge", "5.6.7.8:9200/icmp via 87.107.117.192/28",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	group := appConfig.Client.Groups[0]
	if len(group.Paths) != 2 || group.Paths[0].Bridge || !group.Paths[1].Bridge {
		t.Fatalf("ingress paths = %#v", group.Paths)
	}
	if len(group.EgressPaths) != 1 || !group.EgressPaths[0].Bridge {
		t.Fatalf("egress paths = %#v", group.EgressPaths)
	}
	for _, args := range [][]string{
		{"client", "-p", "51820", "-s", "192.0.2.10", "--ingress-bridge", "5.6.7.8:9100/udp"},
		{"client", "-p", "51820", "-s", "192.0.2.10", "-u", "203.0.113.5:9000/udp", "--egress-bridge", "5.6.7.8:9200/udp"},
	} {
		if _, err := parseArgs(args); err == nil {
			t.Fatalf("parseArgs(%q) succeeded", args)
		}
	}
}

func TestParseArgsBridge(t *testing.T) {
	appConfig, err := parseArgs([]string{"bridge", "-s", "46.102.130.95", "-p", "9000-9399", "-a", "46.102.130.0/24", "--control-socket", ""})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	bridge := appConfig.Bridge
	if bridge == nil || bridge.Server != netip.MustParseAddr("46.102.130.95") || bridge.Port.Last != 9399 ||
		len(bridge.Allow) != 1 || bridge.ControlSocket != "" {
		t.Fatalf("bridge = %#v", bridge)
	}
	for _, args := range [][]string{
		{"bridge", "-p", "9000"},
		{"bridge", "-s", "46.102.130.95"},
		{"bridge", "-s", "46.102.130.95", "-p", "9000", "-a", "0.0.0.0/0"},
		{"bridge", "-s", "46.102.130.95", "-p", "9000", "extra"},
	} {
		if _, err := parseArgs(args); err == nil {
			t.Fatalf("parseArgs(%q) succeeded", args)
		}
	}
}

func TestParseArgsClientOldBridgeFlags(t *testing.T) {
	appConfig, err := parseArgs([]string{
		"client", "-p", "51820", "-s", "160.119.74.74",
		"--up", "46.102.130.95:9000/icmp", "--up-bridge", "5.6.7.8:9100/udp",
		"--down-bridge", "5.6.7.8:9200/icmp via 87.107.117.192/28",
	})
	if err != nil {
		t.Fatalf("parseArgs with the old bridge flags: %v", err)
	}
	group := appConfig.Client.Groups[0]
	if len(group.Paths) != 2 || group.Paths[0].Bridge || !group.Paths[1].Bridge ||
		len(group.EgressPaths) != 1 || !group.EgressPaths[0].Bridge {
		t.Fatalf("group = %#v", group)
	}
}
