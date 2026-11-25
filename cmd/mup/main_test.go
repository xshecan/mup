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
			if group.ListenPort != 51820 || group.Mode != config.ModeFailover || len(group.Paths) != 2 {
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
		"--mode", "repeater",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if group := app.Client.Groups[0]; group.Mode != config.ModeRepeater || group.Paths[0].Interface != "eth0" {
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
		"--ingress-mode", "balancer", "--egress-mode", "repeater",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	group := appConfig.Client.Groups[0]
	if len(group.Paths) != 2 || len(group.EgressPaths) != 1 ||
		group.Mode != config.ModeBalancer || group.EgressMode != config.ModeRepeater {
		t.Fatalf("group = %#v", group)
	}
}

// TestParseArgsClientRejectsRemovedNames checks that the flags from before the
// ingress and egress rename, and the old mode names, do not parse.
func TestParseArgsClientRejectsRemovedNames(t *testing.T) {
	base := []string{"client", "-p", "51820", "-s", "192.0.2.10"}
	for _, extra := range [][]string{
		{"--up", "203.0.113.5:9000/udp", "--egress", "203.0.113.5:9200/udp"},
		{"--ingress", "203.0.113.5:9000/udp", "--down", "203.0.113.5:9200/udp"},
		{"--ingress", "203.0.113.5:9000/udp", "--egress", "203.0.113.5:9200/udp", "--up-mode", "balancer"},
		{"--ingress", "203.0.113.5:9000/udp", "--egress", "203.0.113.5:9200/udp", "--down-mode", "balancer"},
		{"--ingress", "203.0.113.5:9000/udp", "--egress", "203.0.113.5:9200/udp", "--up-bridge", "5.6.7.8:9100/udp"},
		{"--ingress", "203.0.113.5:9000/udp", "--egress", "203.0.113.5:9200/udp", "--down-bridge", "5.6.7.8:9200/udp"},
		{"-u", "203.0.113.5:9000/udp", "--mode", "fallback"},
		{"-u", "203.0.113.5:9000/udp", "--mode", "burst"},
	} {
		args := append(append([]string{}, base...), extra...)
		if _, err := parseArgs(args); err == nil {
			t.Fatalf("parseArgs(%q) succeeded", args)
		}
	}
}

func TestParseArgsClientRejectsMixedForms(t *testing.T) {
	for _, args := range [][]string{
		{"client", "-p", "51820", "-s", "192.0.2.10", "-u", "203.0.113.5:9000/udp", "--egress", "203.0.113.5:9200/udp"},
		{"client", "-p", "51820", "-s", "192.0.2.10", "--ingress", "203.0.113.5:9000/udp"},
		{"client", "-p", "51820", "-s", "192.0.2.10", "--ingress", "203.0.113.5:9000/udp", "--egress", "203.0.113.5:9200/udp", "--mode", "repeater"},
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

func TestParseArgsClientEgressBridgesMatchTheFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "mup.yaml")
	content := `client:
  advertise: 160.119.74.74
  servers:
    - port: 51820
      ingress:
        routes: [46.102.130.95:9000/icmp]
      egress:
        routes:
          - 46.102.130.95:9201/udp via 87.107.117.9 bridge 5.6.7.8
        bridges:
          - 5.6.7.8:9202/icmp via 87.107.117.192/28
          - 5.6.7.8:9203/udp
`
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fromFile, err := config.Load(file)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	fromFlags, err := parseArgs([]string{
		"client", "-p", "51820", "-s", "160.119.74.74",
		"--ingress", "46.102.130.95:9000/icmp",
		"--egress", "46.102.130.95:9201/udp via 87.107.117.9 bridge 5.6.7.8",
		"--egress-bridge", "5.6.7.8:9202/icmp via 87.107.117.192/28",
		"--egress-bridge", "5.6.7.8:9203/udp",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	want, got := fromFile.Client.Groups[0].EgressPaths, fromFlags.Client.Groups[0].EgressPaths
	if len(got) != len(want) {
		t.Fatalf("egress paths = %#v, the file gives %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("egress path %d = %#v, the file gives %#v", index, got[index], want[index])
		}
	}
	if !got[0].Bridge || got[0].BridgeVia || !got[1].BridgeVia || got[2].BridgeVia {
		t.Fatalf("egress paths = %#v, want a bridge that reflects, a bridge via, and a plain bridge", got)
	}
	_, err = parseArgs([]string{
		"client", "-p", "51820", "-s", "160.119.74.74",
		"--ingress", "46.102.130.95:9000/icmp", "--egress", "46.102.130.95:9201/udp bridge 5.6.7.8",
	})
	if err == nil || !strings.Contains(err.Error(), "needs a via") || !strings.Contains(err.Error(), "--egress[0]") {
		t.Fatalf("parseArgs with a bridge suffix and no via error = %v", err)
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
	if entries := appConfig.BridgeEntries(); len(entries) != 1 || entries[0].Server != bridge.Server || appConfig.BridgeControlSocket() != "" {
		t.Fatalf("bridge entries = %#v", entries)
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

func TestParseArgsClientLossAndPreferSplit(t *testing.T) {
	appConfig, err := parseArgs([]string{
		"client", "-p", "51820", "-s", "192.0.2.10",
		"--ingress", "203.0.113.5:9000/udp", "--egress", "203.0.113.5:9200/udp",
		"--ingress-tolerance", "5%", "--ingress-prefer", "latency",
		"--egress-tolerance", "0.5", "--egress-prefer", "order",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	group := appConfig.Client.Groups[0]
	if group.Tolerance != 50 || group.Prefer != config.PreferLatency || group.EgressTolerance != 5 || group.EgressPrefer != config.PreferOrder {
		t.Fatalf("group = %#v", group)
	}
}

func TestParseArgsClientLossAndPreferPlainValid(t *testing.T) {
	appConfig, err := parseArgs([]string{
		"client", "-p", "51820", "-s", "192.0.2.10", "-u", "203.0.113.5:9000/udp",
		"--tolerance", "12.5", "--prefer", "latency",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	group := appConfig.Client.Groups[0]
	if group.Tolerance != 125 || group.Prefer != config.PreferLatency || group.EgressTolerance != 0 {
		t.Fatalf("group = %#v", group)
	}
}

func TestParseArgsClientLossAndPreferErrors(t *testing.T) {
	plain := []string{"client", "-p", "51820", "-s", "192.0.2.10", "-u", "203.0.113.5:9000/udp"}
	split := []string{"client", "-p", "51820", "-s", "192.0.2.10", "--ingress", "203.0.113.5:9000/udp", "--egress", "203.0.113.5:9200/udp"}
	for _, tc := range []struct {
		base  []string
		extra []string
		want  string
	}{
		{plain, []string{"--tolerance", "0"}, "--tolerance: invalid tolerance"},
		{plain, []string{"--prefer", "fast"}, `--prefer: invalid prefer "fast"`},
		{plain, []string{"--mode", "balancer", "--prefer", "latency"}, "prefer latency needs the failover mode"},
		{split, []string{"--ingress-tolerance", "0.25"}, "--ingress-tolerance: invalid tolerance"},
		{split, []string{"--egress-tolerance", "101"}, "--egress-tolerance: invalid tolerance"},
		{split, []string{"--ingress-prefer", "fast"}, "--ingress-prefer: invalid prefer"},
		{split, []string{"--egress-prefer", "latency", "--egress-mode", "repeater"}, "egress prefer latency needs the failover mode"},
		{split, []string{"--tolerance", "5"}, "not both"},
		{split, []string{"--prefer", "latency"}, "not both"},
		{plain, []string{"--egress-tolerance", "5"}, "not both"},
		{plain, []string{"--ingress-prefer", "latency"}, "not both"},
	} {
		args := append(append([]string{}, tc.base...), tc.extra...)
		_, err := parseArgs(args)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("parseArgs(%q) error = %v, want %q", args, err, tc.want)
		}
	}
}

func TestParseArgsClientReadsTheBandwidthOfARoute(t *testing.T) {
	t.Parallel()

	app, err := parseArgs([]string{"client", "-p", "51820", "-s", "192.0.2.10", "--ingress-mode", "balancer",
		"--ingress", "203.0.113.5:9000/udp bw 10mbit",
		"--ingress", "203.0.113.6:9000/udp src 5000-6000 bw 1.5gbit",
		"--egress", "203.0.113.5:9100/icmp via 198.51.100.0/28 per-packet bw 20Mbps per-member",
		"--egress", "203.0.113.5:9101/udp via 198.51.100.9 bw 500kbit bridge 192.0.2.7",
		"--egress-bridge", "192.0.2.8:9300/udp bw 3mbit"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	group := app.Client.Groups[0]
	for index, want := range []uint64{10_000_000, 1_500_000_000} {
		if got := group.Paths[index].BandwidthBitsPerSecond; got != want {
			t.Fatalf("ingress %d bandwidth = %d, want %d", index, got, want)
		}
	}
	for index, want := range []struct {
		rate      uint64
		perMember bool
	}{{20_000_000, true}, {500_000, false}, {3_000_000, false}} {
		path := group.EgressPaths[index]
		if path.BandwidthBitsPerSecond != want.rate || path.BandwidthPerMember != want.perMember {
			t.Fatalf("egress %d = %#v, want %d per-member %v", index, path, want.rate, want.perMember)
		}
	}
	if _, err := parseArgs([]string{"client", "-p", "51820", "-s", "192.0.2.10", "-u", "203.0.113.5:9000/udp bw 10mbit per-member"}); err == nil || !strings.Contains(err.Error(), "per-member needs a via") {
		t.Fatalf("parseArgs error = %v, want the per-member error", err)
	}
}
