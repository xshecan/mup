package main

import (
	"strings"
	"testing"
	"time"

	"github.com/xshecan/mup/api"
)

func TestBridgeCommands(t *testing.T) {
	t.Parallel()

	daemon := fakeDaemon(t, splitClientStatus())
	if code, stdout, stderr := runCommand(t, daemon, "add", "path", "5.6.7.8:9600/udp", "--bridge", "--group", "51820"); code != 0 ||
		!strings.Contains(stdout, "bridge/5 created in group 51820 (5.6.7.8:9600/udp, unhealthy until the first ACK)") {
		t.Fatalf("add bridge = %d, %q, %q", code, stdout, stderr)
	}
	if code, stdout, stderr := runCommand(t, daemon, "add", "path", "5.6.7.8:9600/udp", "--bridge", "--egress", "--group", "51820"); code != 0 ||
		!strings.Contains(stdout, "egress-bridge/5 created in group 51820 (5.6.7.8:9600/udp, unhealthy until the first probe)") {
		t.Fatalf("add egress bridge = %d, %q, %q", code, stdout, stderr)
	}
	if code, _, stderr := runCommand(t, daemon, "delete", "path", "1", "--bridge"); code != 2 || !strings.Contains(stderr, "--bridge works only with add") {
		t.Fatalf("delete --bridge = %d, %q", code, stderr)
	}
}

func TestPathsShowTheBridges(t *testing.T) {
	t.Parallel()

	status := splitClientStatus()
	status.Client.Paths = append(status.Client.Paths, api.Path{
		ID: 2, Direction: "egress", Bridge: true, ListenPort: 51820, Server: "5.6.7.8", Port: 9700, Transport: "icmp",
		ReturnIP: "87.107.117.192/28", Healthy: true, LastProbe: testNow.Add(-time.Second),
	})
	code, stdout, stderr := runCommand(t, fakeDaemon(t, status), "get", "paths")
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{
		"ID   PATH      KIND     GROUP   SERVER",
		"0    ingress   route    51820   203.0.113.5:9000",
		"2    egress    bridge   51820   5.6.7.8:9700       icmp        87.107.117.192/28",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("paths output misses %q:\n%s", want, stdout)
		}
	}
}

func TestStatusShowsABridge(t *testing.T) {
	t.Parallel()

	status := api.Status{
		Role:      api.RoleBridge,
		StartedAt: testNow.Add(-time.Minute),
		Bridge: &api.BridgeStatus{
			Server: "46.102.130.95", Port: 9000, PortLast: 9399, Addresses: []string{"5.6.7.8"},
			IngressPackets: 12, IngressBytes: 2048, EgressPackets: 30, EgressBytes: 3 * 1024 * 1024,
		},
		Drops: []api.Drop{{Reason: 23, Name: "BRIDGE_SOURCE", Count: 4}},
	}
	var out strings.Builder
	printStatus(&out, status, nil, false, testNow)
	for _, want := range []string{
		"Role:        bridge",
		"Server:      46.102.130.95",
		"Port:        9000-9399",
		"Allow:       -",
		"Addresses:   5.6.7.8",
		"Ingress:     12 packets, 2.0 KiB",
		"Egress:      30 packets, 3.0 MiB",
		"BRIDGE_SOURCE",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("status output misses %q:\n%s", want, out.String())
		}
	}
}
