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

func TestPathsTellTheTwoKindsOfEgressBridgeWithAVia(t *testing.T) {
	t.Parallel()

	status := splitClientStatus()
	status.Client.Paths = append(status.Client.Paths,
		api.Path{ID: 2, Direction: "egress", Bridge: true, ListenPort: 51820, Server: "5.6.7.8", Port: 9700, Transport: "icmp", ReturnIP: "87.107.117.192/28"},
		api.Path{ID: 3, Direction: "egress", Bridge: true, BridgeVia: true, ListenPort: 51820, Server: "5.6.7.9", Port: 9701, Transport: "udp", ReturnIP: "87.107.117.200"},
	)
	code, stdout, stderr := runCommand(t, fakeDaemon(t, status), "get", "paths")
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{
		"2    egress    bridge       51820   5.6.7.8:9700       icmp        87.107.117.192/28",
		"3    egress    bridge-via   51820   5.6.7.9:9701       udp         87.107.117.200",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("paths output misses %q:\n%s", want, stdout)
		}
	}
}

func TestClientsTellTheTwoKindsOfEgressBridgeWithAVia(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	printClients(&out, []api.RegisteredClient{{
		AdvertisedIP: "192.0.2.10",
		Nonce:        "8f3a0000000000aa",
		LeaseSeconds: 24,
		Egress: &api.EgressGroup{Mode: "failover", Paths: []api.EgressPath{
			{ID: 0, Bridge: true, Server: "5.6.7.8", Port: 9700, Transport: "icmp", ReturnIP: "87.107.117.192/28", Healthy: true, Members: 9, HealthyMembers: 7},
			{ID: 1, Bridge: true, BridgeVia: true, Server: "5.6.7.9", Port: 9701, Transport: "udp", ReturnIP: "87.107.117.200", Members: 1},
			{ID: 2, Bridge: true, Server: "5.6.7.9", Port: 9702, Transport: "udp"},
		}},
	}}, true)
	want := "0:icmp:bridge 5.6.7.8:9700 reflects via 87.107.117.192/28 (7/9)," +
		"1:udp:bridge 5.6.7.9:9701 via 87.107.117.200 (0/1)," +
		"2:udp:bridge 5.6.7.9:9702"
	if !strings.Contains(out.String(), want) {
		t.Fatalf("clients output misses %q:\n%s", want, out.String())
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

func TestStatusShowsABridgeWithOneEntryAsBefore(t *testing.T) {
	t.Parallel()

	bridge := api.BridgeStatus{
		Server: "46.102.130.95", Port: 9000, PortLast: 9399, Allow: []string{"46.102.130.0/24"}, Addresses: []string{"5.6.7.8"},
		IngressPackets: 12, IngressBytes: 2048, EgressPackets: 30, EgressBytes: 3 * 1024 * 1024,
	}
	status := api.Status{Role: api.RoleBridge, StartedAt: testNow.Add(-time.Minute), Bridge: &bridge}
	var before strings.Builder
	printStatus(&before, status, nil, false, testNow)

	withEntries := bridge
	withEntries.Entries = []api.BridgeEntryStatus{{Server: "46.102.130.95", Port: 9000, PortLast: 9399, Allow: []string{"46.102.130.0/24"}}}
	status.Bridge = &withEntries
	var after strings.Builder
	printStatus(&after, status, nil, false, testNow)
	if after.String() != before.String() {
		t.Fatalf("status of one entry:\n%s\nwant the output without entries:\n%s", after.String(), before.String())
	}
	if strings.Contains(after.String(), "SERVER") {
		t.Fatalf("status of one entry shows a table:\n%s", after.String())
	}
}

func TestStatusShowsTheEntriesOfABridgeInATable(t *testing.T) {
	t.Parallel()

	status := api.Status{
		Role:      api.RoleBridge,
		StartedAt: testNow.Add(-time.Minute),
		Bridge: &api.BridgeStatus{
			Server: "160.119.74.33", Port: 9000, PortLast: 9999, Allow: []string{"79.175.167.5/32", "46.102.130.95/32"},
			Entries: []api.BridgeEntryStatus{
				{Server: "160.119.74.33", Port: 9000, PortLast: 9999, Allow: []string{"79.175.167.5/32", "46.102.130.95/32"}},
				{Server: "178.160.229.46", Port: 5000, PortLast: 5005, Allow: []string{"79.175.167.5/32", "178.160.228.0/24"}},
				{Server: "178.160.229.46", Port: 6000, PortLast: 6000},
			},
			Addresses:      []string{"5.6.7.8"},
			IngressPackets: 12, IngressBytes: 2048, EgressPackets: 30, EgressBytes: 3 * 1024 * 1024,
		},
	}
	var out strings.Builder
	printStatus(&out, status, nil, false, testNow)
	want := `Role:        bridge
Addresses:   5.6.7.8
Uptime:      1m
Ingress:     12 packets, 2.0 KiB
Egress:      30 packets, 3.0 MiB
Drops:       0

SERVER           PORT        ALLOW
160.119.74.33    9000-9999   79.175.167.5/32, 46.102.130.95/32
178.160.229.46   5000-5005   79.175.167.5/32, 178.160.228.0/24
178.160.229.46   6000        -
`
	if out.String() != want {
		t.Fatalf("status output:\n%s\nwant:\n%s", out.String(), want)
	}
}
