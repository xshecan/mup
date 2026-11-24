package main

import (
	"strings"
	"testing"
	"time"

	"github.com/xshecan/mup/api"
)

func splitClientStatus() api.Status {
	return api.Status{
		Role:      api.RoleClient,
		StartedAt: testNow.Add(-time.Hour),
		Client: &api.ClientStatus{
			AdvertisedIP: "192.0.2.10",
			Generation:   2,
			TokensFree:   4095,
			Groups: []api.Group{
				{ListenPort: 51820, Mode: "failover", Paths: 1, HealthyPaths: 1, EgressMode: "repeater", EgressPaths: 2, HealthyEgressPaths: 1},
				{ListenPort: 51821, Mode: "balancer", Paths: 1, HealthyPaths: 1},
			},
			Paths: []api.Path{
				{ID: 0, Direction: "ingress", ListenPort: 51820, Server: "203.0.113.5", Port: 9000, Transport: "udp", Interface: "eth0", Healthy: true, InUse: true, LastACK: testNow.Add(-4 * time.Second), RTTSeconds: 0.07},
				{ID: 1, ListenPort: 51821, Server: "203.0.113.6", Port: 5000, Transport: "icmp", Interface: "eth0", Healthy: true, InUse: true, LastACK: testNow.Add(-2 * time.Second)},
				{ID: 0, Direction: "egress", ListenPort: 51820, Server: "203.0.113.5", Port: 9200, Transport: "icmp", ReturnIP: "198.51.100.0/28", Healthy: true, InUse: true, LastProbe: testNow.Add(-time.Second), RTTSeconds: 0.0345},
				{ID: 1, Direction: "egress", ListenPort: 51820, Server: "203.0.113.5", Port: 9300, Transport: "udp"},
			},
		},
	}
}

func TestStatusShowsSeparateDirections(t *testing.T) {
	t.Parallel()

	code, stdout, stderr := runCommand(t, fakeDaemon(t, splitClientStatus()), "status")
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{
		"Paths:          2/2 healthy, generation 2",
		"Egress paths:   1/2 healthy",
		"GROUP   MODE       PATHS         EGRESS MODE   EGRESS PATHS   PEERS",
		"51820   failover   1/1 healthy   repeater      1/2 healthy    0",
		"51821   balancer   1/1 healthy   -             -              0",
		"ID   PATH      GROUP   SERVER",
		"0    ingress   51820   203.0.113.5:9000   udp         -                 eth0        active      4s ago",
		"0    egress    51820   203.0.113.5:9200   icmp        198.51.100.0/28   -           active      1s ago   34.5ms",
		"1    egress    51820   203.0.113.5:9300   udp         -                 -           unhealthy   never",
		"1    -         51821   203.0.113.6:5000   icmp",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("status output misses %q:\n%s", want, stdout)
		}
	}
}

func TestEgressPathCommands(t *testing.T) {
	t.Parallel()

	daemon := fakeDaemon(t, splitClientStatus())
	if code, stdout, stderr := runCommand(t, daemon, "add", "path", "203.0.113.8:9300/udp", "via", "198.51.100.0/28", "per-packet", "--egress", "--group", "51820"); code != 0 ||
		!strings.Contains(stdout, "egress-path/4 created in group 51820 (203.0.113.8:9300/udp via 198.51.100.0/28, unhealthy until the first probe)") {
		t.Fatalf("add egress path = %d, %q, %q", code, stdout, stderr)
	}
	if code, stdout, stderr := runCommand(t, daemon, "delete", "path", "1", "--egress"); code != 0 || stdout != "egress-path/1 deleted\n" {
		t.Fatalf("delete egress path = %d, %q, %q", code, stdout, stderr)
	}
	if code, stdout, stderr := runCommand(t, daemon, "set", "mode", "balancer", "--egress", "--group", "51821"); code != 0 || stdout != "egress mode set to balancer\n" {
		t.Fatalf("set egress mode = %d, %q, %q", code, stdout, stderr)
	}
	if code, _, stderr := runCommand(t, daemon, "get", "paths", "--egress"); code != 2 && !strings.Contains(stderr, "--egress works only") {
		t.Fatalf("get paths --egress = %d, %q", code, stderr)
	}
}

func TestClientsShowTheEgressPaths(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	printClients(&out, []api.RegisteredClient{{
		AdvertisedIP: "192.0.2.10",
		Nonce:        "8f3a0000000000aa",
		LeaseSeconds: 24,
		Egress: &api.EgressGroup{Mode: "failover", Paths: []api.EgressPath{
			{ID: 0, Server: "203.0.113.5", Port: 9200, Transport: "icmp", ReturnIP: "198.51.100.0/28", Healthy: true, Members: 9, HealthyMembers: 7},
			{ID: 1, Server: "203.0.113.5", Port: 9300, Transport: "udp"},
		}},
	}}, true)
	for _, want := range []string{"1/2 healthy, failover", "0:icmp:203.0.113.5:9200 via 198.51.100.0/28 (7/9),1:udp:203.0.113.5:9300"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("clients output misses %q:\n%s", want, out.String())
		}
	}
}

func TestClientsShowTheListenPortsAndEveryEgressGroup(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	printClients(&out, []api.RegisteredClient{{
		AdvertisedIP: "192.0.2.10",
		Nonce:        "8f3a0000000000aa",
		LeaseSeconds: 24,
		ListenPort:   51825,
		Paths: []api.RegisteredPath{
			{ID: 0, ListenPort: 51825, Transport: "udp", Local: "203.0.113.5"},
			{ID: 1, ListenPort: 51820, Transport: "udp", Local: "203.0.113.5"},
			{ID: 2, ListenPort: 51820, Transport: "udp", Local: "203.0.113.6"},
		},
		Egresses: []api.EgressGroup{
			{ListenPort: 51820, Mode: "failover", Paths: []api.EgressPath{{ID: 0, Server: "203.0.113.5", Port: 9200, Transport: "udp", Healthy: true}}},
			{ListenPort: 51825, Mode: "repeater", Paths: []api.EgressPath{{ID: 3, Server: "203.0.113.5", Port: 9300, Transport: "udp"}}},
		},
	}}, true)
	for _, want := range []string{"51820,51825", "51820:1/1 healthy, failover; 51825:0/1 healthy, repeater", "51820:0:udp:203.0.113.5:9200; 51825:3:udp:203.0.113.5:9300"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("clients output misses %q:\n%s", want, out.String())
		}
	}
}

func TestClientsFallBackToTheClientListenPort(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	printClients(&out, []api.RegisteredClient{{
		AdvertisedIP: "192.0.2.10",
		Nonce:        "8f3a0000000000aa",
		LeaseSeconds: 24,
		ListenPort:   51820,
		Paths:        []api.RegisteredPath{{ID: 0, Transport: "udp", Local: "203.0.113.5"}},
	}}, true)
	if !strings.Contains(out.String(), "51820") {
		t.Fatalf("clients output misses the listen port:\n%s", out.String())
	}
}
