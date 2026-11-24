package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xshecan/mup/api"
)

func TestWidePathsShowTheSourceRange(t *testing.T) {
	t.Parallel()

	paths := []api.Path{
		{ID: 0, ListenPort: 51820, Server: "203.0.113.5", Port: 9000, Transport: "udp", SrcFirst: 20000, SrcLast: 20999},
		{ID: 1, ListenPort: 51820, Server: "203.0.113.6", Port: 5000, Transport: "icmp", SrcFirst: 30000, SrcLast: 30000},
		{ID: 2, ListenPort: 51820, Server: "203.0.113.7", Port: 5000, Transport: "udp"},
	}
	var wide bytes.Buffer
	printPaths(&wide, paths, true, testNow)
	lines := strings.Split(strings.TrimSpace(wide.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("output = %q", wide.String())
	}
	header := strings.Fields(lines[0])
	column := -1
	for index, name := range header {
		if name == "SRC" {
			column = index
		}
	}
	if column < 0 {
		t.Fatalf("header = %q, want SRC", lines[0])
	}
	// The SRC column counts from the end, because the STATE and SEEN cells
	// have spaces in them.
	fromEnd := len(header) - column
	for line, want := range map[int]string{1: "20000-20999", 2: "30000", 3: "-"} {
		fields := strings.Fields(lines[line])
		if got := fields[len(fields)-fromEnd]; got != want {
			t.Fatalf("row %d SRC = %q, want %q: %q", line, got, want, lines[line])
		}
	}

	var normal bytes.Buffer
	printPaths(&normal, paths, false, testNow)
	if strings.Contains(normal.String(), "SRC") || strings.Contains(normal.String(), "20000") {
		t.Fatalf("normal output shows the source range:\n%s", normal.String())
	}
}

func TestWideClientsShowTheSourceRangeOfEachPath(t *testing.T) {
	t.Parallel()

	clients := []api.RegisteredClient{{
		AdvertisedIP: "192.0.2.10",
		Nonce:        "8f3a0000000000aa",
		LeaseSeconds: 24,
		ListenPort:   51820,
		Paths: []api.RegisteredPath{
			{ID: 0, ListenPort: 51820, Transport: "icmp", Local: "203.0.113.5", SrcFirst: 20000, SrcLast: 20999},
			{ID: 1, ListenPort: 51820, Transport: "udp", Local: "203.0.113.5"},
		},
		Egress: &api.EgressGroup{Mode: "failover", Paths: []api.EgressPath{
			{ID: 0, Server: "203.0.113.5", Port: 9200, Transport: "udp", SrcFirst: 30000, SrcLast: 30000},
			{ID: 1, Server: "203.0.113.5", Port: 9300, Transport: "udp"},
		}},
	}}
	var wide strings.Builder
	printClients(&wide, clients, true)
	for _, want := range []string{"0:icmp:203.0.113.5 src 20000-20999,1:udp:203.0.113.5", "0:udp:203.0.113.5:9200 src 30000,1:udp:203.0.113.5:9300"} {
		if !strings.Contains(wide.String(), want) {
			t.Fatalf("wide clients output misses %q:\n%s", want, wide.String())
		}
	}
	var normal strings.Builder
	printClients(&normal, clients, false)
	if strings.Contains(normal.String(), "src") {
		t.Fatalf("normal clients output shows the source range:\n%s", normal.String())
	}
}
