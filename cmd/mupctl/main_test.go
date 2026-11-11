package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xshecan/mup/api"
)

var testNow = time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)

func clientStatus() api.Status {
	return api.Status{
		Role:      api.RoleClient,
		StartedAt: testNow.Add(-3*time.Hour - 12*time.Minute),
		Client: &api.ClientStatus{
			AdvertisedIP: "192.0.2.10",
			Generation:   7,
			Peers:        14,
			TokensFree:   4081,
			Groups: []api.Group{
				{ListenPort: 51820, Mode: "fallback", Paths: 2, HealthyPaths: 2, Peers: 12},
				{ListenPort: 51821, Mode: "burst", Paths: 1, Peers: 2},
			},
			Paths: []api.Path{
				{ID: 0, ListenPort: 51820, Server: "203.0.113.5", Port: 5000, Transport: "udp", Interface: "eth0", Healthy: true, InUse: true, LastACK: testNow.Add(-4 * time.Second), RTTSeconds: 0.0123},
				{ID: 1, ListenPort: 51820, Server: "203.0.113.6", Port: 5000, Transport: "icmp", Interface: "eth1", Healthy: true, Priority: 1},
				{ID: 2, ListenPort: 51821, Server: "198.51.100.7", Port: 6000, Transport: "udp", ReturnIP: "1.1.1.1", Priority: 2, Misses: 3},
			},
		},
		Drops: []api.Drop{
			{Reason: 6, Name: "WG_LENGTH", Count: 7},
			{Reason: 15, Name: "NO_PATH", Count: 30},
			{Reason: 16, Name: "DUPLICATE", Count: 0},
		},
	}
}

// fakeDaemon serves canned responses in the shape of the mup control API.
func fakeDaemon(t *testing.T, status api.Status) *api.DaemonClient {
	t.Helper()
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, code int, value any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(value)
	}
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) { reply(w, http.StatusOK, status) })
	mux.HandleFunc("GET /v1/paths", func(w http.ResponseWriter, _ *http.Request) { reply(w, http.StatusOK, status.Client.Paths) })
	mux.HandleFunc("POST /v1/paths", func(w http.ResponseWriter, r *http.Request) {
		var request api.AddPathRequest
		_ = json.NewDecoder(r.Body).Decode(&request)
		if request.ListenPort == 0 {
			reply(w, http.StatusBadRequest, api.Error{Error: "the client has 2 groups, so choose one with its listen port"})
			return
		}
		reply(w, http.StatusCreated, api.Path{ID: 3, ListenPort: request.ListenPort, Server: "203.0.113.8", Port: 5000, Transport: "icmp"})
	})
	mux.HandleFunc("PUT /v1/mode", func(w http.ResponseWriter, r *http.Request) {
		var request api.ModeRequest
		_ = json.NewDecoder(r.Body).Decode(&request)
		if request.ListenPort != 51821 {
			reply(w, http.StatusNotFound, api.Error{Error: "no group has that listen port"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("DELETE /v1/paths/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") != "2" {
			reply(w, http.StatusNotFound, api.Error{Error: "path " + r.PathValue("id") + " does not exist"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/clients", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, http.StatusOK, []api.RegisteredClient{{
			AdvertisedIP: "192.0.2.10",
			Nonce:        "8f3a0000000000aa",
			LeaseSeconds: 24,
			Peers:        14,
			Paths:        []api.RegisteredPath{{ID: 0, Transport: "udp", Local: "203.0.113.5"}},
		}})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return api.NewHTTPDaemonClient(server.URL, server.Client())
}

func testEnvironment() environment {
	return environment{
		getenv: func(string) string { return "" },
		exists: func(string) bool { return false },
		now:    func() time.Time { return testNow },
	}
}

func runCommand(t *testing.T, daemon *api.DaemonClient, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, &stdout, &stderr, testEnvironment(), daemon)
	return code, stdout.String(), stderr.String()
}

func TestStatusShowsTheClientOverview(t *testing.T) {
	t.Parallel()

	code, stdout, stderr := runCommand(t, fakeDaemon(t, clientStatus()), "status")
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{
		"Role:            client",
		"Uptime:          3h12m",
		"Paths:           2/3 healthy, generation 7",
		"Drops:           37 (NO_PATH 30, WG_LENGTH 7)",
		"GROUP   MODE       PATHS         PEERS",
		"51820   fallback   2/2 healthy   12",
		"51821   burst      0/1 healthy   2",
		"ID   GROUP   SERVER              TRANSPORT   VIA       INTERFACE   STATUS      IN USE   LAST ACK   RTT",
		"0    51820   203.0.113.5:5000    udp         -         eth0        healthy     yes      4s         12.3ms",
		"2    51821   198.51.100.7:6000   udp         1.1.1.1   -           unhealthy   no       never      -",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("status output misses %q:\n%s", want, stdout)
		}
	}
}

func TestStatusShowsTheServerClients(t *testing.T) {
	t.Parallel()

	status := api.Status{
		Role:      api.RoleServer,
		StartedAt: testNow.Add(-26 * time.Hour),
		Server:    &api.ServerStatus{Port: 5000, Target: "198.51.100.7:51820", Clients: 1, Paths: 1, Peers: 14, PortsFree: 40986},
	}
	code, stdout, stderr := runCommand(t, fakeDaemon(t, status), "status")
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{"Role:           server", "Uptime:         1d2h", "Target ports:   40986 free, 0 quarantined", "192.0.2.10   8f3a0000   1       14      -           24s"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("status output misses %q:\n%s", want, stdout)
		}
	}
}

func TestGetDropsHidesZeroCounters(t *testing.T) {
	t.Parallel()

	daemon := fakeDaemon(t, clientStatus())
	_, stdout, _ := runCommand(t, daemon, "get", "drops")
	if strings.Contains(stdout, "DUPLICATE") || !strings.Contains(stdout, "NO_PATH") {
		t.Fatalf("drops output:\n%s", stdout)
	}
	_, stdout, _ = runCommand(t, daemon, "get", "drops", "-o", "wide")
	if !strings.Contains(stdout, "DUPLICATE") {
		t.Fatalf("wide drops output misses zero counters:\n%s", stdout)
	}
}

func TestPathCommands(t *testing.T) {
	t.Parallel()

	daemon := fakeDaemon(t, clientStatus())
	if code, stdout, _ := runCommand(t, daemon, "add", "path", "203.0.113.8:5000/icmp", "--group", "51821"); code != 0 || !strings.Contains(stdout, "path/3 created in group 51821") {
		t.Fatalf("add path = %d, %q", code, stdout)
	}
	if code, _, stderr := runCommand(t, daemon, "add", "path", "203.0.113.8:5000/icmp"); code != 1 || !strings.Contains(stderr, "choose one with its listen port") {
		t.Fatalf("add path without a group = %d, %q", code, stderr)
	}
	if code, stdout, _ := runCommand(t, daemon, "delete", "path", "2"); code != 0 || stdout != "path/2 deleted\n" {
		t.Fatalf("delete path = %d, %q", code, stdout)
	}
	if code, _, stderr := runCommand(t, daemon, "rm", "path", "5"); code != 1 || !strings.Contains(stderr, "path 5 does not exist") {
		t.Fatalf("rm path 5 = %d, %q", code, stderr)
	}
}

func TestGroupCommands(t *testing.T) {
	t.Parallel()

	daemon := fakeDaemon(t, clientStatus())
	code, stdout, stderr := runCommand(t, daemon, "get", "groups")
	if code != 0 || !strings.Contains(stdout, "51821   burst      0/1 healthy") {
		t.Fatalf("get groups = %d, %q, %q", code, stdout, stderr)
	}
	if code, stdout, stderr := runCommand(t, daemon, "set", "mode", "burst", "--group=51821"); code != 0 || stdout != "mode set to burst\n" {
		t.Fatalf("set mode = %d, %q, %q", code, stdout, stderr)
	}
	if code, _, stderr := runCommand(t, daemon, "set", "mode", "burst"); code != 1 || !strings.Contains(stderr, "listen port") {
		t.Fatalf("set mode without a group = %d, %q", code, stderr)
	}
	server := fakeDaemon(t, api.Status{Role: api.RoleServer, Server: &api.ServerStatus{Port: 5000}})
	if code, _, stderr := runCommand(t, server, "get", "groups"); code != 1 || !strings.Contains(stderr, "only a client has groups") {
		t.Fatalf("get groups on a server = %d, %q", code, stderr)
	}
}

func TestJSONOutputDecodes(t *testing.T) {
	t.Parallel()

	_, stdout, _ := runCommand(t, fakeDaemon(t, clientStatus()), "-o", "json", "get", "paths")
	var paths []api.Path
	if err := json.Unmarshal([]byte(stdout), &paths); err != nil || len(paths) != 3 {
		t.Fatalf("JSON paths = %v, %v:\n%s", paths, err, stdout)
	}
}

func TestParseOptionsAcceptsFlagsAnywhere(t *testing.T) {
	t.Parallel()

	opts, err := parseOptions([]string{"get", "--socket=/tmp/m.sock", "paths", "-owide", "-w"})
	if err != nil {
		t.Fatalf("parseOptions: %v", err)
	}
	if opts.socket != "/tmp/m.sock" || opts.output != "wide" || !opts.watch || strings.Join(opts.args, " ") != "get paths" {
		t.Fatalf("options = %#v", opts)
	}
	for _, args := range [][]string{{"--output"}, {"-o", "yaml", "status"}, {"--color", "status"}, {"--group", "x"}, {"--group", "0"}, {"--group", "70000"}} {
		if _, err := parseOptions(args); err == nil {
			t.Fatalf("parseOptions(%q) unexpectedly succeeded", args)
		}
	}
}

func TestParseCommandRejectsInvalidCommands(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"get"},
		{"get", "pods"},
		{"add", "peer", "x"},
		{"delete", "path", "one"},
		{"set", "port", "5000"},
		{"restart"},
	} {
		if _, err := parseCommand(options{args: args}); err == nil {
			t.Fatalf("parseCommand(%q) unexpectedly succeeded", args)
		}
	}
	if _, err := parseCommand(options{args: []string{"add", "path", "x"}, watch: true}); err == nil {
		t.Fatal("--watch with add unexpectedly succeeded")
	}
	if _, err := parseCommand(options{args: []string{"status"}, group: 51820}); err == nil {
		t.Fatal("--group with status unexpectedly succeeded")
	}
}

func TestResolveSocket(t *testing.T) {
	t.Parallel()

	env := testEnvironment()
	if socket, err := resolveSocket("/x.sock", env); err != nil || socket != "/x.sock" {
		t.Fatalf("flag socket = %q, %v", socket, err)
	}
	env.getenv = func(string) string { return "/env.sock" }
	if socket, _ := resolveSocket("", env); socket != "/env.sock" {
		t.Fatalf("environment socket = %q", socket)
	}
	env.getenv = func(string) string { return "" }
	env.exists = func(path string) bool { return path == api.DefaultServerSocket }
	if socket, _ := resolveSocket("", env); socket != api.DefaultServerSocket {
		t.Fatalf("detected socket = %q", socket)
	}
	env.exists = func(string) bool { return true }
	if _, err := resolveSocket("", env); err == nil {
		t.Fatal("two sockets unexpectedly resolved")
	}
	env.exists = func(string) bool { return false }
	if _, err := resolveSocket("", env); err == nil {
		t.Fatal("a missing socket unexpectedly resolved")
	}
}

func TestHumanDuration(t *testing.T) {
	t.Parallel()

	tests := map[time.Duration]string{
		-time.Second:                   "0s",
		45 * time.Second:               "45s",
		3*time.Minute + 20*time.Second: "3m20s",
		10 * time.Minute:               "10m",
		5*time.Hour + 12*time.Minute:   "5h12m",
		50 * time.Hour:                 "2d2h",
	}
	for duration, want := range tests {
		if got := humanDuration(duration); got != want {
			t.Fatalf("humanDuration(%v) = %q, want %q", duration, got, want)
		}
	}
}
