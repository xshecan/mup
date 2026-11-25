package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xshecan/mup/api"
)

func percent(value float64) *float64 { return &value }

func measuredPaths() []api.Path {
	return []api.Path{
		{ID: 0, ListenPort: 51820, Server: "203.0.113.5", Port: 9000, Transport: "udp", Healthy: true, InUse: true, RTTSeconds: 0.0123,
			Measurement: api.Measurement{LossPercent: percent(0.4), LossLongPercent: percent(0.2), ProbeLossPercent: percent(1.5),
				RTTAvgSeconds: 0.0152, RTTJitterSeconds: 0.0008, RateBitsPerSecond: 12.4e6}},
		{ID: 1, ListenPort: 51820, Server: "203.0.113.6", Port: 9000, Transport: "udp", Healthy: true, RTTSeconds: 0.02,
			Measurement: api.Measurement{ProbeLossPercent: percent(12.5)}},
		{ID: 2, ListenPort: 51820, Server: "203.0.113.7", Port: 9000, Transport: "icmp"},
		{ID: 3, ListenPort: 51820, Server: "203.0.113.8", Port: 9000, Transport: "udp", Healthy: true,
			Measurement: api.Measurement{LossLongPercent: percent(0), RateBitsPerSecond: 850e3}},
	}
}

func TestPathsShowTheLossColumn(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	printPaths(&out, measuredPaths(), false, testNow)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if !strings.HasSuffix(lines[0], "RTT      LOSS") {
		t.Fatalf("header = %q", lines[0])
	}
	for i, want := range []string{"12.3ms   0.4%", "20ms     12.5%", "-        -", "-        -"} {
		if !strings.HasSuffix(strings.TrimSpace(lines[i+1]), want) {
			t.Fatalf("row %d = %q, want the suffix %q", i, lines[i+1], want)
		}
	}
}

func TestWidePathsShowTheMeasurement(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	printPaths(&out, measuredPaths(), true, testNow)
	text := out.String()
	for _, column := range []string{"AVG RTT", "JITTER", "DATA LOSS", "PROBE LOSS", "RATE", "SRC", "PORTS", "PRIORITY", "MISSES"} {
		if !strings.Contains(strings.Split(text, "\n")[0], column) {
			t.Fatalf("wide header misses %q:\n%s", column, text)
		}
	}
	for _, cell := range []string{"0.4%/0.2%", "1.5%", "12.4Mbit", "15.2ms", "800µs", "-/0.0%", "850kbit"} {
		if !strings.Contains(text, cell) {
			t.Fatalf("wide output misses %q:\n%s", cell, text)
		}
	}
	// A path without any measurement shows a dash in every new column.
	if row := strings.Fields(strings.Split(text, "\n")[3]); len(row) < 14 || strings.Join(row[9:15], " ") != "- - - - - -" {
		t.Fatalf("empty row = %q", row)
	}
}

func TestFormatRateAtTheUnitBorders(t *testing.T) {
	t.Parallel()

	for rate, want := range map[float64]string{
		0:        "-",
		-1:       "-",
		12:       "12bit",
		999:      "999bit",
		999.6:    "1kbit",
		1000:     "1kbit",
		850e3:    "850kbit",
		999.4e3:  "999kbit",
		999.6e3:  "1.0Mbit",
		1e6:      "1.0Mbit",
		12.4e6:   "12.4Mbit",
		999.94e6: "999.9Mbit",
		999.96e6: "1.0Gbit",
		1.2e9:    "1.2Gbit",
		2500.0e9: "2500.0Gbit",
	} {
		if got := formatRate(rate); got != want {
			t.Errorf("formatRate(%v) = %q, want %q", rate, got, want)
		}
	}
}

func TestDataLossTextHandlesMissingSides(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct {
		measurement api.Measurement
		want        string
	}{
		"both":  {api.Measurement{LossPercent: percent(0.4), LossLongPercent: percent(0.2)}, "0.4%/0.2%"},
		"short": {api.Measurement{LossPercent: percent(0)}, "0.0%/-"},
		"long":  {api.Measurement{LossLongPercent: percent(3.25)}, "-/3.2%"},
		"none":  {api.Measurement{ProbeLossPercent: percent(9)}, "-"},
	} {
		if got := dataLossText(test.measurement); got != test.want {
			t.Errorf("%s: dataLossText = %q, want %q", name, got, test.want)
		}
	}
}

func TestMembersOfAClient(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	printMembers(&out, []api.Member{
		{Direction: "ingress", PathID: 4, ListenPort: 51820, Address: "198.51.100.1", Healthy: true,
			Measurement: api.Measurement{ProbeLossPercent: percent(0), RTTAvgSeconds: 0.0152, RTTJitterSeconds: 0.0008}},
		{Direction: "ingress", PathID: 4, ListenPort: 51820, Address: "198.51.100.2"},
	})
	if strings.Fields(out.String())[0] != "PATH" || strings.Contains(out.String(), "CLIENT") {
		t.Fatalf("client members:\n%s", out.String())
	}
	for _, cell := range []string{"ingress 4", "51820", "198.51.100.1", "healthy", "15.2ms", "800µs", "0.0%", "unhealthy"} {
		if !strings.Contains(out.String(), cell) {
			t.Fatalf("members output misses %q:\n%s", cell, out.String())
		}
	}
}

func TestMembersOfAServer(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	printMembers(&out, []api.Member{
		{Client: "192.0.2.10", Direction: "egress", PathID: 2, ListenPort: 51820, Address: "198.51.100.1", Healthy: true,
			Measurement: api.Measurement{ProbeLossPercent: percent(12.5), RTTAvgSeconds: 0.0152}},
		{Client: "192.0.2.11", Direction: "egress", PathID: 0, Address: "203.0.113.5"},
	})
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || strings.Fields(lines[0])[0] != "CLIENT" {
		t.Fatalf("server members:\n%s", out.String())
	}
	if got := strings.Fields(lines[1]); strings.Join(got, " ") != "192.0.2.10 egress 2 51820 198.51.100.1 healthy 15.2ms - 12.5%" {
		t.Fatalf("row 1 = %q", got)
	}
	if got := strings.Fields(lines[2]); strings.Join(got, " ") != "192.0.2.11 egress 0 - 203.0.113.5 unhealthy - - -" {
		t.Fatalf("row 2 = %q", got)
	}
	var none strings.Builder
	printMembers(&none, nil)
	if none.String() != "No members found.\n" {
		t.Fatalf("empty = %q", none.String())
	}
}

func membersDaemon(t *testing.T, role string) *api.DaemonClient {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(api.Status{Role: role})
	})
	mux.HandleFunc("GET /v1/members", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(api.MemberList{Members: []api.Member{
			{Direction: "ingress", PathID: 1, Address: "198.51.100.1", Healthy: true, Measurement: api.Measurement{ProbeLossPercent: percent(2)}},
		}})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return api.NewHTTPDaemonClient(server.URL, server.Client())
}

func TestGetMembersCommand(t *testing.T) {
	t.Parallel()

	daemon := membersDaemon(t, api.RoleClient)
	for _, args := range [][]string{{"get", "members"}, {"members"}, {"get", "member"}} {
		if code, stdout, stderr := runCommand(t, daemon, args...); code != 0 || !strings.Contains(stdout, "ingress 1") || !strings.Contains(stdout, "2.0%") {
			t.Fatalf("%v = %d, %q, %q", args, code, stdout, stderr)
		}
	}
	code, stdout, stderr := runCommand(t, daemon, "get", "members", "-o", "json")
	var list api.MemberList
	if code != 0 || json.Unmarshal([]byte(stdout), &list) != nil || len(list.Members) != 1 || *list.Members[0].ProbeLossPercent != 2 {
		t.Fatalf("json = %d, %q, %q", code, stdout, stderr)
	}
	if code, _, stderr := runCommand(t, membersDaemon(t, api.RoleBridge), "get", "members"); code == 0 || !strings.Contains(stderr, "only a client or a server has members") {
		t.Fatalf("bridge = %d, %q", code, stderr)
	}
}

func TestWideClientsShowTheLossAndRTTOfEachEgressPath(t *testing.T) {
	t.Parallel()

	client := func(paths ...api.EgressPath) []api.RegisteredClient {
		return []api.RegisteredClient{{AdvertisedIP: "192.0.2.10", Nonce: "8f3a0000000000aa",
			Egress: &api.EgressGroup{Mode: "failover", Paths: paths}}}
	}
	var out strings.Builder
	printClients(&out, client(
		api.EgressPath{ID: 0, Server: "203.0.113.5", Port: 9200, Transport: "icmp", ReturnIP: "198.51.100.0/28", Members: 14, HealthyMembers: 13,
			Measurement: api.Measurement{LossPercent: percent(0.3), ProbeLossPercent: percent(4), RTTAvgSeconds: 0.0152}},
		api.EgressPath{ID: 1, Server: "203.0.113.5", Port: 9300, Transport: "udp",
			Measurement: api.Measurement{ProbeLossPercent: percent(2.5)}},
		api.EgressPath{ID: 2, Server: "203.0.113.5", Port: 9400, Transport: "udp"},
	), true)
	want := "0:icmp:203.0.113.5:9200 via 198.51.100.0/28 (13/14) loss 0.3% rtt 15.2ms,1:udp:203.0.113.5:9300 loss 2.5%,2:udp:203.0.113.5:9400"
	if !strings.Contains(out.String(), want) {
		t.Fatalf("clients output misses %q:\n%s", want, out.String())
	}
}
