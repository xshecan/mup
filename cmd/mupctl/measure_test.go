package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
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

func TestModeTextShowsTheSettings(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		mode, prefer string
		loss         float64
		want         string
	}{
		{"failover", "latency", 5, "failover (latency, tolerance 5%)"},
		{"failover", "latency", 0, "failover (latency)"},
		{"balancer", "", 2.5, "balancer (tolerance 2.5%)"},
		{"failover", "order", 0, "failover"},
		{"repeater", "", 0, "repeater"},
		{"", "", 0, ""},
	} {
		if got := modeText(test.mode, test.prefer, test.loss); got != test.want {
			t.Errorf("modeText(%q, %q, %v) = %q, want %q", test.mode, test.prefer, test.loss, got, test.want)
		}
	}
}

func TestGroupsShowTheSettingsNextToTheMode(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	printGroups(&out, []api.Group{
		{ListenPort: 51820, Mode: "failover", Prefer: "latency", TolerancePercent: 5, EgressMode: "balancer", EgressTolerancePercent: 2.5, Paths: 2, HealthyPaths: 2, EgressPaths: 1, HealthyEgressPaths: 1},
		{ListenPort: 51821, Mode: "repeater", Paths: 1, HealthyPaths: 1},
	})
	for _, want := range []string{"failover (latency, tolerance 5%)", "balancer (tolerance 2.5%)", "51821   repeater "} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("groups output misses %q:\n%s", want, out.String())
		}
	}
	t.Log("\n" + out.String())

	var plain strings.Builder
	printGroups(&plain, []api.Group{{ListenPort: 51820, Mode: "failover", Paths: 1, HealthyPaths: 1}})
	if strings.Contains(plain.String(), "(") {
		t.Fatalf("plain groups output has settings:\n%s", plain.String())
	}
}

func TestDegradedPathsShowTheirState(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	printPaths(&out, []api.Path{
		{ID: 0, ListenPort: 51820, Server: "203.0.113.5", Port: 9000, Transport: "udp", Healthy: true, InUse: true},
		{ID: 1, ListenPort: 51820, Server: "203.0.113.6", Port: 9000, Transport: "udp", Healthy: true, Degraded: true, Reason: "loss 12.5% above 5%"},
		{ID: 2, ListenPort: 51820, Server: "203.0.113.7", Port: 9000, Transport: "udp", Degraded: true},
		{ID: 3, ListenPort: 51820, Server: "203.0.113.8", Port: 9000, Transport: "udp", Healthy: true},
	}, false, testNow)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	for i, want := range []string{"active", "degraded", "unhealthy", "standby"} {
		if got := strings.Fields(lines[i+1])[6]; got != want {
			t.Fatalf("row %d state = %q, want %q:\n%s", i, got, want, out.String())
		}
	}
	t.Log("\n" + out.String())
}

func TestEgressSummaryAndListShowTheSettings(t *testing.T) {
	t.Parallel()

	clients := []api.RegisteredClient{{AdvertisedIP: "192.0.2.10", Nonce: "8f3a0000000000aa",
		Egress: &api.EgressGroup{Mode: "failover", Prefer: "latency", TolerancePercent: 5, Paths: []api.EgressPath{
			{ID: 0, Server: "203.0.113.5", Port: 9200, Transport: "udp", Healthy: true, Active: true,
				Measurement: api.Measurement{LossPercent: percent(0.3), RTTAvgSeconds: 0.0152}},
			{ID: 1, Server: "203.0.113.5", Port: 9300, Transport: "udp", Healthy: true, Degraded: true, Reason: "loss 12.5% above 5%",
				Measurement: api.Measurement{LossPercent: percent(12.5), RTTAvgSeconds: 0.02}},
			{ID: 2, Server: "203.0.113.5", Port: 9400, Transport: "udp", Healthy: true},
		}}}}
	var out strings.Builder
	printClients(&out, clients, true)
	for _, want := range []string{
		"3/3 healthy, failover (latency, tolerance 5%)",
		"*0:udp:203.0.113.5:9200 loss 0.3% rtt 15.2ms",
		"1:udp:203.0.113.5:9300 degraded loss 12.5% rtt 20ms",
		"2:udp:203.0.113.5:9400",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("clients output misses %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "*1:") || strings.Contains(out.String(), "*2:") || strings.Contains(out.String(), "2:udp:203.0.113.5:9400 degraded") {
		t.Fatalf("a path that is not active has a star:\n%s", out.String())
	}
	t.Log("\n" + out.String())

	var plain strings.Builder
	printClients(&plain, []api.RegisteredClient{{AdvertisedIP: "192.0.2.10", Nonce: "8f3a",
		Egress: &api.EgressGroup{Mode: "failover", Paths: []api.EgressPath{{ID: 0, Server: "203.0.113.5", Port: 9200, Transport: "udp", Healthy: true}}}}}, true)
	if strings.Contains(plain.String(), "*") || strings.Contains(plain.String(), "degraded") || strings.Contains(plain.String(), "(") && strings.Contains(plain.String(), "failover (") {
		t.Fatalf("plain clients output has a mark:\n%s", plain.String())
	}
}

func TestMembersShowDegraded(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	printMembers(&out, []api.Member{
		{Direction: "ingress", PathID: 4, ListenPort: 51820, Address: "198.51.100.1", Healthy: true, Degraded: true,
			Measurement: api.Measurement{ProbeLossPercent: percent(12.5)}},
		{Direction: "ingress", PathID: 4, ListenPort: 51820, Address: "198.51.100.2", Degraded: true},
		{Direction: "ingress", PathID: 4, ListenPort: 51820, Address: "198.51.100.3", Healthy: true},
	})
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	for i, want := range []string{"degraded", "unhealthy", "healthy"} {
		if got := strings.Fields(lines[i+1])[4]; got != want {
			t.Fatalf("member %d state = %q, want %q:\n%s", i, got, want, out.String())
		}
	}
	t.Log("\n" + out.String())
}

func TestWidePathsShowTheBandwidthLimit(t *testing.T) {
	t.Parallel()

	paths := []api.Path{
		{ID: 0, ListenPort: 51820, Server: "203.0.113.5", Port: 9000, Transport: "udp",
			BandwidthBitsPerSecond: 10e6, Measurement: api.Measurement{RateBitsPerSecond: 8.5e6}},
		{ID: 1, ListenPort: 51820, Server: "203.0.113.6", Port: 9000, Transport: "udp",
			BandwidthBitsPerSecond: 500e3, BandwidthPerMember: true},
		{ID: 2, ListenPort: 51820, Server: "203.0.113.7", Port: 9000, Transport: "udp"},
	}
	var out strings.Builder
	printPaths(&out, paths, true, testNow)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	header := strings.Fields(lines[0])
	bw := slices.Index(header, "BW")
	if bw < 0 || header[bw+1] != "RATE" {
		t.Fatalf("header = %q, want BW directly before RATE", lines[0])
	}
	for i, want := range [][]string{{"10.0Mbit", "8.5Mbit"}, {"500kbit/member", "-"}, {"-", "-"}} {
		cells := strings.Fields(lines[i+1])
		// SRC, PORTS, PRIORITY and MISSES follow RATE.
		got := cells[len(cells)-6 : len(cells)-4]
		if got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("row %d = %q, want BW %q and RATE %q", i, lines[i+1], want[0], want[1])
		}
	}
	// Without a limit the plain output is unchanged.
	out.Reset()
	printPaths(&out, paths, false, testNow)
	if strings.Contains(out.String(), "BW") {
		t.Fatalf("plain output shows BW:\n%s", out.String())
	}
}

func TestEgressListShowsTheBandwidthLimit(t *testing.T) {
	t.Parallel()

	groups := []api.EgressGroup{{Mode: "failover", Paths: []api.EgressPath{
		{ID: 0, Server: "203.0.113.5", Port: 9200, Transport: "icmp", ReturnIP: "198.51.100.0/28", Members: 14, HealthyMembers: 13,
			BandwidthBitsPerSecond: 10e6, BandwidthPerMember: true, Degraded: true, Active: true, SrcFirst: 40000, SrcLast: 40100,
			Measurement: api.Measurement{LossPercent: percent(0.3), RTTAvgSeconds: 0.0152}},
		{ID: 1, Server: "203.0.113.5", Port: 9300, Transport: "udp", BandwidthBitsPerSecond: 2e9},
		{ID: 2, Server: "203.0.113.5", Port: 9400, Transport: "udp"},
	}}}
	want := "*0:icmp:203.0.113.5:9200 via 198.51.100.0/28 (13/14) bw 10.0Mbit/member degraded loss 0.3% rtt 15.2ms src 40000-40100," +
		"1:udp:203.0.113.5:9300 bw 2.0Gbit,2:udp:203.0.113.5:9400"
	if got := egressList(groups); got != want {
		t.Fatalf("egressList = %q, want %q", got, want)
	}
}
