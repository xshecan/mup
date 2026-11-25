package config

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseTolerance(t *testing.T) {
	t.Parallel()

	valid := map[string]Tolerance{
		"5": 50, "5%": 50, " 5 % ": 50, "0.5%": 5, "0.5": 5, "100": 1000, "100%": 1000, "0.1": 1, "12.3": 123,
	}
	for raw, want := range valid {
		got, err := ParseTolerance(raw)
		if err != nil || got != want {
			t.Errorf("ParseTolerance(%q) = %d, %v, want %d", raw, got, err, want)
		}
	}
	rangeError := "use a percent from 0.1 to 100, such as 5 or 5%"
	for _, raw := range []string{"0", "0%", "101", "-1", "abc", "5%%", "", "0.05", "NaN", "Inf"} {
		_, err := ParseTolerance(raw)
		if err == nil || !strings.Contains(err.Error(), rangeError) {
			t.Errorf("ParseTolerance(%q) error = %v", raw, err)
		}
	}
	if _, err := ParseTolerance("0.25"); err == nil || !strings.Contains(err.Error(), "use at most one digit after the point") {
		t.Errorf("ParseTolerance(0.25) error = %v", err)
	}
}

func TestToleranceString(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"5%", "0.5%", "100%", "0.1%", "12.3%"} {
		limit, err := ParseTolerance(raw)
		if err != nil || limit.String() != raw {
			t.Errorf("round trip %q = %q, %v", raw, limit.String(), err)
		}
	}
	if Tolerance(0).String() != "" || Tolerance(0).Percent() != 0 || Tolerance(55).Percent() != 5.5 {
		t.Errorf("zero or percent wrong")
	}
}

func TestParsePrefer(t *testing.T) {
	t.Parallel()

	for raw, want := range map[string]Prefer{"order": PreferOrder, "latency": PreferLatency} {
		got, err := ParsePrefer(raw)
		if err != nil || got != want || got.String() != raw {
			t.Errorf("ParsePrefer(%q) = %v, %v", raw, got, err)
		}
	}
	_, err := ParsePrefer("fast")
	if err == nil || err.Error() != `invalid prefer "fast": use latency or order` {
		t.Errorf("ParsePrefer(fast) error = %v", err)
	}
}

func TestLoadLossAndPreferForms(t *testing.T) {
	t.Parallel()

	for yamlValue, want := range map[string]Tolerance{"5": 50, "5%": 50, "0.5%": 5, "0.5": 5, `"5%"`: 50} {
		app, err := Load(writeFile(t, `
client:
  advertise: 192.0.2.10
  servers:
    - port: 51820
      mode: failover
      tolerance: `+yamlValue+`
      prefer: latency
      routes:
        - 203.0.113.5:9000/udp
`))
		if err != nil {
			t.Fatalf("Load %s: %v", yamlValue, err)
		}
		group := app.Client.Groups[0]
		if group.Tolerance != want || group.Prefer != PreferLatency || group.EgressTolerance != 0 {
			t.Errorf("tolerance %s: group = %#v", yamlValue, group)
		}
	}
}

func TestLoadLossAndPreferSplit(t *testing.T) {
	t.Parallel()

	app, err := Load(writeFile(t, `
client:
  advertise: 192.0.2.10
  servers:
    - port: 51825
      ingress:
        mode: failover
        tolerance: 5%
        prefer: latency
        routes:
          - 203.0.113.5:9000/udp
      egress:
        mode: failover
        tolerance: 0.5
        routes:
          - 203.0.113.5:9200/udp
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	group := app.Client.Groups[0]
	if group.Tolerance != 50 || group.Prefer != PreferLatency || group.EgressTolerance != 5 || group.EgressPrefer != PreferOrder {
		t.Fatalf("group = %#v", group)
	}
}

func TestLoadLossAndPreferRefused(t *testing.T) {
	t.Parallel()

	split := func(ingress, egress string) string {
		return `
client:
  advertise: 192.0.2.10
  servers:
    - port: 51825
      ingress:
        mode: ` + ingress + `
        routes:
          - 203.0.113.5:9000/udp
      egress:
        mode: ` + egress + `
        routes:
          - 203.0.113.5:9200/udp
`
	}
	cases := map[string]struct{ config, want string }{
		"ingress balancer latency": {split("balancer\n        prefer: latency", "failover"), "prefer latency needs the failover mode, not balancer"},
		"egress balancer latency":  {split("failover", "balancer\n        prefer: latency"), "egress prefer latency needs the failover mode, not balancer"},
		"group level tolerance": {`
client:
  advertise: 192.0.2.10
  servers:
    - port: 51825
      tolerance: 5
      ingress:
        routes:
          - 203.0.113.5:9000/udp
      egress:
        routes:
          - 203.0.113.5:9200/udp
`, "use mode, tolerance, prefer and routes, or ingress and egress, not both"},
		"unknown prefer": {split("failover\n        prefer: fast", "failover"), `invalid prefer "fast": use latency or order`},
		"zero tolerance": {split("failover\n        tolerance: 0", "failover"), "invalid tolerance"},
		"plain balancer": {`
client:
  advertise: 192.0.2.10
  servers:
    - port: 51825
      mode: balancer
      prefer: latency
      routes:
        - 203.0.113.5:9000/udp
`, "prefer latency needs the failover mode, not balancer"},
	}
	for name, tc := range cases {
		_, err := Load(writeFile(t, tc.config))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want %q", name, err, tc.want)
		}
	}
}

func TestGroupValidateLossAndPrefer(t *testing.T) {
	t.Parallel()

	base := Group{ListenPort: 51820, Paths: []Path{{Server: netip.MustParseAddr("203.0.113.5"), ServerPort: 9000}}}
	cases := map[string]struct {
		edit func(*Group)
		want string
	}{
		"prefer":        {func(g *Group) { g.Prefer = 2 }, "server 51820: invalid prefer 2"},
		"egress prefer": {func(g *Group) { g.EgressPrefer = 2 }, "server 51820: invalid egress prefer 2"},
		"max loss":      {func(g *Group) { g.Tolerance = 1001 }, "server 51820: invalid tolerance 1001"},
		"egress loss":   {func(g *Group) { g.EgressTolerance = 1001 }, "server 51820: invalid egress tolerance 1001"},
		"no egress":     {func(g *Group) { g.EgressTolerance = 5 }, "server 51820: the egress settings need a group with ingress and egress"},
	}
	for name, tc := range cases {
		group := base
		tc.edit(&group)
		if err := group.validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want %q", name, err, tc.want)
		}
	}
}
