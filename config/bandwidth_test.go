package config

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseRateReadsEveryUnit(t *testing.T) {
	t.Parallel()

	for raw, want := range map[string]uint64{
		"10mbit":       10_000_000,
		"500kbit":      500_000,
		"1.5gbit":      1_500_000_000,
		"8kbit":        8_000,
		"100gbit":      100_000_000_000,
		"10Mbit":       10_000_000,
		"10MBIT":       10_000_000,
		"10mbps":       10_000_000,
		"64kbps":       64_000,
		"2Gbps":        2_000_000_000,
		"0.5mbit":      500_000,
		".5mbit":       500_000,
		"1.234mbit":    1_234_000,
		"1.000001gbit": 1_000_001_000,
		"007mbit":      7_000_000,
	} {
		got, err := ParseRate(raw)
		if err != nil || got != want {
			t.Fatalf("ParseRate(%q) = %d, %v, want %d", raw, got, err, want)
		}
	}
}

func TestParseRateRefusesABadRate(t *testing.T) {
	t.Parallel()

	for raw, want := range map[string]string{
		"10":          "use a positive number and a unit",
		"mbit":        "use a positive number and a unit",
		"10 mbit":     "use a positive number and a unit",
		"10mb":        "use a positive number and a unit",
		"10bit":       "use a positive number and a unit",
		"-1mbit":      "use a positive number and a unit",
		"+1mbit":      "use a positive number and a unit",
		"0mbit":       "use a positive number and a unit",
		"1e3kbit":     "use a positive number and a unit",
		"1..5mbit":    "use a positive number and a unit",
		"0x10mbit":    "use a positive number and a unit",
		"7kbit":       "from 8kbit to 100gbit",
		"101gbit":     "from 8kbit to 100gbit",
		"100.001gbit": "from 8kbit to 100gbit",
		"8.5kbit":     "a whole number of kbit",
		"1.0005mbit":  "a whole number of kbit",
	} {
		_, err := ParseRate(raw)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("ParseRate(%q) error = %v, want %q", raw, err, want)
		}
	}
}

func TestFormatRatePicksOneUnit(t *testing.T) {
	t.Parallel()

	for rate, want := range map[uint64]string{
		8_000:           "8kbit",
		500_000:         "500kbit",
		999_000:         "999kbit",
		1_000_000:       "1mbit",
		1_234_000:       "1.234mbit",
		10_000_000:      "10mbit",
		1_500_000_000:   "1.5gbit",
		1_000_001_000:   "1.000001gbit",
		100_000_000_000: "100gbit",
	} {
		if got := FormatRate(rate); got != want {
			t.Fatalf("FormatRate(%d) = %q, want %q", rate, got, want)
		}
		if again, err := ParseRate(want); err != nil || again != rate {
			t.Fatalf("ParseRate(%q) = %d, %v, want %d", want, again, err, rate)
		}
	}
}

func TestParsePathReadsABandwidthInEveryPosition(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		raw       string
		rate      uint64
		perMember bool
		print     string
	}{
		{raw: "203.0.113.5:9000/udp bw 10mbit", rate: 10_000_000, print: "203.0.113.5:9000/udp bw 10mbit"},
		{raw: "203.0.113.5:9000/icmp bw 10Mbps", rate: 10_000_000, print: "203.0.113.5:9000/icmp bw 10mbit"},
		{raw: "203.0.113.5%eth1:9000-9099/udp bw 1500kbit", rate: 1_500_000, print: "203.0.113.5%eth1:9000-9099/udp bw 1.5mbit"},
		{raw: "203.0.113.5:9000/udp via 198.51.100.9 bw 500kbit", rate: 500_000, print: "203.0.113.5:9000/udp via 198.51.100.9 bw 500kbit"},
		{raw: "203.0.113.5:9000/udp via 198.51.100.9 bw 500kbit per-member", rate: 500_000, perMember: true, print: "203.0.113.5:9000/udp via 198.51.100.9 bw 500kbit per-member"},
		{raw: "203.0.113.5:9001/icmp via 198.51.100.0/28 per-packet bw 10mbit per-member", rate: 10_000_000, perMember: true, print: "203.0.113.5:9001/icmp via 198.51.100.0/28 per-packet bw 10mbit per-member"},
		{raw: "203.0.113.5:9001/icmp via 198.51.100.0/28 bw 1gbit", rate: 1_000_000_000, print: "203.0.113.5:9001/icmp via 198.51.100.0/28 per-peer bw 1gbit"},
		{raw: "203.0.113.5:9000/udp src 5000-50000 bw 2gbps", rate: 2_000_000_000, print: "203.0.113.5:9000/udp src 5000-50000 bw 2gbit"},
		{raw: "203.0.113.5:9002/udp via 198.51.100.9 src 5000-50000 bw 500kbit bridge 192.0.2.7", rate: 500_000, print: "203.0.113.5:9002/udp via 198.51.100.9 src 5000-50000 bw 500kbit bridge 192.0.2.7"},
		{raw: "203.0.113.5:9002/udp via 198.51.100.0/28 per-peer src 5000 bw 8kbit per-member bridge 192.0.2.7", rate: 8_000, perMember: true, print: "203.0.113.5:9002/udp via 198.51.100.0/28 per-peer src 5000 bw 8kbit per-member bridge 192.0.2.7"},
	} {
		path := mustParsePath(t, test.raw)
		if path.BandwidthBitsPerSecond != test.rate || path.BandwidthPerMember != test.perMember || !path.HasBandwidth() {
			t.Fatalf("%q: bandwidth = %d per-member %v", test.raw, path.BandwidthBitsPerSecond, path.BandwidthPerMember)
		}
		if got := path.String(); got != test.print {
			t.Fatalf("%q: String = %q, want %q", test.raw, got, test.print)
		}
		if again := mustParsePath(t, path.String()); again != path {
			t.Fatalf("%q: reparsed path = %#v, want %#v", test.raw, again, path)
		}
	}
}

func TestParsePathWithoutABandwidthHasNone(t *testing.T) {
	t.Parallel()

	path := mustParsePath(t, "203.0.113.5:9000/udp via 198.51.100.0/28 per-packet src 5000-6000 bridge 192.0.2.7")
	if path.HasBandwidth() || path.BandwidthPerMember {
		t.Fatalf("path = %#v", path)
	}
	if strings.Contains(path.String(), "bw") {
		t.Fatalf("String = %q", path.String())
	}
}

func TestParsePathRefusesABadBandwidth(t *testing.T) {
	t.Parallel()

	for raw, want := range map[string]string{
		"203.0.113.5:9000/udp bw":                                               "bw needs a rate",
		"203.0.113.5:9000/udp bw 10":                                            "use a positive number and a unit",
		"203.0.113.5:9000/udp bw 10 mbit":                                       "bw RATE comes after via and src",
		"203.0.113.5:9000/udp bw 7kbit":                                         "from 8kbit to 100gbit",
		"203.0.113.5:9000/udp bw 10mbit per-member":                             "per-member needs a via",
		"203.0.113.5:9000/udp per-member":                                       "per-member comes right after bw RATE",
		"203.0.113.5:9000/udp via 198.51.100.9 per-member bw 10mbit":            "per-member comes right after bw RATE",
		"203.0.113.5:9000/udp bw 10mbit bw 20mbit":                              "a path takes bw once",
		"203.0.113.5:9000/udp bw 10mbit via 198.51.100.9":                       "bw RATE comes after via and src",
		"203.0.113.5:9000/udp via 198.51.100.9 bw 10mbit src 5000":              "bw RATE comes after via and src",
		"203.0.113.5:9000/udp via 198.51.100.0/28 bw 10mbit per-peer":           "bw RATE comes after via and src",
		"203.0.113.5:9000/udp via 198.51.100.9 bridge 192.0.2.7 bw 1mbit":       "then an optional bridge BRIDGE_IP",
		"203.0.113.5:9000/udp via 198.51.100.9 bw 10mbit per-member per-member": "per-member comes right after bw RATE",
	} {
		_, err := ParsePath(raw)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("ParsePath(%q) error = %v, want %q", raw, err, want)
		}
	}
}

func TestPathValidateChecksTheBandwidth(t *testing.T) {
	t.Parallel()

	base := mustParsePath(t, "203.0.113.5:9000/udp via 198.51.100.9")
	for name, tt := range map[string]struct {
		alter func(*Path)
		want  string
	}{
		"too low":          {func(p *Path) { p.BandwidthBitsPerSecond = 7_999 }, "outside the rates"},
		"too high":         {func(p *Path) { p.BandwidthBitsPerSecond = MaxRate + 1 }, "outside the rates"},
		"per-member alone": {func(p *Path) { p.BandwidthPerMember = true }, "per-member needs bw RATE"},
		"per-member no via": {func(p *Path) {
			p.BandwidthBitsPerSecond, p.BandwidthPerMember, p.ReturnIP = MinRate, true, netip.Addr{}
		}, "needs a via"},
	} {
		path := base
		tt.alter(&path)
		if err := path.validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Fatalf("%s: validate error = %v, want %q", name, err, tt.want)
		}
	}
}

func TestLoadReadsTheBandwidthOfEveryEntry(t *testing.T) {
	t.Parallel()

	groups := loadClientGroups(t, `
    - port: 51820
      mode: balancer
      routes:
        - 203.0.113.5:9000/udp bw 10mbit
        - 203.0.113.5:9001/icmp via 198.51.100.0/28 per-packet bw 10mbit per-member
    - port: 51821
      ingress:
        routes:
          - 203.0.113.6:9000/udp bw 20mbit
          - 203.0.113.6:9001/icmp via 198.51.100.16/28 bw 5mbit per-member
        bridges:
          - 192.0.2.8:9400/udp bw 3mbit
      egress:
        routes:
          - 203.0.113.6:9100/udp bw 30mbit
          - 203.0.113.6:9002/udp via 198.51.100.9 src 5000-50000 bw 500kbit bridge 192.0.2.7
        bridges:
          - 192.0.2.7:9300/icmp via 198.51.100.32/28 bw 20mbit
          - 192.0.2.9:9301/udp via 198.51.100.48/28 bw 1mbit per-member
          - 192.0.2.10:9302/udp bw 40mbit`)
	type want struct {
		rate      uint64
		perMember bool
		print     string
	}
	check := func(where string, path Path, w want) {
		t.Helper()
		if path.BandwidthBitsPerSecond != w.rate || path.BandwidthPerMember != w.perMember {
			t.Fatalf("%s: path = %#v, want rate %d per-member %v", where, path, w.rate, w.perMember)
		}
		if got := path.String(); got != w.print {
			t.Fatalf("%s: String = %q, want %q", where, got, w.print)
		}
	}
	check("plain route 0", groups[0].Paths[0], want{10_000_000, false, "203.0.113.5:9000/udp bw 10mbit"})
	check("plain route 1", groups[0].Paths[1], want{10_000_000, true, "203.0.113.5:9001/icmp via 198.51.100.0/28 per-packet bw 10mbit per-member"})
	split := groups[1]
	check("ingress route 0", split.Paths[0], want{20_000_000, false, "203.0.113.6:9000/udp bw 20mbit"})
	check("ingress route 1", split.Paths[1], want{5_000_000, true, "203.0.113.6:9001/icmp via 198.51.100.16/28 per-peer bw 5mbit per-member"})
	check("ingress bridge", split.Paths[2], want{3_000_000, false, "192.0.2.8:9400/udp bw 3mbit"})
	if !split.Paths[2].Bridge {
		t.Fatalf("ingress bridge = %#v", split.Paths[2])
	}
	check("egress route", split.EgressPaths[0], want{30_000_000, false, "203.0.113.6:9100/udp bw 30mbit"})
	suffix := split.EgressPaths[1]
	check("egress bridge suffix", suffix, want{500_000, false, "203.0.113.6:9002/udp via 198.51.100.9 src 5000-50000 bw 500kbit bridge 192.0.2.7"})
	if !suffix.Bridge || suffix.Server != netip.MustParseAddr("192.0.2.7") || suffix.NamedServer != netip.MustParseAddr("203.0.113.6") {
		t.Fatalf("egress bridge suffix = %#v", suffix)
	}
	check("egress bridge via", split.EgressPaths[2], want{20_000_000, false, "192.0.2.7:9300/icmp via 198.51.100.32/28 per-peer bw 20mbit"})
	check("egress bridge via per member", split.EgressPaths[3], want{1_000_000, true, "192.0.2.9:9301/udp via 198.51.100.48/28 per-peer bw 1mbit per-member"})
	check("egress bridge", split.EgressPaths[4], want{40_000_000, false, "192.0.2.10:9302/udp bw 40mbit"})
	for index, path := range split.EgressPaths[2:] {
		if !path.Bridge || path.BridgeVia != path.ReturnIP.IsValid() {
			t.Fatalf("egress bridge entry %d = %#v", index, path)
		}
	}
	// A normalized egress path prints the text that gives it back.
	for index, path := range split.EgressPaths {
		parsed := mustParsePath(t, path.String())
		again, err := NormalizeEgressPath(parsed, path.Bridge && !path.NamedServer.IsValid())
		if err != nil || again != path {
			t.Fatalf("egress path %d: reparsed = %#v, %v, want %#v", index, again, err, path)
		}
	}
}

func TestLoadRefusesABandwidthPerMemberWithoutAVia(t *testing.T) {
	t.Parallel()

	_, err := Load(writeFile(t, `client:
  advertise: 192.0.2.10
  servers:
    - port: 51820
      ingress:
        routes: [203.0.113.5:9000/udp]
      egress:
        bridges:
          - 192.0.2.7:9300/icmp bw 20mbit per-member
`))
	if err == nil || !strings.Contains(err.Error(), "per-member needs a via") {
		t.Fatalf("Load error = %v", err)
	}
}
