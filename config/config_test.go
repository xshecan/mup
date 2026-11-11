package config

import (
	"net/netip"
	"testing"

	"github.com/xshecan/mup/protocol"
)

func TestParsePathRoundTrip(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"198.51.100.1:5000/udp", "198.51.100.2%eth1:5000/icmp"} {
		path, err := ParsePath(raw)
		if err != nil {
			t.Fatalf("ParsePath(%q): %v", raw, err)
		}
		if got := path.String(); got != raw {
			t.Fatalf("ParsePath(%q).String() = %q", raw, got)
		}
	}
	path, _ := ParsePath("198.51.100.2%eth1:5000/icmp")
	want := Path{Server: netip.MustParseAddr("198.51.100.2"), ServerPort: 5000, Transport: protocol.TransportICMP, Interface: "eth1"}
	if path != want {
		t.Fatalf("path = %#v, want %#v", path, want)
	}
}

func TestParsePathRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"", "198.51.100.1:5000", "198.51.100.1:5000/tcp", "198.51.100.1:0/udp",
		"0.0.0.0:5000/udp", "2001:db8::1:5000/udp", "198.51.100.1%:5000/udp", "host:5000/udp",
	} {
		if _, err := ParsePath(raw); err == nil {
			t.Fatalf("ParsePath(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestParseMode(t *testing.T) {
	t.Parallel()

	for _, mode := range []Mode{ModeFallback, ModeBalancer, ModeBurst} {
		parsed, err := ParseMode(mode.String())
		if err != nil || parsed != mode {
			t.Fatalf("ParseMode(%q) = %v, %v", mode, parsed, err)
		}
	}
	if _, err := ParseMode("sideways"); err == nil {
		t.Fatal("ParseMode(sideways) unexpectedly succeeded")
	}
}

func testClient(t *testing.T, groups ...Group) Client {
	t.Helper()
	return Client{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), Groups: groups}
}

func testPaths(t *testing.T, raw ...string) []Path {
	t.Helper()
	paths := make([]Path, 0, len(raw))
	for _, value := range raw {
		path, err := ParsePath(value)
		if err != nil {
			t.Fatalf("ParsePath(%q): %v", value, err)
		}
		paths = append(paths, path)
	}
	return paths
}

func TestClientValidateAcceptsGroupsOfDifferentServers(t *testing.T) {
	t.Parallel()

	client := testClient(t,
		// One server can have a UDP path and an ICMP path in one group, and the
		// servers of a group can use different ports.
		Group{ListenPort: 51820, Paths: testPaths(t, "198.51.100.1:5000/udp", "198.51.100.1:5000/icmp", "198.51.100.2:5001/udp")},
		// One address with another port is another server behind port forwarding.
		Group{ListenPort: 51821, Paths: testPaths(t, "198.51.100.1:6000/udp", "203.0.113.1:6000/icmp")},
	)
	if err := client.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestClientValidateRejectsInvalidGroups(t *testing.T) {
	t.Parallel()

	one := testPaths(t, "198.51.100.1:5000/udp")
	nine := testPaths(t, "198.51.100.1:5000/udp", "198.51.100.2:5000/udp", "198.51.100.3:5000/udp",
		"198.51.100.4:5000/udp", "198.51.100.5:5000/udp")
	more := testPaths(t, "203.0.113.1:5000/udp", "203.0.113.2:5000/udp", "203.0.113.3:5000/udp", "203.0.113.4:5000/udp")
	tests := map[string]Client{
		"no advertised IP": {Groups: []Group{{ListenPort: 51820, Paths: one}}},
		"no groups":        testClient(t),
		"zero listen port": testClient(t, Group{Paths: one}),
		"bad return IP":    testClient(t, Group{ListenPort: 51820, Paths: []Path{{Server: netip.MustParseAddr("198.51.100.1"), ServerPort: 5000, ReturnIP: netip.MustParseAddr("0.0.0.0")}}}),
		"same route twice": testClient(t, Group{ListenPort: 51820, Paths: append(testPaths(t, "198.51.100.1:5000/udp via 192.0.2.77"), one...)}),
		"bad mode":         testClient(t, Group{ListenPort: 51820, Mode: ModeBurst + 1, Paths: one}),
		"no paths":         testClient(t, Group{ListenPort: 51820}),
		"duplicate group port": testClient(t,
			Group{ListenPort: 51820, Paths: one},
			Group{ListenPort: 51820, Paths: more[:1]}),
		"duplicate path": testClient(t, Group{ListenPort: 51820, Paths: append(testPaths(t, "198.51.100.1:5000/udp"), one...)}),
		"server in two groups": testClient(t,
			Group{ListenPort: 51820, Paths: testPaths(t, "198.51.100.1:5000/udp")},
			Group{ListenPort: 51821, Paths: testPaths(t, "198.51.100.1:5000/icmp")}),
		"nine paths in all": testClient(t,
			Group{ListenPort: 51820, Paths: nine},
			Group{ListenPort: 51821, Paths: more}),
	}
	for name, client := range tests {
		t.Run(name, func(t *testing.T) {
			if err := client.Validate(); err == nil {
				t.Fatal("Validate unexpectedly succeeded")
			}
		})
	}
}
