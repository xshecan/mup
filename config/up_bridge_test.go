package config

import (
	"net/netip"
	"testing"
)

func mustParsePath(t *testing.T, raw string) Path {
	t.Helper()
	path, err := ParsePath(raw)
	if err != nil {
		t.Fatalf("ParsePath(%q): %v", raw, err)
	}
	return path
}

func TestParsePathBridgeReflectPool(t *testing.T) {
	t.Parallel()
	path := mustParsePath(t, "160.119.74.33:9000/icmp via 5.6.7.0/28 balance per-packet bridge 203.0.113.9")
	if path.Server != netip.MustParseAddr("160.119.74.33") {
		t.Fatalf("server = %s", path.Server)
	}
	if !path.IsPool() || path.ReturnIP != netip.MustParseAddr("5.6.7.0") || path.ReturnPrefix != 28 {
		t.Fatalf("pool = %s/%d", path.ReturnIP, path.ReturnPrefix)
	}
	if path.Balance != BalancePerPacket {
		t.Fatalf("balance = %v", path.Balance)
	}
	if path.ProxyBridge != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("proxy bridge = %s", path.ProxyBridge)
	}
	if !path.BridgeReflect() {
		t.Fatal("BridgeReflect = false")
	}
	if got := path.String(); got != "160.119.74.33:9000/icmp via 5.6.7.0/28 balance per-packet bridge 203.0.113.9" {
		t.Fatalf("String = %q", got)
	}
}

func TestParsePathBridgeReflectSingleVia(t *testing.T) {
	t.Parallel()
	path := mustParsePath(t, "160.119.74.33:9000/icmp via 198.51.100.7 bridge 203.0.113.9")
	if path.IsPool() || path.ReturnIP != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("return = %s pool = %v", path.ReturnIP, path.IsPool())
	}
	if path.ProxyBridge != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("proxy bridge = %s", path.ProxyBridge)
	}
}

func TestParsePathBridgeRejectsBadAddress(t *testing.T) {
	t.Parallel()
	if _, err := ParsePath("160.119.74.33:9000/icmp via 5.6.7.8/28 bridge nope"); err == nil {
		t.Fatal("ParsePath accepted a bad bridge address")
	}
}

func TestParsePathPlainRouteHasNoProxyBridge(t *testing.T) {
	t.Parallel()
	path := mustParsePath(t, "160.119.74.33:9000/icmp via 5.6.7.8/28 balance per-packet")
	if path.ProxyBridge.IsValid() || path.BridgeReflect() {
		t.Fatalf("plain route has a proxy bridge: %s", path.ProxyBridge)
	}
}

func TestBridgeReflectNeedsSplit(t *testing.T) {
	t.Parallel()
	group := Group{
		ListenPort: 51820,
		Paths:      []Path{mustParsePath(t, "160.119.74.33:9000/icmp via 5.6.7.8/28 bridge 203.0.113.9")},
	}
	if err := group.validate(); err == nil {
		t.Fatal("a bridge reflect without egress paths was accepted")
	}
}

func TestBridgeReflectNeedsVia(t *testing.T) {
	t.Parallel()
	// A bridge suffix with no via is an emit with nothing to reflect.
	group := Group{
		ListenPort:  51820,
		Paths:       []Path{mustParsePath(t, "160.119.74.33:9000/icmp bridge 203.0.113.9")},
		EgressPaths: []Path{mustParsePath(t, "160.119.74.33:9200/icmp")},
	}
	if err := group.validate(); err == nil {
		t.Fatal("a bridge reflect without a via was accepted")
	}
}

func TestBridgeReflectInSplitGroup(t *testing.T) {
	t.Parallel()
	group := Group{
		ListenPort:  51820,
		Paths:       []Path{mustParsePath(t, "160.119.74.33:9000/icmp via 5.6.7.8/28 bridge 203.0.113.9")},
		EgressPaths: []Path{mustParsePath(t, "160.119.74.33:9200/icmp")},
	}
	if err := group.validate(); err != nil {
		t.Fatalf("split group with a bridge reflect: %v", err)
	}
}

func TestBridgeReflectRejectedOnEgressPath(t *testing.T) {
	t.Parallel()
	path := mustParsePath(t, "160.119.74.33:9200/icmp via 5.6.7.8/28 bridge 203.0.113.9")
	if err := path.ValidateEgress(); err == nil {
		t.Fatal("an egress route with a bridge reflect was accepted")
	}
}
