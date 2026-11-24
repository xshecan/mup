package dataplane

import (
	"net/netip"
	"testing"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/protocol"
)

func TestEncodeEgressPathEntryOfABridge(t *testing.T) {
	t.Parallel()

	client := ClientKey{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), InstanceNonce: 7}
	entry := EgressPathEntry{
		Client: client, PathID: 1, Server: netip.MustParseAddr("5.6.7.8"), ServerPort: 9200,
		Transport: protocol.TransportICMP, Ifindex: 3, ReturnIP: netip.MustParseAddr("198.51.100.9"),
		Bridge: true, LocalIP: netip.MustParseAddr("203.0.113.5"),
	}
	_, value, err := encodeEgressPathEntry(entry)
	if err != nil {
		t.Fatalf("encodeEgressPathEntry: %v", err)
	}
	if value.Flags != protocol.ControlFlagReturnIP|protocol.ControlFlagBridge || ipv4FromWord(value.LocalIp) != entry.LocalIP ||
		ipv4FromWord(value.ServerIp) != entry.Server {
		t.Fatalf("value = %#v", value)
	}
	entry.LocalIP = netip.Addr{}
	if _, _, err := encodeEgressPathEntry(entry); err == nil {
		t.Fatal("a bridge without a source encoded")
	}
}

func TestBridgeSettingsEncoding(t *testing.T) {
	t.Parallel()

	settings := BridgeSettings{Entries: []BridgeEntry{{
		Server: netip.MustParseAddr("46.102.130.95"),
		Ports:  config.PortRange{First: 9000, Last: 9399},
		Allow:  []netip.Prefix{netip.MustParsePrefix("46.102.130.17/24")},
	}}}
	configurations, err := encodeBridgeConfigs(settings)
	if err != nil {
		t.Fatalf("encodeBridgeConfigs: %v", err)
	}
	if configuration := configurations[0]; ipv4FromWord(configuration.ServerIp) != settings.Entries[0].Server ||
		configuration.PortFirst != 9000 || configuration.PortLast != 9399 {
		t.Fatalf("configuration = %#v", configuration)
	}
	for index := 1; index < MaxBridges; index++ {
		if configurations[index] != (mupBridgeConfigV1{}) {
			t.Fatalf("configuration %d = %#v, want an unused entry", index, configurations[index])
		}
	}
	senders, err := bridgeSenders(settings)
	if err != nil {
		t.Fatalf("bridgeSenders: %v", err)
	}
	if len(senders) != 2 || senders[0].Prefixlen != 64 || senders[0].Bridge != 0 || ipv4FromWord(senders[0].Address) != settings.Entries[0].Server ||
		senders[1].Prefixlen != 32+24 || senders[1].Bridge != 0 || ipv4FromWord(senders[1].Address) != netip.MustParseAddr("46.102.130.0") {
		t.Fatalf("senders = %#v", senders)
	}
	settings.Entries[0].Allow = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	if _, err := bridgeSenders(settings); err == nil {
		t.Fatal("an open allow range encoded")
	}
	if _, err := encodeBridgeConfigs(BridgeSettings{Entries: []BridgeEntry{{Server: settings.Entries[0].Server}}}); err == nil {
		t.Fatal("a bridge without ports encoded")
	}
}

func TestBridgeSettingsEncodingOfSeveralEntries(t *testing.T) {
	t.Parallel()

	settings := BridgeSettings{Entries: []BridgeEntry{
		{
			Server: netip.MustParseAddr("160.119.74.33"),
			Ports:  config.PortRange{First: 9000, Last: 9999},
			Allow:  []netip.Prefix{netip.MustParsePrefix("79.175.167.5/32"), netip.MustParsePrefix("46.102.130.95/32")},
		},
		{
			Server: netip.MustParseAddr("178.160.229.46"),
			Ports:  config.PortRange{First: 5000, Last: 5005},
			Allow:  []netip.Prefix{netip.MustParsePrefix("79.175.167.5/32"), netip.MustParsePrefix("178.160.228.7/24")},
		},
	}}
	configurations, err := encodeBridgeConfigs(settings)
	if err != nil {
		t.Fatalf("encodeBridgeConfigs: %v", err)
	}
	for index, entry := range settings.Entries {
		configuration := configurations[index]
		if ipv4FromWord(configuration.ServerIp) != entry.Server || configuration.PortFirst != entry.Ports.First || configuration.PortLast != entry.Ports.Last {
			t.Fatalf("configuration %d = %#v", index, configuration)
		}
	}
	for index := len(settings.Entries); index < MaxBridges; index++ {
		if configurations[index] != (mupBridgeConfigV1{}) {
			t.Fatalf("configuration %d = %#v, want an unused entry", index, configurations[index])
		}
	}

	senders, err := bridgeSenders(settings)
	if err != nil {
		t.Fatalf("bridgeSenders: %v", err)
	}
	type sender struct {
		prefixlen uint32
		bridge    uint32
		address   string
	}
	want := []sender{
		{64, 0, "160.119.74.33"}, {64, 0, "79.175.167.5"}, {64, 0, "46.102.130.95"},
		{64, 1, "178.160.229.46"}, {64, 1, "79.175.167.5"}, {56, 1, "178.160.228.0"},
	}
	if len(senders) != len(want) {
		t.Fatalf("senders = %#v, want %d keys", senders, len(want))
	}
	for index, key := range senders {
		got := sender{key.Prefixlen, key.Bridge, ipv4FromWord(key.Address).String()}
		if got != want[index] {
			t.Fatalf("sender %d = %+v, want %+v", index, got, want[index])
		}
	}
}

func TestBridgeSettingsRefuseAnEmptyOrLongList(t *testing.T) {
	t.Parallel()

	entry := BridgeEntry{Server: netip.MustParseAddr("160.119.74.33"), Ports: config.SinglePort(9000)}
	tooMany := make([]BridgeEntry, MaxBridges+1)
	for index := range tooMany {
		tooMany[index] = entry
		tooMany[index].Ports = config.SinglePort(uint16(9000 + index))
	}
	for name, settings := range map[string]BridgeSettings{"no entry": {}, "too many entries": {Entries: tooMany}} {
		if _, err := encodeBridgeConfigs(settings); err == nil {
			t.Fatalf("%s: encodeBridgeConfigs succeeded", name)
		}
		if _, err := bridgeSenders(settings); err == nil {
			t.Fatalf("%s: bridgeSenders succeeded", name)
		}
	}
	if _, err := encodeBridgeConfigs(BridgeSettings{Entries: tooMany[:MaxBridges]}); err != nil {
		t.Fatalf("encodeBridgeConfigs of %d entries: %v", MaxBridges, err)
	}
}

func TestDataplaneMaxBridgesMatchesTheConfiguration(t *testing.T) {
	t.Parallel()

	if MaxBridges != config.MaxBridges {
		t.Fatalf("dataplane.MaxBridges = %d, config.MaxBridges = %d", MaxBridges, config.MaxBridges)
	}
}

func TestEncodeEgressPathEntryOfABridgeVia(t *testing.T) {
	t.Parallel()

	client := ClientKey{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), InstanceNonce: 7}
	entry := EgressPathEntry{
		Client: client, PathID: 1, Server: netip.MustParseAddr("192.0.2.80"), ServerPort: 9300,
		Transport: protocol.TransportUDP, Ifindex: 3, ReturnIP: netip.MustParseAddr("198.51.100.9"),
		Bridge: true, BridgeVia: true, LocalIP: netip.MustParseAddr("203.0.113.5"),
	}
	_, value, err := encodeEgressPathEntry(entry)
	if err != nil {
		t.Fatalf("encodeEgressPathEntry: %v", err)
	}
	if value.Flags != protocol.ControlFlagReturnIP|protocol.ControlFlagBridge|protocol.ControlFlagBridgeVia ||
		ipv4FromWord(value.ReturnIp) != entry.ReturnIP || ipv4FromWord(value.ServerIp) != entry.Server {
		t.Fatalf("value = %#v", value)
	}

	pool := entry
	pool.ReturnIP = netip.Addr{}
	pool.Pool, pool.PerPacket = true, true
	pool.Members = []netip.Addr{netip.MustParseAddr("198.51.100.40"), netip.MustParseAddr("198.51.100.41")}
	if _, value, err = encodeEgressPathEntry(pool); err != nil {
		t.Fatalf("encodeEgressPathEntry of a pool: %v", err)
	}
	if value.Flags != protocol.ControlFlagReturnPool|protocol.ControlFlagBalancePerPacket|protocol.ControlFlagBridge|protocol.ControlFlagBridgeVia ||
		value.Count != 2 {
		t.Fatalf("pool value = %#v", value)
	}

	noBridge := entry
	noBridge.Bridge = false
	noVia := entry
	noVia.ReturnIP = netip.Addr{}
	for name, bad := range map[string]EgressPathEntry{"without a bridge": noBridge, "without a return IP or pool": noVia} {
		if _, _, err := encodeEgressPathEntry(bad); err == nil {
			t.Fatalf("a bridge via %s encoded", name)
		}
	}
}

func TestClientEgressPathOfABridgeViaExpectsTheBridge(t *testing.T) {
	t.Parallel()

	path := config.Path{
		Server: netip.MustParseAddr("192.0.2.80"), ServerPort: 9300, Transport: protocol.TransportUDP,
		ReturnIP: netip.MustParseAddr("198.51.100.0"), ReturnPrefix: 28, Bridge: true, BridgeVia: true,
	}
	settings := EgressPathFromConfig(path)
	if settings.Server != path.Server || settings.ReturnIP.IsValid() || settings.ReturnPrefix != 0 {
		t.Fatalf("settings = %#v, want the bridge address without a return IP", settings)
	}
	encoded, err := encodeClientEgressPath(2, settings)
	if err != nil {
		t.Fatalf("encodeClientEgressPath: %v", err)
	}
	if encoded.Flags != 0 || encoded.ReturnIp != 0 || encoded.Prefix != 0 || ipv4FromWord(encoded.ServerIp) != path.Server {
		t.Fatalf("encoded = %#v, want the bridge address only", encoded)
	}

	// A bridge path without BridgeVia keeps its via, because the bridge emits
	// the reflected reply.
	path.BridgeVia = false
	if settings := EgressPathFromConfig(path); settings.ReturnIP != path.ReturnIP || settings.ReturnPrefix != 28 {
		t.Fatalf("settings = %#v, want the pool", settings)
	}
}
