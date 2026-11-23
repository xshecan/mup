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

	settings := BridgeSettings{
		Server: netip.MustParseAddr("46.102.130.95"),
		Ports:  config.PortRange{First: 9000, Last: 9399},
		Allow:  []netip.Prefix{netip.MustParsePrefix("46.102.130.17/24")},
	}
	configuration, err := encodeBridgeConfig(settings)
	if err != nil || ipv4FromWord(configuration.ServerIp) != settings.Server || configuration.PortFirst != 9000 || configuration.PortLast != 9399 {
		t.Fatalf("configuration = %#v, %v", configuration, err)
	}
	senders, err := bridgeSenders(settings)
	if err != nil {
		t.Fatalf("bridgeSenders: %v", err)
	}
	if len(senders) != 2 || senders[0].Prefixlen != 32 || ipv4FromWord(senders[0].Address) != settings.Server ||
		senders[1].Prefixlen != 24 || ipv4FromWord(senders[1].Address) != netip.MustParseAddr("46.102.130.0") {
		t.Fatalf("senders = %#v", senders)
	}
	settings.Allow = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	if _, err := bridgeSenders(settings); err == nil {
		t.Fatal("an open allow range encoded")
	}
	if _, err := encodeBridgeConfig(BridgeSettings{Server: settings.Server}); err == nil {
		t.Fatal("a bridge without ports encoded")
	}
}
