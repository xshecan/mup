//go:build linux

package dataplane

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/protocol"
)

var (
	bridgeAddress = netip.MustParseAddr("192.0.2.80")
	bridgeServer  = netip.MustParseAddr("203.0.113.5")
	bridgeAllowed = netip.MustParseAddr("203.0.114.7")
	bridgeClient  = netip.MustParseAddr("198.51.100.10")
	bridgeMember  = netip.MustParseAddr("198.51.100.40")
	// bridgeServer2 and bridgeAllowed2 belong to the second entry of a bridge
	// with two entries.
	bridgeServer2  = netip.MustParseAddr("203.0.113.6")
	bridgeAllowed2 = netip.MustParseAddr("203.0.116.7")
)

// bridgeEntry is the entry of bridgeCollection: the server 203.0.113.5, on
// ports 9000 to 9399, that also takes wrapped replies from 203.0.114.0/24.
var bridgeEntry = BridgeEntry{
	Server: bridgeServer,
	Ports:  config.PortRange{First: 9000, Last: 9399},
	Allow:  []netip.Prefix{netip.MustParsePrefix("203.0.114.0/24")},
}

// bridgeCollection loads a bridge at 192.0.2.80 with the one entry
// bridgeEntry.
func bridgeCollection(t *testing.T) *ebpf.Collection {
	t.Helper()
	return bridgeCollectionOf(t, bridgeEntry)
}

// bridgeCollectionOf loads a bridge at 192.0.2.80 with the entries. It writes
// the maps with the encoders of ConfigureBridge.
func bridgeCollectionOf(t *testing.T, entries ...BridgeEntry) *ebpf.Collection {
	t.Helper()
	collection := loadTestCollection(t)
	put := func(name string, key, value any) {
		t.Helper()
		if err := collection.Maps[name].Update(key, value, ebpf.UpdateAny); err != nil {
			t.Fatalf("update %s: %v", name, err)
		}
	}
	settings := BridgeSettings{Entries: entries}
	configurations, err := encodeBridgeConfigs(settings)
	if err != nil {
		t.Fatalf("encodeBridgeConfigs: %v", err)
	}
	senders, err := bridgeSenders(settings)
	if err != nil {
		t.Fatalf("bridgeSenders: %v", err)
	}
	for _, sender := range senders {
		put("bridge_allow", sender, uint8(1))
	}
	put("bridge_addresses", mustTestWord(t, bridgeAddress), uint8(1))
	for index, configuration := range configurations {
		put("bridge_config", uint32(index), configuration)
	}
	return collection
}

// twoEntryBridgeCollection loads a bridge with bridgeEntry and a second entry
// for the server 203.0.113.6, on ports 9400 to 9499, that also takes wrapped
// replies from 203.0.116.0/24.
func twoEntryBridgeCollection(t *testing.T) *ebpf.Collection {
	t.Helper()
	return bridgeCollectionOf(t, bridgeEntry, BridgeEntry{
		Server: bridgeServer2,
		Ports:  config.PortRange{First: 9400, Last: 9499},
		Allow:  []netip.Prefix{netip.MustParsePrefix("203.0.116.0/24")},
	})
}

// runBridge runs the bridge program on a frame. A send is a redirect, or a
// drop of the FIB lookup in a namespace without a route.
func runBridge(t *testing.T, collection *ebpf.Collection, frame []byte) (uint32, []byte) {
	t.Helper()
	before := dropCount(t, collection, protocol.DropFIB)
	result, output, err := collection.Programs["mup_bridge_ingress"].Test(frame)
	if err != nil {
		t.Fatalf("program test: %v", err)
	}
	if result == tcActShot && dropCount(t, collection, protocol.DropFIB) > before {
		result = tcActRedirect
	}
	return result, output
}

func bridgeCounter(t *testing.T, collection *ebpf.Collection, index uint32) uint64 {
	t.Helper()
	var values []uint64
	if err := collection.Maps["bridge_counters"].Lookup(index, &values); err != nil {
		t.Fatalf("read bridge counter %d: %v", index, err)
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	return total
}

// wrappedFrame wraps the IPv4 packet of a frame as a server does for a bridge.
func wrappedFrame(frame []byte, source netip.Addr, port uint16) []byte {
	wrapped := protocol.WrapForBridge(frame[14:], source, bridgeAddress, port)
	return append(bytes.Clone(frame[:14]), wrapped...)
}

func TestBridgeSendsTheIngressToItsServer(t *testing.T) {
	collection := bridgeCollection(t)
	defer collection.Close()

	result, output := runBridge(t, collection, udpWireGuardFrame(t, bridgeClient, bridgeAddress, 51820, 9100, 9))
	if result != tcActRedirect {
		t.Fatalf("UDP return value = %d, want a redirect", int32(result))
	}
	assertUDPHeader(t, output, bridgeClient, bridgeServer, 51820, 9100)

	result, output = runBridge(t, collection, icmpWireGuardFrame(t, bridgeClient, bridgeAddress, 8, 9100, 9))
	if result != tcActRedirect {
		t.Fatalf("ICMP return value = %d, want a redirect", int32(result))
	}
	ip := output[14:]
	if source, destination := netip.AddrFrom4([4]byte(ip[12:16])), netip.AddrFrom4([4]byte(ip[16:20])); source != bridgeClient || destination != bridgeServer {
		t.Fatalf("ICMP addresses %s to %s, want %s to %s", source, destination, bridgeClient, bridgeServer)
	}
	if l4 := ip[20:]; l4[0] != 8 || binary.BigEndian.Uint16(l4[4:6]) != 9100 || onesComplement(ip[:20], 0) != 0 || onesComplement(l4, 0) != 0 {
		t.Fatalf("ICMP header %x, or a checksum is invalid", l4[:8])
	}
	if packets := bridgeCounter(t, collection, 0); packets != 2 {
		t.Fatalf("ingress packets = %d, want 2", packets)
	}
}

func TestBridgePassesOtherTraffic(t *testing.T) {
	collection := bridgeCollection(t)
	defer collection.Close()

	for name, frame := range map[string][]byte{
		"port outside the range": udpWireGuardFrame(t, bridgeClient, bridgeAddress, 51820, 8000, 9),
		"other destination":      udpWireGuardFrame(t, bridgeClient, netip.MustParseAddr("192.0.2.81"), 51820, 9100, 9),
		"normal ping":            icmpWireGuardFrame(t, bridgeClient, bridgeAddress, 8, 9100, 0),
		"echo reply":             icmpWireGuardFrame(t, bridgeClient, bridgeAddress, 0, 9100, 9),
		"plain WireGuard":        udpWireGuardFrame(t, bridgeClient, bridgeAddress, 51820, 9100, 0),
		"from the server":        udpWireGuardFrame(t, bridgeServer, bridgeAddress, 51820, 9100, 9),
	} {
		result, _, err := collection.Programs["mup_bridge_ingress"].Test(frame)
		if err != nil {
			t.Fatalf("%s: program test: %v", name, err)
		}
		if result != tcxNext {
			t.Fatalf("%s: return value = %d, want the next program", name, int32(result))
		}
	}
}

func TestBridgeUnwrapsTheRepliesOfItsServer(t *testing.T) {
	collection := bridgeCollection(t)
	defer collection.Close()

	inner := icmpWireGuardFrame(t, bridgeClient, bridgeMember, 8, 9200, 9)
	for name, source := range map[string]netip.Addr{"server": bridgeServer, "allow range": bridgeAllowed} {
		result, output := runBridge(t, collection, wrappedFrame(inner, source, 9200))
		if result != tcActRedirect {
			t.Fatalf("%s: return value = %d, want a redirect", name, int32(result))
		}
		ip, want := output[14:], inner[14:]
		if len(ip) != len(want) || !bytes.Equal(ip[12:20], want[12:20]) || ip[9] != want[9] ||
			binary.BigEndian.Uint16(ip[2:4]) != uint16(len(want)) || onesComplement(ip[:20], 0) != 0 {
			t.Fatalf("%s: unwrapped header %x, want the inner header %x", name, ip[:20], want[:20])
		}
		if !bytes.Equal(ip[20:], want[20:]) {
			t.Fatalf("%s: the inner message changed", name)
		}
	}
	if packets := bridgeCounter(t, collection, 2); packets != 2 {
		t.Fatalf("egress packets = %d, want 2", packets)
	}

	direct := udpWireGuardFrame(t, bridgeAddress, bridgeClient, 9300, 51820, 9)
	result, output := runBridge(t, collection, wrappedFrame(direct, bridgeServer, 9300))
	if result != tcActRedirect {
		t.Fatalf("direct return value = %d, want a redirect", int32(result))
	}
	assertUDPHeader(t, output, bridgeAddress, bridgeClient, 9300, 51820)

	badVersion := wrappedFrame(inner, bridgeServer, 9200)
	badVersion[14+20+10] = 2
	for name, test := range map[string]struct {
		frame  []byte
		reason protocol.DropReason
	}{
		"unknown sender":   {wrappedFrame(inner, netip.MustParseAddr("203.0.115.7"), 9200), protocol.DropBridgeSource},
		"bad version":      {badVersion, protocol.DropBridgePacket},
		"not a MUP packet": {wrappedFrame(icmpWireGuardFrame(t, bridgeClient, bridgeMember, 8, 9200, 0), bridgeServer, 9200), protocol.DropBridgePacket},
	} {
		before := dropCount(t, collection, test.reason)
		result, _, err := collection.Programs["mup_bridge_ingress"].Test(test.frame)
		if err != nil {
			t.Fatalf("%s: program test: %v", name, err)
		}
		if after := dropCount(t, collection, test.reason); result != tcActShot || after != before+1 {
			t.Fatalf("%s: return value = %d, %s drops %d to %d, want a drop", name, int32(result), test.reason, before, after)
		}
	}
}

func TestBridgeSendsTheIngressOfEachEntryToTheServerOfThatEntry(t *testing.T) {
	collection := twoEntryBridgeCollection(t)
	defer collection.Close()

	for _, test := range []struct {
		port   uint16
		server netip.Addr
	}{{9100, bridgeServer}, {9399, bridgeServer}, {9400, bridgeServer2}, {9450, bridgeServer2}} {
		result, output := runBridge(t, collection, udpWireGuardFrame(t, bridgeClient, bridgeAddress, 51820, test.port, 9))
		if result != tcActRedirect {
			t.Fatalf("UDP port %d: return value = %d, want a redirect", test.port, int32(result))
		}
		assertUDPHeader(t, output, bridgeClient, test.server, 51820, test.port)
	}

	result, output := runBridge(t, collection, icmpWireGuardFrame(t, bridgeClient, bridgeAddress, 8, 9450, 9))
	if result != tcActRedirect {
		t.Fatalf("ICMP return value = %d, want a redirect", int32(result))
	}
	ip := output[14:]
	if destination := netip.AddrFrom4([4]byte(ip[16:20])); destination != bridgeServer2 {
		t.Fatalf("ICMP destination %s, want %s", destination, bridgeServer2)
	}
}

func TestBridgeTakesTheWrappedRepliesOfAnEntryOnlyFromItsSenders(t *testing.T) {
	collection := twoEntryBridgeCollection(t)
	defer collection.Close()

	for name, test := range map[string]struct {
		source netip.Addr
		port   uint16
	}{
		"allow range of entry 1": {bridgeAllowed, 9200},
		"server of entry 1":      {bridgeServer, 9200},
		"allow range of entry 2": {bridgeAllowed2, 9450},
		"server of entry 2":      {bridgeServer2, 9450},
	} {
		inner := icmpWireGuardFrame(t, bridgeClient, bridgeMember, 8, test.port, 9)
		result, output := runBridge(t, collection, wrappedFrame(inner, test.source, test.port))
		if result != tcActRedirect {
			t.Fatalf("%s: return value = %d, want a redirect", name, int32(result))
		}
		if ip, want := output[14:], inner[14:]; len(ip) != len(want) || !bytes.Equal(ip[12:20], want[12:20]) {
			t.Fatalf("%s: unwrapped header %x, want the inner header %x", name, ip[:20], want[:20])
		}
	}

	for name, test := range map[string]struct {
		source netip.Addr
		port   uint16
	}{
		"allow range of entry 1 on a port of entry 2": {bridgeAllowed, 9450},
		"server of entry 1 on a port of entry 2":      {bridgeServer, 9450},
		"allow range of entry 2 on a port of entry 1": {bridgeAllowed2, 9200},
		"server of entry 2 on a port of entry 1":      {bridgeServer2, 9200},
	} {
		inner := icmpWireGuardFrame(t, bridgeClient, bridgeMember, 8, test.port, 9)
		before := dropCount(t, collection, protocol.DropBridgeSource)
		result, _, err := collection.Programs["mup_bridge_ingress"].Test(wrappedFrame(inner, test.source, test.port))
		if err != nil {
			t.Fatalf("%s: program test: %v", name, err)
		}
		if after := dropCount(t, collection, protocol.DropBridgeSource); result != tcActShot || after != before+1 {
			t.Fatalf("%s: return value = %d, BRIDGE_SOURCE drops %d to %d, want a drop", name, int32(result), before, after)
		}
	}
}

func TestBridgePassesAPacketOnAPortOfNoEntry(t *testing.T) {
	collection := twoEntryBridgeCollection(t)
	defer collection.Close()

	for name, frame := range map[string][]byte{
		"UDP below the entries":  udpWireGuardFrame(t, bridgeClient, bridgeAddress, 51820, 8999, 9),
		"UDP above the entries":  udpWireGuardFrame(t, bridgeClient, bridgeAddress, 51820, 9500, 9),
		"ICMP above the entries": icmpWireGuardFrame(t, bridgeClient, bridgeAddress, 8, 9500, 9),
		"wrapped reply":          wrappedFrame(icmpWireGuardFrame(t, bridgeClient, bridgeMember, 8, 9500, 9), bridgeServer, 9500),
	} {
		result, output, err := collection.Programs["mup_bridge_ingress"].Test(frame)
		if err != nil {
			t.Fatalf("%s: program test: %v", name, err)
		}
		if result != tcxNext || !bytes.Equal(output, frame) {
			t.Fatalf("%s: return value = %d, want the next program and an unchanged packet", name, int32(result))
		}
	}
}

// A sender leaves the UDP checksum of a packet from a local socket to its
// device. A device that finds the UDP header by the IPv4 header does not
// complete it behind the wrapper, so the inner packet arrives with the
// pseudo-header sum only, and the bridge completes the checksum.
func TestBridgeCompletesAPartialInnerChecksum(t *testing.T) {
	collection := bridgeCollection(t)
	defer collection.Close()

	inner := udpWireGuardFrame(t, bridgeMember, bridgeServer, 51820, 9300, 9)
	ip := inner[14:]
	binary.BigEndian.PutUint16(ip[26:28], ^onesComplement(nil, pseudoHeaderSum(ip)))
	if onesComplement(ip[20:], pseudoHeaderSum(ip)) == 0 {
		t.Fatal("the test packet must start with an incomplete checksum")
	}
	result, output := runBridge(t, collection, wrappedFrame(inner, bridgeAllowed, 9300))
	if result != tcActRedirect {
		t.Fatalf("return value = %d, want a redirect", int32(result))
	}
	assertUDPHeader(t, output, bridgeMember, bridgeServer, 51820, 9300)
	if !bytes.Equal(output[14+28:], inner[14+28:]) {
		t.Fatal("the inner payload changed")
	}
}

// egressBridgeCollection is egressReplyCollection with path 0 through a bridge
// that reflects through the pool, and path 1 a direct UDP path.
func egressBridgeCollection(t *testing.T, mode uint8, healthy uint8) *ebpf.Collection {
	t.Helper()
	collection := egressReplyCollection(t, mode, healthy)
	client := mupClientKeyV1{AdvertisedIp: mustTestWord(t, ingressClient), InstanceNonce: 7}
	bridged := mupDownPathV1{
		ServerIp: mustTestWord(t, bridgeAddress), Ifindex: 1, ServerPort: 9300, Transport: uint8(protocol.TransportICMP),
		Flags: protocol.ControlFlagReturnPool | protocol.ControlFlagBridge, Count: 2, LocalIp: mustTestWord(t, bridgeServer),
	}
	bridged.Members[0] = mustTestWord(t, egressMemberA)
	bridged.Members[1] = mustTestWord(t, egressMemberB)
	direct := mupDownPathV1{
		ServerIp: mustTestWord(t, egressDirectServer), Ifindex: 1, ServerPort: 9200, Transport: uint8(protocol.TransportUDP),
	}
	for id, value := range []mupDownPathV1{bridged, direct} {
		if err := collection.Maps["server_down_paths"].Update(mupDownPathKeyV1{Client: client, PathId: uint32(id)}, value, ebpf.UpdateAny); err != nil {
			t.Fatalf("update egress path %d: %v", id, err)
		}
	}
	if err := collection.Maps["server_down_groups"].Update(mupDownGroupKeyV1{Client: client, ListenPort: 51821}, mupDownGroupV1{
		Mode: mode, PathMask: 0b11, HealthyMask: healthy, IcmpMask: 0b01,
	}, ebpf.UpdateAny); err != nil {
		t.Fatalf("update egress group: %v", err)
	}
	return collection
}

func TestServerWrapsTheReplyOfAEgressBridge(t *testing.T) {
	collection := egressBridgeCollection(t, 0, 0b01)
	defer collection.Close()
	result, output := targetReply(t, collection)
	if result != tcActOK && result != tcActRedirect {
		t.Fatalf("return value = %d, want pass or redirect", int32(result))
	}
	// The outer UDP checksum is zero, and the inner checksum covers the
	// payload.
	ip := output[14:]
	if source, destination := netip.AddrFrom4([4]byte(ip[12:16])), netip.AddrFrom4([4]byte(ip[16:20])); ip[9] != protocol.IPProtocolUDP ||
		source != bridgeServer || destination != bridgeAddress || onesComplement(ip[:20], 0) != 0 {
		t.Fatalf("outer header %x, want valid UDP from %s to %s", ip[:20], bridgeServer, bridgeAddress)
	}
	if binary.BigEndian.Uint16(ip[20:22]) != 9300 || binary.BigEndian.Uint16(ip[22:24]) != 9300 ||
		binary.BigEndian.Uint16(ip[24:26]) != binary.BigEndian.Uint16(ip[2:4])-20 || binary.BigEndian.Uint16(ip[26:28]) != 0 ||
		!bytes.Equal(ip[28:32], []byte{0x4d, 0x42, 1, protocol.IPProtocolICMP}) {
		t.Fatalf("wrapper %x", ip[20:40])
	}
	inner, err := protocol.UnwrapBridge(ip[:binary.BigEndian.Uint16(ip[2:4])])
	if err != nil {
		t.Fatalf("UnwrapBridge: %v", err)
	}
	assertReflectedICMP(t, append(bytes.Clone(output[:14]), inner...))
}

// In repeater mode, the copy of an egress bridge loses its wrapper after the clone, so
// the next path gets the reply as it was.
func TestServerRepeaterUnwrapsAfterTheBridgeCopy(t *testing.T) {
	collection := egressBridgeCollection(t, 2, 0b11)
	defer collection.Close()
	result, output := targetReply(t, collection)
	if result != tcActOK && result != tcActRedirect {
		t.Fatalf("return value = %d, want pass or redirect", int32(result))
	}
	assertUDPHeader(t, output, egressDirectServer, ingressClient, 9200, 51821)
	if drops := dropCount(t, collection, protocol.DropBridgePacket); drops != 0 {
		t.Fatalf("BRIDGE_PACKET drops = %d", drops)
	}
}

// egressBridgeViaCollection is egressReplyCollection with path 0 through a
// bridge with BRIDGE_VIA, on the transport. One member is a return IP, and
// more members are a pool.
func egressBridgeViaCollection(t *testing.T, transport protocol.TransportID, perPacket bool, members ...netip.Addr) *ebpf.Collection {
	t.Helper()
	collection := egressReplyCollection(t, 0, 0b01)
	client := mupClientKeyV1{AdvertisedIp: mustTestWord(t, ingressClient), InstanceNonce: 7}
	path := mupDownPathV1{
		ServerIp: mustTestWord(t, bridgeAddress), Ifindex: 1, ServerPort: 9300, Transport: uint8(transport),
		Flags: protocol.ControlFlagBridge | protocol.ControlFlagBridgeVia, LocalIp: mustTestWord(t, bridgeServer),
	}
	if len(members) == 1 {
		path.Flags |= protocol.ControlFlagReturnIP
		path.ReturnIp = mustTestWord(t, members[0])
	} else {
		path.Flags |= protocol.ControlFlagReturnPool
		if perPacket {
			path.Flags |= protocol.ControlFlagBalancePerPacket
		}
		for index, member := range members {
			path.Members[index] = mustTestWord(t, member)
		}
		path.Count = uint32(len(members))
	}
	if err := collection.Maps["server_down_paths"].Update(mupDownPathKeyV1{Client: client, PathId: 0}, path, ebpf.UpdateAny); err != nil {
		t.Fatalf("update egress path: %v", err)
	}
	var icmpMask uint8
	if transport == protocol.TransportICMP {
		icmpMask = 0b01
	}
	if err := collection.Maps["server_down_groups"].Update(mupDownGroupKeyV1{Client: client, ListenPort: 51821}, mupDownGroupV1{
		PathMask: 0b11, HealthyMask: 0b01, IcmpMask: icmpMask,
	}, ebpf.UpdateAny); err != nil {
		t.Fatalf("update egress group: %v", err)
	}
	return collection
}

// assertBridgeViaWrapper checks that a frame is a wrapper from the member to
// the bridge on port 9300 with a zero UDP checksum, and returns the frame with
// the inner packet.
func assertBridgeViaWrapper(t *testing.T, frame []byte, member netip.Addr, protocolID uint8) []byte {
	t.Helper()
	ip := frame[14:]
	if source, destination := netip.AddrFrom4([4]byte(ip[12:16])), netip.AddrFrom4([4]byte(ip[16:20])); ip[9] != protocol.IPProtocolUDP ||
		source != member || destination != bridgeAddress || onesComplement(ip[:20], 0) != 0 {
		t.Fatalf("outer header %x, want valid UDP from %s to %s", ip[:20], member, bridgeAddress)
	}
	if binary.BigEndian.Uint16(ip[20:22]) != 9300 || binary.BigEndian.Uint16(ip[22:24]) != 9300 ||
		binary.BigEndian.Uint16(ip[24:26]) != binary.BigEndian.Uint16(ip[2:4])-20 || binary.BigEndian.Uint16(ip[26:28]) != 0 ||
		!bytes.Equal(ip[28:32], []byte{0x4d, 0x42, 1, protocolID}) {
		t.Fatalf("wrapper %x", ip[20:40])
	}
	inner, err := protocol.UnwrapBridge(ip[:binary.BigEndian.Uint16(ip[2:4])])
	if err != nil {
		t.Fatalf("UnwrapBridge: %v", err)
	}
	return append(bytes.Clone(frame[:14]), inner...)
}

// setReflectorCursor sets the per-packet cursor on every CPU, so the next
// reply takes the same member wherever the test runs.
func setReflectorCursor(t *testing.T, collection *ebpf.Collection, value uint32) {
	t.Helper()
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("possible CPUs: %v", err)
	}
	values := make([]uint32, cpus)
	for index := range values {
		values[index] = value
	}
	if err := collection.Maps["reflector_cursor"].Update(uint32(0), values, ebpf.UpdateAny); err != nil {
		t.Fatalf("update reflector cursor: %v", err)
	}
}

// With BRIDGE_VIA, the server applies the return IP to the leg to the bridge.
// The wrapper leaves from the return IP, and the bridge gets the direct reply
// from its own address.
func TestServerWrapsTheReplyOfABridgeViaFromTheReturnIP(t *testing.T) {
	collection := egressBridgeViaCollection(t, protocol.TransportUDP, false, egressMemberA)
	defer collection.Close()
	result, output := targetReply(t, collection)
	if result != tcActOK && result != tcActRedirect {
		t.Fatalf("return value = %d, want pass or redirect", int32(result))
	}
	inner := assertBridgeViaWrapper(t, output, egressMemberA, protocol.IPProtocolUDP)
	assertUDPHeader(t, inner, bridgeAddress, ingressClient, 9300, 51821)
}

// A per-packet pool on a bridge via path spreads the wrappers over its
// members, and the inner reply stays the direct reply from the bridge.
func TestServerSpreadsTheWrappersOfABridgeViaOverThePool(t *testing.T) {
	collection := egressBridgeViaCollection(t, protocol.TransportUDP, true, egressMemberA, egressMemberB)
	defer collection.Close()
	for cursor, member := range []netip.Addr{egressMemberA, egressMemberB} {
		setReflectorCursor(t, collection, uint32(cursor))
		result, output := targetReply(t, collection)
		if result != tcActOK && result != tcActRedirect {
			t.Fatalf("reply %d: return value = %d, want pass or redirect", cursor, int32(result))
		}
		inner := assertBridgeViaWrapper(t, output, member, protocol.IPProtocolUDP)
		assertUDPHeader(t, inner, bridgeAddress, ingressClient, 9300, 51821)
	}
}

// assertBridgeEchoWrapper checks that a frame is the reflected wrapper of an
// ICMP bridge via path: an Echo Request from the bridge address to the member,
// with the server port 9300 as the identifier and the sequence, the bridge
// header, and a valid ICMP checksum. It returns the frame with the inner
// packet.
func assertBridgeEchoWrapper(t *testing.T, frame []byte, member netip.Addr) []byte {
	t.Helper()
	ip := frame[14:]
	ip = ip[:binary.BigEndian.Uint16(ip[2:4])]
	if source, destination := netip.AddrFrom4([4]byte(ip[12:16])), netip.AddrFrom4([4]byte(ip[16:20])); ip[9] != protocol.IPProtocolICMP ||
		source != bridgeAddress || destination != member || onesComplement(ip[:20], 0) != 0 {
		t.Fatalf("outer header %x, want valid ICMP from %s to %s", ip[:20], bridgeAddress, member)
	}
	icmp := ip[20:]
	if icmp[0] != 8 || icmp[1] != 0 || binary.BigEndian.Uint16(icmp[4:6]) != 9300 || binary.BigEndian.Uint16(icmp[6:8]) != 9300 {
		t.Fatalf("Echo header %x, want an Echo Request with identifier and sequence 9300", icmp[:8])
	}
	if !bytes.Equal(icmp[8:12], []byte{0x4d, 0x42, 1, protocol.IPProtocolICMP}) {
		t.Fatalf("bridge header %x", icmp[8:20])
	}
	if onesComplement(icmp, 0) != 0 {
		t.Fatal("the ICMP checksum of the wrapper is invalid")
	}
	inner, err := protocol.UnwrapBridge(ip)
	if err != nil {
		t.Fatalf("UnwrapBridge: %v", err)
	}
	return append(bytes.Clone(frame[:14]), inner...)
}

// assertBridgeEchoReply checks an Echo Reply from the bridge address to the
// client with the identifier 9300, the token, and valid checksums.
func assertBridgeEchoReply(t *testing.T, frame []byte) {
	t.Helper()
	ip := frame[14:]
	l4 := ip[20:binary.BigEndian.Uint16(ip[2:4])]
	if source, destination := netip.AddrFrom4([4]byte(ip[12:16])), netip.AddrFrom4([4]byte(ip[16:20])); ip[9] != protocol.IPProtocolICMP ||
		source != bridgeAddress || destination != ingressClient {
		t.Fatalf("inner header %x, want ICMP from %s to %s", ip[:20], bridgeAddress, ingressClient)
	}
	if l4[0] != 0 || binary.BigEndian.Uint16(l4[4:6]) != 9300 {
		t.Fatalf("ICMP type %d, identifier %d, want an Echo Reply with identifier 9300", l4[0], binary.BigEndian.Uint16(l4[4:6]))
	}
	if onesComplement(ip[:20], 0) != 0 || onesComplement(l4, 0) != 0 {
		t.Fatal("a checksum is invalid")
	}
	if token := l4[9:12]; token[0] != 0 || token[1] != 0 || token[2] != 9 {
		t.Fatalf("token bytes = %x, want 000009", token)
	}
}

// An ICMP bridge via path reflects the wrapper off the member. The wrapper is
// an Echo Request from the bridge address to the member, and it holds the
// direct Echo Reply from the bridge address to the client.
func TestServerReflectsTheWrapperOfAnICMPBridgeViaOffTheMember(t *testing.T) {
	collection := egressBridgeViaCollection(t, protocol.TransportICMP, false, egressMemberA)
	defer collection.Close()
	result, output := targetReply(t, collection)
	if result != tcActOK && result != tcActRedirect {
		t.Fatalf("return value = %d, want pass or redirect", int32(result))
	}
	inner := assertBridgeEchoWrapper(t, output, egressMemberA)
	assertBridgeEchoReply(t, inner)

	// The wrapper is the Echo wrapper of protocol.WrapForBridgeEcho, byte
	// for byte.
	ip := output[14:]
	ip = ip[:binary.BigEndian.Uint16(ip[2:4])]
	if want := protocol.WrapForBridgeEcho(inner[14:], bridgeAddress, egressMemberA, 9300, 9300); !bytes.Equal(ip, want) {
		t.Fatalf("wrapper = %x, want %x", ip, want)
	}
}

// A pool on an ICMP bridge via path spreads the reflected wrappers over its
// members.
func TestServerSpreadsTheEchoWrappersOfAnICMPBridgeViaOverThePool(t *testing.T) {
	collection := egressBridgeViaCollection(t, protocol.TransportICMP, true, egressMemberA, egressMemberB)
	defer collection.Close()
	for cursor, member := range []netip.Addr{egressMemberA, egressMemberB} {
		setReflectorCursor(t, collection, uint32(cursor))
		result, output := targetReply(t, collection)
		if result != tcActOK && result != tcActRedirect {
			t.Fatalf("reply %d: return value = %d, want pass or redirect", cursor, int32(result))
		}
		assertBridgeEchoReply(t, assertBridgeEchoWrapper(t, output, member))
	}
}

// In repeater mode, the copy on an ICMP bridge via path loses its Echo wrapper
// after the clone, so the next path gets the reply as it was.
func TestServerRepeaterUnwrapsAfterTheEchoWrapperCopy(t *testing.T) {
	collection := egressBridgeViaCollection(t, protocol.TransportICMP, false, egressMemberA)
	defer collection.Close()
	client := mupClientKeyV1{AdvertisedIp: mustTestWord(t, ingressClient), InstanceNonce: 7}
	if err := collection.Maps["server_down_groups"].Update(mupDownGroupKeyV1{Client: client, ListenPort: 51821}, mupDownGroupV1{
		Mode: 2, PathMask: 0b11, HealthyMask: 0b11, IcmpMask: 0b11,
	}, ebpf.UpdateAny); err != nil {
		t.Fatalf("update egress group: %v", err)
	}
	result, output := targetReply(t, collection)
	if result != tcActOK && result != tcActRedirect {
		t.Fatalf("return value = %d, want pass or redirect", int32(result))
	}
	// Path 1 of egressReplyCollection is an ICMP path that reflects through
	// the pool with identifier 9300.
	assertReflectedICMP(t, output)
	if drops := dropCount(t, collection, protocol.DropBridgePacket); drops != 0 {
		t.Fatalf("BRIDGE_PACKET drops = %d", drops)
	}
}

// A partial reply on an ICMP bridge via path gets a full inner checksum with
// the token, so the outer Echo Request, whose checksum covers only the wrapper
// bytes, is valid as well.
func TestServerWritesValidChecksumsOnAPartialReplyOfAnICMPBridgeVia(t *testing.T) {
	for _, length := range []int{protocol.HandshakeResponseLength, 1440} {
		collection := egressBridgeViaCollection(t, protocol.TransportICMP, false, egressMemberA)
		result, output := partialTargetReply(t, collection, length)
		collection.Close()
		if result != tcActOK && result != tcActRedirect {
			t.Fatalf("length %d: return value = %d, want pass or redirect", length, int32(result))
		}
		inner := assertBridgeEchoWrapper(t, output, egressMemberA)
		assertBridgeEchoReply(t, inner)
		ip := inner[14:]
		if icmp := ip[20:binary.BigEndian.Uint16(ip[2:4])]; len(icmp) != 8+length {
			t.Fatalf("length %d: inner ICMP length = %d, want %d", length, len(icmp), 8+length)
		}
	}
}

// echoReplyOf turns the Echo Request of a frame into the Echo Reply that its
// destination sends back: the addresses swap, the type is 0, and the checksums
// are new.
func echoReplyOf(frame []byte) []byte {
	reply := bytes.Clone(frame)
	ip := reply[14:]
	ip = ip[:binary.BigEndian.Uint16(ip[2:4])]
	var source [4]byte
	copy(source[:], ip[12:16])
	copy(ip[12:16], ip[16:20])
	copy(ip[16:20], source[:])
	ip[10], ip[11] = 0, 0
	binary.BigEndian.PutUint16(ip[10:12], onesComplement(ip[:20], 0))
	icmp := ip[20:]
	icmp[0] = 0
	icmp[2], icmp[3] = 0, 0
	binary.BigEndian.PutUint16(icmp[2:4], onesComplement(icmp, 0))
	return reply
}

// The bridge takes the Echo Reply that the member reflects for an ICMP bridge
// via path when the member is in its allow list, and sends the inner Echo
// Reply from its own address. The Echo Request itself is not a wrapper.
func TestBridgeUnwrapsTheEchoReplyOfAnICMPBridgeViaFromAnAllowedMember(t *testing.T) {
	server := egressBridgeViaCollection(t, protocol.TransportICMP, false, egressMemberA)
	defer server.Close()
	result, request := targetReply(t, server)
	if result != tcActOK && result != tcActRedirect {
		t.Fatalf("server return value = %d, want pass or redirect", int32(result))
	}
	reply := echoReplyOf(request)

	bridge := bridgeCollection(t)
	defer bridge.Close()
	before := dropCount(t, bridge, protocol.DropBridgeSource)
	result, _, err := bridge.Programs["mup_bridge_ingress"].Test(reply)
	if err != nil {
		t.Fatalf("program test: %v", err)
	}
	if after := dropCount(t, bridge, protocol.DropBridgeSource); result != tcActShot || after != before+1 {
		t.Fatalf("return value = %d, BRIDGE_SOURCE drops %d to %d, want a drop", int32(result), before, after)
	}

	if err := bridge.Maps["bridge_allow"].Update(mupBridgeAllowKeyV1{Prefixlen: 64, Bridge: 0, Address: mustTestWord(t, egressMemberA)}, uint8(1), ebpf.UpdateAny); err != nil {
		t.Fatalf("update bridge_allow: %v", err)
	}
	result, output := runBridge(t, bridge, reply)
	if result != tcActRedirect {
		t.Fatalf("return value = %d, want a redirect", int32(result))
	}
	assertBridgeEchoReply(t, output)

	// An Echo Request with the magic to the bridge is not a wrapper, so it
	// goes on to the kernel.
	toBridge := bytes.Clone(reply)
	toBridge[14+20] = 8
	toBridge[14+22], toBridge[14+23] = 0, 0
	icmp := toBridge[14+20 : 14+int(binary.BigEndian.Uint16(toBridge[14+2:14+4]))]
	binary.BigEndian.PutUint16(icmp[2:4], onesComplement(icmp, 0))
	result, _, err = bridge.Programs["mup_bridge_ingress"].Test(toBridge)
	if err != nil {
		t.Fatalf("Echo Request: program test: %v", err)
	}
	if result != tcxNext {
		t.Fatalf("Echo Request: return value = %d, want the next program", int32(result))
	}
}

// The bridge takes the wrapper of a bridge via path when the member is in its
// allow list, and sends the inner reply from its own address. It drops the
// wrapper of a member that it does not allow.
func TestBridgeUnwrapsTheReplyOfABridgeViaFromAnAllowedMember(t *testing.T) {
	server := egressBridgeViaCollection(t, protocol.TransportUDP, false, egressMemberA)
	defer server.Close()
	result, wrapped := targetReply(t, server)
	if result != tcActOK && result != tcActRedirect {
		t.Fatalf("server return value = %d, want pass or redirect", int32(result))
	}

	bridge := bridgeCollection(t)
	defer bridge.Close()
	before := dropCount(t, bridge, protocol.DropBridgeSource)
	result, _, err := bridge.Programs["mup_bridge_ingress"].Test(wrapped)
	if err != nil {
		t.Fatalf("program test: %v", err)
	}
	if after := dropCount(t, bridge, protocol.DropBridgeSource); result != tcActShot || after != before+1 {
		t.Fatalf("return value = %d, BRIDGE_SOURCE drops %d to %d, want a drop", int32(result), before, after)
	}

	if err := bridge.Maps["bridge_allow"].Update(mupBridgeAllowKeyV1{Prefixlen: 64, Bridge: 0, Address: mustTestWord(t, egressMemberA)}, uint8(1), ebpf.UpdateAny); err != nil {
		t.Fatalf("update bridge_allow: %v", err)
	}
	result, output := runBridge(t, bridge, wrapped)
	if result != tcActRedirect {
		t.Fatalf("return value = %d, want a redirect", int32(result))
	}
	assertUDPHeader(t, output, bridgeAddress, ingressClient, 9300, 51821)
}
