//go:build linux

package dataplane

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/xshecan/mup/protocol"
)

var (
	bridgeAddress = netip.MustParseAddr("192.0.2.80")
	bridgeServer  = netip.MustParseAddr("203.0.113.5")
	bridgeAllowed = netip.MustParseAddr("203.0.114.7")
	bridgeClient  = netip.MustParseAddr("198.51.100.10")
	bridgeMember  = netip.MustParseAddr("198.51.100.40")
)

// bridgeCollection loads a bridge at 192.0.2.80 for the server 203.0.113.5,
// on ports 9000 to 9399, that also takes wrapped replies from 203.0.114.0/24.
func bridgeCollection(t *testing.T) *ebpf.Collection {
	t.Helper()
	collection := loadTestCollection(t)
	put := func(name string, key, value any) {
		t.Helper()
		if err := collection.Maps[name].Update(key, value, ebpf.UpdateAny); err != nil {
			t.Fatalf("update %s: %v", name, err)
		}
	}
	put("bridge_config", uint32(0), mupBridgeConfigV1{ServerIp: mustTestWord(t, bridgeServer), PortFirst: 9000, PortLast: 9399})
	put("bridge_addresses", mustTestWord(t, bridgeAddress), uint8(1))
	put("bridge_allow", mupBridgeAllowKeyV1{Prefixlen: 32, Address: mustTestWord(t, bridgeServer)}, uint8(1))
	put("bridge_allow", mupBridgeAllowKeyV1{Prefixlen: 24, Address: mustTestWord(t, netip.MustParseAddr("203.0.114.0"))}, uint8(1))
	return collection
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

// An ICMP bridge via path wraps an Echo Reply from the bridge address to the
// client, not an Echo Request to the member.
func TestServerWrapsAnEchoReplyOfAnICMPBridgeVia(t *testing.T) {
	collection := egressBridgeViaCollection(t, protocol.TransportICMP, false, egressMemberA)
	defer collection.Close()
	result, output := targetReply(t, collection)
	if result != tcActOK && result != tcActRedirect {
		t.Fatalf("return value = %d, want pass or redirect", int32(result))
	}
	ip := assertBridgeViaWrapper(t, output, egressMemberA, protocol.IPProtocolICMP)[14:]
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

	if err := bridge.Maps["bridge_allow"].Update(mupBridgeAllowKeyV1{Prefixlen: 32, Address: mustTestWord(t, egressMemberA)}, uint8(1), ebpf.UpdateAny); err != nil {
		t.Fatalf("update bridge_allow: %v", err)
	}
	result, output := runBridge(t, bridge, wrapped)
	if result != tcActRedirect {
		t.Fatalf("return value = %d, want a redirect", int32(result))
	}
	assertUDPHeader(t, output, bridgeAddress, ingressClient, 9300, 51821)
}
