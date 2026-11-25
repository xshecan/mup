//go:build linux

package dataplane

import (
	"encoding/binary"
	"math"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/xshecan/mup/protocol"
)

// ipv4Length is the IPv4 total length of an Ethernet frame.
func ipv4Length(frame []byte) uint64 {
	return uint64(binary.BigEndian.Uint16(frame[14+2 : 14+4]))
}

// assertClientCounters checks every client path counter against want. An
// index that want does not name must be zero.
func assertClientCounters(t *testing.T, collection *ebpf.Collection, want map[uint32]PathCounter) {
	t.Helper()
	for index := range uint32(16) {
		got, err := readClientPathCounter(collection.Maps["client_path_counters"], index)
		if err != nil {
			t.Fatalf("read client path counter %d: %v", index, err)
		}
		if got != want[index] {
			t.Errorf("client path counter %d = %+v, want %+v", index, got, want[index])
		}
	}
}

func serverCounterKey(client mupClientKeyV1, pathID uint32, direction uint8) mupPathCounterKeyV1 {
	return mupPathCounterKeyV1{Client: client, PathId: pathID, Direction: uint32(direction)}
}

func ensureTestServerCounter(t *testing.T, collection *ebpf.Collection, key mupPathCounterKeyV1) {
	t.Helper()
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("PossibleCPU: %v", err)
	}
	if err := ensurePathCounter(collection.Maps["server_path_counters"], key, cpus); err != nil {
		t.Fatalf("ensurePathCounter: %v", err)
	}
}

// assertServerCounter checks one server path counter. A want of nil means no
// entry.
func assertServerCounter(t *testing.T, collection *ebpf.Collection, key mupPathCounterKeyV1, want *PathCounter) {
	t.Helper()
	got, ok, err := readServerPathCounter(collection.Maps["server_path_counters"], key)
	if err != nil {
		t.Fatalf("read server path counter: %v", err)
	}
	if want == nil {
		if ok {
			t.Errorf("server path counter of path %d direction %d = %+v, want no entry", key.PathId, key.Direction, got)
		}
		return
	}
	if !ok || got != *want {
		t.Errorf("server path counter of path %d direction %d = %+v (entry %v), want %+v", key.PathId, key.Direction, got, ok, *want)
	}
}

func serverCounterEntries(t *testing.T, collection *ebpf.Collection) uint64 {
	t.Helper()
	count, err := countEntries[mupPathCounterKeyV1, []mupPathCounterV1](collection.Maps["server_path_counters"], "server path counters")
	if err != nil {
		t.Fatal(err)
	}
	return count
}

// withMessageCounter writes counter into the WireGuard counter field of a UDP
// or ICMP WireGuard frame and fixes its checksum. The server drops a second
// packet of a route with the same first 24 WireGuard bytes as a duplicate, so
// each packet of a test that must pass needs its own counter.
func withMessageCounter(frame []byte, counter uint64) []byte {
	frame = append([]byte(nil), frame...)
	ip := frame[14:]
	l4 := ip[20:binary.BigEndian.Uint16(ip[2:4])]
	// The WireGuard message starts after the 8-byte UDP or ICMP header, and
	// its counter is at message bytes 8 to 15.
	binary.LittleEndian.PutUint64(l4[8+8:8+16], counter)
	if ip[9] == protocol.IPProtocolICMP {
		l4[2], l4[3] = 0, 0
		binary.BigEndian.PutUint16(l4[2:4], onesComplement(l4, 0))
	} else {
		l4[6], l4[7] = 0, 0
		binary.BigEndian.PutUint16(l4[6:8], onesComplement(l4, pseudoHeaderSum(ip)))
	}
	return frame
}

// udpControlFrame is udpWireGuardFrame with a 48-byte MUPC control frame in
// place of the WireGuard message.
func udpControlFrame(t *testing.T, source, destination netip.Addr, sourcePort, destinationPort uint16) []byte {
	t.Helper()
	frame := udpWireGuardFrame(t, source, destination, sourcePort, destinationPort, 0)
	ip := frame[14:]
	udp := ip[20:]
	if err := protocol.EncodeControlFrame(udp[8:], protocol.ControlFrame{
		Type:          protocol.ControlRegister,
		Transport:     protocol.TransportUDP,
		ListenPort:    51820,
		ServerPort:    5000,
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		InstanceNonce: 7,
	}); err != nil {
		t.Fatalf("encode control frame: %v", err)
	}
	udp[6], udp[7] = 0, 0
	binary.BigEndian.PutUint16(udp[6:8], onesComplement(udp, pseudoHeaderSum(ip)))
	return frame
}

func TestClientCountsAnIngressPacketOnItsPathSlot(t *testing.T) {
	collection := srcClientCollection(t, protocol.TransportUDP, 0, 0)
	defer collection.Close()
	frame := udpWireGuardFrame(t, zeroUser, zeroAdvertised, 40000, 51820, 0)
	for range 2 {
		result, output := runProgram(t, collection, "mup_client_ingress", frame)
		if result != tcActRedirect {
			t.Fatalf("return value = %d, want the redirect", int32(result))
		}
		if ipv4Length(output) != ipv4Length(frame) {
			t.Fatalf("output length = %d, want %d", ipv4Length(output), ipv4Length(frame))
		}
	}
	assertClientCounters(t, collection, map[uint32]PathCounter{
		srcSlot: {Packets: 2, Bytes: 2 * ipv4Length(frame)},
	})
}

// repeaterClientCollection loads a client whose group 51820 sends each packet
// on the healthy slots 0 and 2. Token 5 is free.
func repeaterClientCollection(t *testing.T) *ebpf.Collection {
	t.Helper()
	collection := loadTestCollection(t)
	put := func(name string, key, value any) {
		t.Helper()
		if err := collection.Maps[name].Update(key, value, ebpf.UpdateAny); err != nil {
			t.Fatalf("update %s: %v", name, err)
		}
	}
	advertised := mustTestWord(t, zeroAdvertised)
	put("client_config", uint32(0), mupClientConfigV1{InstanceNonce: 7, AdvertisedIp: advertised})
	put("path_groups", uint16(51820), mupPathGroupV1{Mode: 2, PathMask: 0b101})
	for _, slot := range []uint32{0, 2} {
		put("path_config", slot, mupPathConfigV1{
			DestinationIp: mustTestWord(t, zeroServer), SourceIp: advertised,
			Ifindex: 1, ServerPort: 9000 + uint16(slot), Transport: uint8(protocol.TransportUDP),
		})
	}
	put("path_state", uint32(0), mupPathStateV1{HealthyMask: 0b101})
	if err := collection.Maps["free_peer_tokens"].Update(nil, uint32(5), ebpf.UpdateAny); err != nil {
		t.Fatalf("push a peer token: %v", err)
	}
	return collection
}

// The repeater counts the copy on each path. The copy on slot 0 counts even
// when the FIB of the test namespace refuses it, because the rewrite
// succeeded.
func TestClientRepeaterCountsEachCopy(t *testing.T) {
	collection := repeaterClientCollection(t)
	defer collection.Close()
	frame := udpWireGuardFrame(t, zeroUser, zeroAdvertised, 40000, 51820, 0)
	result, output := runProgram(t, collection, "mup_client_ingress", frame)
	if result != tcActRedirect {
		t.Fatalf("return value = %d, want the redirect", int32(result))
	}
	assertUDPHeader(t, output, zeroAdvertised, zeroServer, 51820, 9002)
	one := PathCounter{Packets: 1, Bytes: ipv4Length(frame)}
	assertClientCounters(t, collection, map[uint32]PathCounter{0: one, 2: one})
}

func TestClientCountsAnEgressPacketOnItsEgressSlot(t *testing.T) {
	collection := egressClientCollection(t, 0)
	defer collection.Close()
	pool := icmpWireGuardFrame(t, netip.MustParseAddr("198.51.100.36"), egressClientAdvertised, 0, 9300, 5)
	direct := udpWireGuardFrame(t, egressIngressServer, egressClientAdvertised, 9400, 51820, 5)
	ingress := udpWireGuardFrame(t, egressIngressServer, egressClientAdvertised, 9000, 51820, 5)
	for name, frame := range map[string][]byte{"pool member": pool, "direct server": direct, "ingress path": ingress} {
		if result, _ := runProgram(t, collection, "mup_client_ingress", frame); result != tcActRedirect {
			t.Fatalf("%s: return value = %d, want the redirect", name, int32(result))
		}
	}
	// A reply on the ingress path is no egress packet, and a received packet
	// is no ingress packet.
	assertClientCounters(t, collection, map[uint32]PathCounter{
		8: {Packets: 1, Bytes: ipv4Length(pool)},
		9: {Packets: 1, Bytes: ipv4Length(direct)},
	})
}

// A source that an ingress path and an egress path share counts on the egress
// path, because a group with egress paths gets its replies there.
func TestClientCountsASharedSourceOnTheEgressPath(t *testing.T) {
	collection := egressClientCollection(t, 0)
	defer collection.Close()
	if err := collection.Maps["client_down_paths"].Update(uint32(1), mupClientDownPathV1{
		ServerIp: mustTestWord(t, egressIngressServer), ServerPort: 9000, Transport: uint8(protocol.TransportUDP),
	}, ebpf.UpdateAny); err != nil {
		t.Fatalf("update egress path 1: %v", err)
	}
	frame := udpWireGuardFrame(t, egressIngressServer, egressClientAdvertised, 9000, 51820, 5)
	if result, _ := runProgram(t, collection, "mup_client_ingress", frame); result != tcActRedirect {
		t.Fatalf("return value = %d, want the redirect", int32(result))
	}
	assertClientCounters(t, collection, map[uint32]PathCounter{9: {Packets: 1, Bytes: ipv4Length(frame)}})
}

func TestServerIngressCountsADataPacketOfARegisteredPath(t *testing.T) {
	collection, client := targetIngressCollection(t)
	defer collection.Close()
	if err := collection.Maps["free_target_ports"].Update(nil, uint16(20000), ebpf.UpdateAny); err != nil {
		t.Fatalf("push a target port: %v", err)
	}
	program := collection.Programs["mup_server_ingress"]
	packet := udpWireGuardFrame(t, ingressClient, ingressTarget, 51821, 5000, 9)

	// Without a counter of the path, the packet creates none.
	if result, _, err := program.Test(withMessageCounter(packet, 1)); err != nil || result != tcActRedirect {
		t.Fatalf("return value = %d (%v), want the redirect", int32(result), err)
	}
	if entries := serverCounterEntries(t, collection); entries != 0 {
		t.Fatalf("server path counters = %d, want none", entries)
	}

	ingress := serverCounterKey(client, 0, PathCounterIngress)
	egress := serverCounterKey(client, 0, PathCounterEgress)
	ensureTestServerCounter(t, collection, ingress)
	ensureTestServerCounter(t, collection, egress)
	// Each packet has its own WireGuard counter, so none is a duplicate.
	for counter := range uint64(3) {
		if result, _, err := program.Test(withMessageCounter(packet, counter+2)); err != nil || result != tcActRedirect {
			t.Fatalf("packet %d: return value = %d (%v), want the redirect", counter+2, int32(result), err)
		}
	}
	// The count comes before the duplicate check, so a duplicate that the
	// server drops still counts.
	before := dropCount(t, collection, protocol.DropDuplicate)
	if result, _, err := program.Test(withMessageCounter(packet, 4)); err != nil || result != tcActShot {
		t.Fatalf("duplicate: return value = %d (%v), want the drop", int32(result), err)
	}
	if after := dropCount(t, collection, protocol.DropDuplicate); after != before+1 {
		t.Fatalf("DUPLICATE drops %d to %d, want one more", before, after)
	}
	assertServerCounter(t, collection, ingress, &PathCounter{Packets: 4, Bytes: 4 * ipv4Length(packet)})
	assertServerCounter(t, collection, egress, &PathCounter{})
	if entries := serverCounterEntries(t, collection); entries != 2 {
		t.Fatalf("server path counters = %d, want the 2 that the test created", entries)
	}
}

// Each member of an ingress reflect pool has its own registered entry with the
// path ID of the path, and all of them count on that one path.
func TestServerIngressCountsEveryReflectMemberOnThePath(t *testing.T) {
	collection, client := targetIngressCollection(t)
	defer collection.Close()
	if err := collection.Maps["free_target_ports"].Update(nil, uint16(20000), ebpf.UpdateAny); err != nil {
		t.Fatalf("push a target port: %v", err)
	}
	const pathID = 3
	for _, member := range []netip.Addr{ingressViaA, ingressViaB} {
		key := mupRegisteredPathKeyV1{
			SourceIp: mustTestWord(t, member), LocalIp: mustTestWord(t, ingressTarget),
			ServerPort: 5000, Transport: uint8(protocol.TransportICMP),
		}
		value := mupRegisteredPathValueV1{
			Client: client, ExpiresAtNs: math.MaxUint64, PathId: pathID,
			Flags: protocol.ControlFlagIngressReflect, ListenPort: 51821,
		}
		if err := collection.Maps["registered_paths"].Update(key, value, ebpf.UpdateAny); err != nil {
			t.Fatalf("update registered path of %s: %v", member, err)
		}
	}
	key := serverCounterKey(client, pathID, PathCounterIngress)
	ensureTestServerCounter(t, collection, key)
	var bytes uint64
	for index, member := range []netip.Addr{ingressViaA, ingressViaB} {
		// Both members carry packets of one route, so each needs its own
		// WireGuard counter to pass the duplicate check.
		reply := withMessageCounter(icmpWireGuardFrame(t, member, ingressTarget, 0, 5000, 9), uint64(index+1))
		if result, _, err := collection.Programs["mup_server_ingress"].Test(reply); err != nil || result != tcActRedirect {
			t.Fatalf("%s: return value = %d (%v), want the redirect", member, int32(result), err)
		}
		bytes += ipv4Length(reply)
	}
	assertServerCounter(t, collection, key, &PathCounter{Packets: 2, Bytes: bytes})
	assertServerCounter(t, collection, serverCounterKey(client, 0, PathCounterIngress), nil)
}

// The repeater counts each copy on its egress path. A path without a counter
// gets none.
func TestServerEgressCountsEachCopy(t *testing.T) {
	collection := egressReplyCollection(t, 2, 0b11)
	defer collection.Close()
	client := mupClientKeyV1{AdvertisedIp: mustTestWord(t, ingressClient), InstanceNonce: 7}
	reply := udpWireGuardFrame(t, ingressTarget, ingressClient, ingressTargetPort, 20000, 0)
	path0 := serverCounterKey(client, 0, PathCounterEgress)
	path1 := serverCounterKey(client, 1, PathCounterEgress)
	ensureTestServerCounter(t, collection, path0)
	ensureTestServerCounter(t, collection, path1)
	result, output := targetReply(t, collection)
	if result != tcActOK && result != tcActRedirect {
		t.Fatalf("return value = %d, want pass or redirect", int32(result))
	}
	// The packet itself leaves on path 1, an ICMP path whose header has the
	// size of the UDP header, so both copies keep the length of the reply.
	if ipv4Length(output) != ipv4Length(reply) {
		t.Fatalf("output length = %d, want %d", ipv4Length(output), ipv4Length(reply))
	}
	one := PathCounter{Packets: 1, Bytes: ipv4Length(reply)}
	assertServerCounter(t, collection, path0, &one)
	assertServerCounter(t, collection, path1, &one)
	assertServerCounter(t, collection, serverCounterKey(client, 0, PathCounterIngress), nil)

	// Without its counter, path 0 still sends and counts nothing.
	if err := collection.Maps["server_path_counters"].Delete(path0); err != nil {
		t.Fatalf("delete counter of path 0: %v", err)
	}
	if result, _ = targetReply(t, collection); result != tcActOK && result != tcActRedirect {
		t.Fatalf("second reply: return value = %d, want pass or redirect", int32(result))
	}
	assertServerCounter(t, collection, path0, nil)
	assertServerCounter(t, collection, path1, &PathCounter{Packets: 2, Bytes: 2 * ipv4Length(reply)})
}

// A bridge path counts the outer length of the wrapped reply.
func TestServerEgressCountsTheWrappedLengthOfABridgePath(t *testing.T) {
	client := mupClientKeyV1{AdvertisedIp: mustTestWord(t, ingressClient), InstanceNonce: 7}
	reply := udpWireGuardFrame(t, ingressTarget, ingressClient, ingressTargetPort, 20000, 0)
	path0 := serverCounterKey(client, 0, PathCounterEgress)
	path1 := serverCounterKey(client, 1, PathCounterEgress)

	// Failover with only path 0 sends the reply through the bridge.
	collection := egressBridgeCollection(t, 0, 0b01)
	ensureTestServerCounter(t, collection, path0)
	result, output := targetReply(t, collection)
	if result != tcActOK && result != tcActRedirect {
		t.Fatalf("failover: return value = %d, want pass or redirect", int32(result))
	}
	if ipv4Length(output) != ipv4Length(reply)+uint64(protocol.BridgeOverhead) {
		t.Fatalf("failover: output length = %d, want the wrapped length %d", ipv4Length(output), ipv4Length(reply)+uint64(protocol.BridgeOverhead))
	}
	assertServerCounter(t, collection, path0, &PathCounter{Packets: 1, Bytes: ipv4Length(output)})
	collection.Close()

	// The repeater wraps the copy on path 0 and sends the packet itself on
	// the direct path 1.
	collection = egressBridgeCollection(t, 2, 0b11)
	defer collection.Close()
	ensureTestServerCounter(t, collection, path0)
	ensureTestServerCounter(t, collection, path1)
	if result, _ = targetReply(t, collection); result != tcActOK && result != tcActRedirect {
		t.Fatalf("repeater: return value = %d, want pass or redirect", int32(result))
	}
	assertServerCounter(t, collection, path0, &PathCounter{Packets: 1, Bytes: ipv4Length(reply) + uint64(protocol.BridgeOverhead)})
	assertServerCounter(t, collection, path1, &PathCounter{Packets: 1, Bytes: ipv4Length(reply)})
}

func TestAControlFrameChangesNoCounter(t *testing.T) {
	// The client: a frame of the local WireGuard to the listen port, and a
	// frame from the direct egress path.
	clientCollection := egressClientCollection(t, 0)
	defer clientCollection.Close()
	for _, frame := range [][]byte{
		udpControlFrame(t, egressPeer, egressClientAdvertised, 40000, 51820),
		udpControlFrame(t, egressIngressServer, egressClientAdvertised, 9400, 51820),
	} {
		runProgram(t, clientCollection, "mup_client_ingress", frame)
	}
	assertClientCounters(t, clientCollection, nil)

	// The server: a frame on the registered path of the client.
	serverCollection, client := targetIngressCollection(t)
	defer serverCollection.Close()
	key := serverCounterKey(client, 0, PathCounterIngress)
	ensureTestServerCounter(t, serverCollection, key)
	runProgram(t, serverCollection, "mup_server_ingress", udpControlFrame(t, ingressClient, ingressTarget, 51821, 5000))
	assertServerCounter(t, serverCollection, key, &PathCounter{})
}
