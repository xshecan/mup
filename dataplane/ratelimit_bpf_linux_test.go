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

// The program tests run many packets within microseconds, so a bucket of
// limitTestRate empties after its burst of 3000 bytes, and gets no room back
// during a test. A test that needs "time has passed" writes the bucket.
const (
	limitTestRate = 8_000
	// limitHugeRate never runs out of room in a test.
	limitHugeRate = 100_000_000_000
	// limitFullTat is a theoretical arrival time far in the future, so the
	// bucket has no room.
	limitFullTat = math.MaxUint64 / 2
)

func putMapEntry(t *testing.T, collection *ebpf.Collection, name string, key, value any) {
	t.Helper()
	if err := collection.Maps[name].Update(key, value, ebpf.UpdateAny); err != nil {
		t.Fatalf("update %s: %v", name, err)
	}
}

// testBucket is a bucket of rate with the theoretical arrival time tat.
func testBucket(rate, tat uint64) mupRateBucketV1 {
	bucket := rateBucket(RateLimit{BitsPerSecond: rate})
	bucket.TatNs = tat
	return bucket
}

// limitClientCollection loads a client whose group 51820 has the mode and a
// healthy UDP path on each slot of priorities, with that priority. The path
// of slot S goes to server port 9000 + S. Tokens 1 to tokens are free, in that
// order, so the peer of source port 41000 + N takes token N + 1.
func limitClientCollection(t *testing.T, mode uint8, priorities map[uint32]uint8, tokens int) *ebpf.Collection {
	t.Helper()
	collection := loadTestCollection(t)
	advertised := mustTestWord(t, zeroAdvertised)
	var mask uint8
	for slot, priority := range priorities {
		mask |= 1 << slot
		putMapEntry(t, collection, "path_config", slot, mupPathConfigV1{
			DestinationIp: mustTestWord(t, zeroServer), SourceIp: advertised,
			Ifindex: 1, ServerPort: 9000 + uint16(slot), Transport: uint8(protocol.TransportUDP),
			Priority: priority, Weight: 1,
		})
	}
	putMapEntry(t, collection, "client_config", uint32(0), mupClientConfigV1{InstanceNonce: 7, AdvertisedIp: advertised})
	putMapEntry(t, collection, "path_groups", uint16(51820), mupPathGroupV1{Mode: mode, PathMask: mask})
	putMapEntry(t, collection, "path_state", uint32(0), mupPathStateV1{HealthyMask: uint32(mask)})
	for token := range uint32(tokens) {
		if err := collection.Maps["free_peer_tokens"].Update(nil, token+1, ebpf.UpdateAny); err != nil {
			t.Fatalf("push peer token %d: %v", token+1, err)
		}
	}
	return collection
}

// limitClientPath gives client path slot a limit of rate with the limit bits
// flags, and a weight, and an empty bucket.
func limitClientPath(t *testing.T, collection *ebpf.Collection, slot uint32, flags, weight uint8, rate uint64) {
	t.Helper()
	var path mupPathConfigV1
	if err := collection.Maps["path_config"].Lookup(slot, &path); err != nil {
		t.Fatalf("read path %d: %v", slot, err)
	}
	path.Limit, path.Weight = flags, weight
	putMapEntry(t, collection, "path_config", slot, path)
	pathIndex, memberBase := clientBucketIndexes(int(slot))
	if flags == limitFlagPath {
		putMapEntry(t, collection, "client_rate_buckets", pathIndex, testBucket(rate, 0))
		return
	}
	for member := range uint32(MaxPool) {
		putMapEntry(t, collection, "client_rate_buckets", memberBase+member, testBucket(rate, 0))
	}
}

// fillClientBucket leaves no room in the bucket at index.
func fillClientBucket(t *testing.T, collection *ebpf.Collection, index uint32) {
	t.Helper()
	putMapEntry(t, collection, "client_rate_buckets", index, testBucket(limitTestRate, limitFullTat))
}

func udpDestinationPort(t *testing.T, frame []byte) uint16 {
	t.Helper()
	ip := frame[14:]
	if ip[9] != protocol.IPProtocolUDP {
		t.Fatalf("protocol = %d, want UDP", ip[9])
	}
	return binary.BigEndian.Uint16(ip[20+2 : 20+4])
}

// sendClientPacket sends one packet of the peer at source port port and
// returns the server port of the path that carried it, or 0 for a drop.
func sendClientPacket(t *testing.T, collection *ebpf.Collection, port uint16) uint16 {
	t.Helper()
	frame := udpWireGuardFrame(t, zeroUser, zeroAdvertised, port, 51820, 0)
	result, output := runProgram(t, collection, "mup_client_ingress", frame)
	if result == tcActShot {
		return 0
	}
	if result != tcActRedirect {
		t.Fatalf("return value = %d, want the redirect or a drop", int32(result))
	}
	return udpDestinationPort(t, output)
}

// burstPackets is the number of packets of frame that fit the burst of a
// bucket of limitTestRate. A packet that the test runs later gets the room of
// the time that passed, which is far below one byte for each packet.
func burstPackets(frame []byte) int {
	cost, burst := encodeRate(limitTestRate)
	return int(burst / (ipv4Length(frame) * cost >> 16))
}

// A failover group takes its paths in the order of their priority. Slot 1
// comes first, then slot 2, then slot 0. Slot 1 sends until its burst is used,
// and the rest spills to slot 2, which has no limit and never refuses.
func TestClientSpillsToTheNextPathByPriority(t *testing.T) {
	collection := limitClientCollection(t, 0, map[uint32]uint8{0: 2, 1: 0, 2: 1}, 1)
	defer collection.Close()
	limitClientPath(t, collection, 1, limitFlagPath, 1, limitTestRate)
	frame := udpWireGuardFrame(t, zeroUser, zeroAdvertised, 41000, 51820, 0)
	burst := burstPackets(frame)

	limited := 0
	for range burst + 2 {
		if port := sendClientPacket(t, collection, 41000); port == 9001 {
			limited++
		} else if port != 9002 {
			t.Fatalf("server port = %d, want 9001 or the next path by priority 9002", port)
		}
	}
	if limited < burst || limited > burst+1 {
		t.Fatalf("slot 1 sent %d packets, want its burst of %d", limited, burst)
	}
	for range 50 {
		if port := sendClientPacket(t, collection, 41000); port != 9002 {
			t.Fatalf("server port = %d, want the path without a limit 9002", port)
		}
	}
	// Each packet counts on the path that carried it.
	length := ipv4Length(frame)
	assertClientCounters(t, collection, map[uint32]PathCounter{
		1: {Packets: uint64(limited), Bytes: uint64(limited) * length},
		2: {Packets: uint64(burst + 52 - limited), Bytes: uint64(burst+52-limited) * length},
	})

	// Room again: slot 1 takes the packets back.
	pathIndex, _ := clientBucketIndexes(1)
	putMapEntry(t, collection, "client_rate_buckets", pathIndex, testBucket(limitTestRate, 0))
	if port := sendClientPacket(t, collection, 41000); port != 9001 {
		t.Fatalf("server port = %d after the bucket emptied, want 9001", port)
	}
}

func TestClientDropsAPacketThatNoPathHasRoomFor(t *testing.T) {
	collection := limitClientCollection(t, 0, map[uint32]uint8{0: 0, 1: 1}, 1)
	defer collection.Close()
	for _, slot := range []uint32{0, 1} {
		limitClientPath(t, collection, slot, limitFlagPath, 1, limitTestRate)
		fillClientBucket(t, collection, slot)
	}
	before := dropCount(t, collection, protocol.DropRateLimit)
	if port := sendClientPacket(t, collection, 41000); port != 0 {
		t.Fatalf("server port = %d, want a drop", port)
	}
	if after := dropCount(t, collection, protocol.DropRateLimit); after != before+1 {
		t.Fatalf("RATE_LIMIT drops %d to %d, want one more", before, after)
	}
	assertClientCounters(t, collection, nil)
}

// clientBalancerSlot is the slot that select_client_path gives a token among
// the slots of usable, in slot order.
func clientBalancerSlot(token, usable uint32) uint32 {
	var slots []uint32
	for slot := range uint32(8) {
		if usable&(1<<slot) != 0 {
			slots = append(slots, slot)
		}
	}
	hash := token*0x9e3779b1 ^ usable*0x85ebca6b
	hash ^= hash >> 16
	return slots[hash%uint32(len(slots))]
}

// With equal weights the plan of a limited group places each peer on the path
// that the hash gave before the limits, as a group without a limit does.
func TestClientBalancerWithEqualWeightsKeepsThePlacementOfItsPeers(t *testing.T) {
	const peers = 64
	for _, limited := range []bool{false, true} {
		collection := limitClientCollection(t, 1, map[uint32]uint8{0: 0, 1: 0, 3: 0}, peers)
		if limited {
			for _, slot := range []uint32{0, 1, 3} {
				limitClientPath(t, collection, slot, limitFlagPath, 2, limitHugeRate)
			}
		}
		for peer := range uint16(peers) {
			want := 9000 + uint16(clientBalancerSlot(uint32(peer)+1, 0b1011))
			if port := sendClientPacket(t, collection, 41000+peer); port != want {
				t.Fatalf("limited %v, token %d: server port = %d, want %d", limited, peer+1, port, want)
			}
		}
		collection.Close()
	}
}

// When every path has a limit and their weights differ, the shares of the
// peers follow the weights.
func TestClientBalancerSharesThePeersByTheWeights(t *testing.T) {
	const peers = 400
	collection := limitClientCollection(t, 1, map[uint32]uint8{0: 0, 1: 0}, peers)
	defer collection.Close()
	limitClientPath(t, collection, 0, limitFlagPath, 1, limitHugeRate)
	limitClientPath(t, collection, 1, limitFlagPath, 3, limitHugeRate)
	heavy := 0
	for peer := range uint16(peers) {
		switch port := sendClientPacket(t, collection, 41000+peer); port {
		case 9001:
			heavy++
		case 9000:
		default:
			t.Fatalf("server port = %d, want 9000 or 9001", port)
		}
	}
	if share := float64(heavy) / peers; share < 0.65 || share > 0.85 {
		t.Fatalf("the path of weight 3 has %.2f of the peers, want about 0.75", share)
	}
}

// A balancer path without room spills to the other path.
func TestClientBalancerSpillsAFullPath(t *testing.T) {
	collection := limitClientCollection(t, 1, map[uint32]uint8{0: 0, 1: 0}, 1)
	defer collection.Close()
	for _, slot := range []uint32{0, 1} {
		limitClientPath(t, collection, slot, limitFlagPath, 1, limitTestRate)
	}
	hashed := clientBalancerSlot(1, 0b11)
	fillClientBucket(t, collection, hashed)
	if port := sendClientPacket(t, collection, 41000); port != 9000+uint16(1-hashed) {
		t.Fatalf("server port = %d, want the other path %d", port, 9000+1-hashed)
	}
}

// A repeater skips the copy of a path without room, and drops the packet with
// one RATE_LIMIT count when no path has room.
func TestClientRepeaterSkipsACopyWithoutRoom(t *testing.T) {
	collection := limitClientCollection(t, 2, map[uint32]uint8{0: 0, 2: 0}, 1)
	defer collection.Close()
	frame := udpWireGuardFrame(t, zeroUser, zeroAdvertised, 41000, 51820, 0)
	limitClientPath(t, collection, 2, limitFlagPath, 1, limitTestRate)
	fillClientBucket(t, collection, 2)
	// The packet itself goes on the highest path with room.
	if port := sendClientPacket(t, collection, 41000); port != 9000 {
		t.Fatalf("server port = %d, want slot 0", port)
	}
	assertClientCounters(t, collection, map[uint32]PathCounter{0: {Packets: 1, Bytes: ipv4Length(frame)}})

	limitClientPath(t, collection, 0, limitFlagPath, 1, limitTestRate)
	fillClientBucket(t, collection, 0)
	before := dropCount(t, collection, protocol.DropRateLimit)
	if port := sendClientPacket(t, collection, 41000); port != 0 {
		t.Fatalf("server port = %d, want a drop", port)
	}
	if after := dropCount(t, collection, protocol.DropRateLimit); after != before+1 {
		t.Fatalf("RATE_LIMIT drops %d to %d, want one more", before, after)
	}
	assertClientCounters(t, collection, map[uint32]PathCounter{0: {Packets: 1, Bytes: ipv4Length(frame)}})
}

// memberStart is the member that the per-peer hash of a token gives among
// count members.
func memberStart(token, count uint32) uint32 {
	hash := token * 0x9e3779b1
	hash ^= hash >> 16
	return hash % count
}

// A limit per member moves an ingress reflect packet to the next member while
// a member has no room, and the path has no room when no member has.
func TestClientMovesToTheNextMemberWithRoom(t *testing.T) {
	members := []netip.Addr{ingressViaA, ingressViaB}
	collection := ingressReflectClientCollection(t, protocol.TransportICMP, members, false)
	defer collection.Close()
	limitClientPath(t, collection, 0, limitFlagMember, 1, limitTestRate)
	frame := udpWireGuardFrame(t, ingressPeer, ingressAdvertised, 40000, 51820, 0)

	// Token 5 starts at its hash member.
	start := memberStart(5, 2)
	result, output := runProgram(t, collection, "mup_client_ingress", frame)
	if result != tcActRedirect {
		t.Fatalf("return value = %d, want the redirect", int32(result))
	}
	assertIngressReflectICMP(t, output, members[start])

	_, memberBase := clientBucketIndexes(0)
	fillClientBucket(t, collection, memberBase+start)
	result, output = runProgram(t, collection, "mup_client_ingress", frame)
	if result != tcActRedirect {
		t.Fatalf("return value = %d, want the redirect", int32(result))
	}
	assertIngressReflectICMP(t, output, members[1-start])

	fillClientBucket(t, collection, memberBase+1-start)
	before := dropCount(t, collection, protocol.DropRateLimit)
	if result, _ = runProgram(t, collection, "mup_client_ingress", frame); result != tcActShot {
		t.Fatalf("return value = %d, want a drop", int32(result))
	}
	if after := dropCount(t, collection, protocol.DropRateLimit); after != before+1 {
		t.Fatalf("RATE_LIMIT drops %d to %d, want one more", before, after)
	}
}

// limitEgressPath gives egress path pathID of the test client the limit bits
// flags and empty buckets of rate, and writes the limit mask of its group.
func limitEgressPath(t *testing.T, collection *ebpf.Collection, pathID uint32, flags uint8, rate uint64) {
	t.Helper()
	client := mupClientKeyV1{AdvertisedIp: mustTestWord(t, ingressClient), InstanceNonce: 7}
	key := mupDownPathKeyV1{Client: client, PathId: pathID}
	var path mupDownPathV1
	if err := collection.Maps["server_down_paths"].Lookup(key, &path); err != nil {
		t.Fatalf("read egress path %d: %v", pathID, err)
	}
	path.Limit = flags
	putMapEntry(t, collection, "server_down_paths", key, path)
	members := uint32(1)
	if flags == limitFlagMember {
		members = MaxPool
	}
	for member := range members {
		putMapEntry(t, collection, "server_rate_buckets", rateBucketKey(key, member), testBucket(rate, 0))
	}
	updateEgressGroup(t, collection, func(group *mupDownGroupV1) { group.LimitMask |= 1 << pathID })
}

func updateEgressGroup(t *testing.T, collection *ebpf.Collection, change func(*mupDownGroupV1)) {
	t.Helper()
	client := mupClientKeyV1{AdvertisedIp: mustTestWord(t, ingressClient), InstanceNonce: 7}
	key := mupDownGroupKeyV1{Client: client, ListenPort: 51821}
	var group mupDownGroupV1
	if err := collection.Maps["server_down_groups"].Lookup(key, &group); err != nil {
		t.Fatalf("read egress group: %v", err)
	}
	change(&group)
	putMapEntry(t, collection, "server_down_groups", key, group)
}

// fillEgressBucket leaves no room in a bucket of the test client.
func fillEgressBucket(t *testing.T, collection *ebpf.Collection, pathID, member uint32) {
	t.Helper()
	client := mupClientKeyV1{AdvertisedIp: mustTestWord(t, ingressClient), InstanceNonce: 7}
	key := mupDownPathKeyV1{Client: client, PathId: pathID}
	putMapEntry(t, collection, "server_rate_buckets", rateBucketKey(key, member), testBucket(limitTestRate, limitFullTat))
}

func assertReplyLeaves(t *testing.T, result uint32) {
	t.Helper()
	if result != tcActOK && result != tcActRedirect {
		t.Fatalf("return value = %d, want pass or redirect", int32(result))
	}
}

// A failover group sends on path 0 until its burst is used, and then spills to
// path 1. The program tests send far faster than the rate, so the bucket gets
// no room back.
func TestServerFailoverSpillsToTheNextEgressPath(t *testing.T) {
	collection := egressReplyCollection(t, 0, 0b11)
	defer collection.Close()
	limitEgressPath(t, collection, 0, limitFlagPath, limitTestRate)
	reply := udpWireGuardFrame(t, ingressTarget, ingressClient, ingressTargetPort, 20000, 0)
	burst := burstPackets(reply)
	direct := 0
	for range burst + 2 {
		result, output := targetReply(t, collection)
		assertReplyLeaves(t, result)
		if output[14+9] == protocol.IPProtocolUDP {
			assertUDPHeader(t, output, egressDirectServer, ingressClient, 9200, 51821)
			direct++
		} else {
			assertReflectedICMP(t, output)
		}
	}
	if direct < burst || direct > burst+1 {
		t.Fatalf("path 0 sent %d replies, want its burst of %d", direct, burst)
	}
}

// The failover mode tries the preferred path first, and spills from it to the
// paths by ID.
func TestServerFailoverHonorsThePreferredPath(t *testing.T) {
	collection := egressReplyCollection(t, 0, 0b11)
	defer collection.Close()
	updateEgressGroup(t, collection, func(group *mupDownGroupV1) {
		group.Flags = downGroupFlagPreferred
		group.Preferred = 1
	})
	result, output := targetReply(t, collection)
	assertReplyLeaves(t, result)
	assertReflectedICMP(t, output)

	limitEgressPath(t, collection, 1, limitFlagPath, limitTestRate)
	fillEgressBucket(t, collection, 1, 0)
	result, output = targetReply(t, collection)
	assertReplyLeaves(t, result)
	assertUDPHeader(t, output, egressDirectServer, ingressClient, 9200, 51821)

	// A preferred path that is not healthy leaves the other paths, and no
	// room on them drops the reply.
	updateEgressGroup(t, collection, func(group *mupDownGroupV1) { group.Preferred = 0; group.HealthyMask = 0b10 })
	fillEgressBucket(t, collection, 1, 0)
	before := dropCount(t, collection, protocol.DropRateLimit)
	if result, _ = targetReply(t, collection); result != tcActShot {
		t.Fatalf("return value = %d, want a drop", int32(result))
	}
	if after := dropCount(t, collection, protocol.DropRateLimit); after != before+1 {
		t.Fatalf("RATE_LIMIT drops %d to %d, want one more", before, after)
	}
}

// A repeater skips the copy of an egress path without room, and that copy
// counts on no path. With no room anywhere, the reply is dropped once.
func TestServerRepeaterSkipsACopyWithoutRoom(t *testing.T) {
	collection := egressReplyCollection(t, 2, 0b11)
	defer collection.Close()
	client := mupClientKeyV1{AdvertisedIp: mustTestWord(t, ingressClient), InstanceNonce: 7}
	path0 := serverCounterKey(client, 0, PathCounterEgress)
	path1 := serverCounterKey(client, 1, PathCounterEgress)
	ensureTestServerCounter(t, collection, path0)
	ensureTestServerCounter(t, collection, path1)
	reply := udpWireGuardFrame(t, ingressTarget, ingressClient, ingressTargetPort, 20000, 0)

	limitEgressPath(t, collection, 1, limitFlagPath, limitTestRate)
	fillEgressBucket(t, collection, 1, 0)
	result, output := targetReply(t, collection)
	assertReplyLeaves(t, result)
	assertUDPHeader(t, output, egressDirectServer, ingressClient, 9200, 51821)
	assertServerCounter(t, collection, path0, &PathCounter{Packets: 1, Bytes: ipv4Length(reply)})
	assertServerCounter(t, collection, path1, &PathCounter{})

	limitEgressPath(t, collection, 0, limitFlagPath, limitTestRate)
	fillEgressBucket(t, collection, 0, 0)
	fillEgressBucket(t, collection, 1, 0)
	before := dropCount(t, collection, protocol.DropRateLimit)
	if result, _ = targetReply(t, collection); result != tcActShot {
		t.Fatalf("return value = %d, want a drop", int32(result))
	}
	if after := dropCount(t, collection, protocol.DropRateLimit); after != before+1 {
		t.Fatalf("RATE_LIMIT drops %d to %d, want one more", before, after)
	}
	assertServerCounter(t, collection, path0, &PathCounter{Packets: 1, Bytes: ipv4Length(reply)})
}

// A limit per member moves a reply to the next pool member while a member has
// no room, and the path has no room when no member has.
func TestServerMovesToTheNextMemberWithRoom(t *testing.T) {
	collection := egressReplyCollection(t, 0, 0b10)
	defer collection.Close()
	limitEgressPath(t, collection, 1, limitFlagMember, limitTestRate)
	members := []netip.Addr{egressMemberA, egressMemberB}
	start := memberStart(9, 2)
	destination := func(frame []byte) netip.Addr { return netip.AddrFrom4([4]byte(frame[14+16 : 14+20])) }

	result, output := targetReply(t, collection)
	assertReplyLeaves(t, result)
	assertReflectedICMP(t, output)
	if got := destination(output); got != members[start] {
		t.Fatalf("member = %s, want the hash member %s", got, members[start])
	}
	fillEgressBucket(t, collection, 1, start)
	result, output = targetReply(t, collection)
	assertReplyLeaves(t, result)
	if got := destination(output); got != members[1-start] {
		t.Fatalf("member = %s, want the next member %s", got, members[1-start])
	}
	fillEgressBucket(t, collection, 1, 1-start)
	before := dropCount(t, collection, protocol.DropRateLimit)
	if result, _ = targetReply(t, collection); result != tcActShot {
		t.Fatalf("return value = %d, want a drop", int32(result))
	}
	if after := dropCount(t, collection, protocol.DropRateLimit); after != before+1 {
		t.Fatalf("RATE_LIMIT drops %d to %d, want one more", before, after)
	}
}

// The balancer of a group without limits and weights keeps the hash of
// before, and a limited path of the hash spills to the other path.
func TestServerBalancerSpillsAFullPath(t *testing.T) {
	collection := egressReplyCollection(t, 1, 0b11)
	defer collection.Close()
	token, mask := uint32(9), uint32(0b11)
	hash := token*0x9e3779b1 ^ mask*0x85ebca6b
	hash ^= hash >> 16
	hashed := hash % 2
	limitEgressPath(t, collection, 0, limitFlagPath, limitHugeRate)
	limitEgressPath(t, collection, 1, limitFlagPath, limitHugeRate)
	isPath := func(output []byte, pathID uint32) bool {
		return (output[14+9] == protocol.IPProtocolUDP) == (pathID == 0)
	}

	result, output := targetReply(t, collection)
	assertReplyLeaves(t, result)
	if !isPath(output, hashed) {
		t.Fatalf("the reply left on path %d, want the hash path %d", 1-hashed, hashed)
	}
	fillEgressBucket(t, collection, hashed, 0)
	result, output = targetReply(t, collection)
	assertReplyLeaves(t, result)
	if !isPath(output, 1-hashed) {
		t.Fatalf("the reply left on the full path %d, want the other path", hashed)
	}
}
