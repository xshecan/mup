//go:build linux

package dataplane

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/protocol"
)

func limitRuntime(collection *ebpf.Collection) *Runtime {
	return &Runtime{objects: mupObjects{mupMaps: mupMaps{
		PathConfig:        collection.Maps["path_config"],
		PathReturns:       collection.Maps["path_returns"],
		UpReflectMembers:  collection.Maps["up_reflect_members"],
		ClientPathSrc:     collection.Maps["client_path_src"],
		ClientRateBuckets: collection.Maps["client_rate_buckets"],
		ServerDownPaths:   collection.Maps["server_down_paths"],
		ServerDownGroups:  collection.Maps["server_down_groups"],
		ServerRateBuckets: collection.Maps["server_rate_buckets"],
	}}}
}

func limitedPath(port uint16, priority uint8, limit RateLimit) PathSettings {
	return PathSettings{
		DestinationIP: netip.MustParseAddr("198.51.100.9"),
		SourceIP:      netip.MustParseAddr("192.0.2.20"),
		Ifindex:       1,
		ServerPort:    port,
		Transport:     protocol.TransportICMP,
		Priority:      priority,
		ReturnIP:      netip.MustParseAddr("198.51.100.40"),
		Limit:         limit,
	}
}

func readClientBucket(t *testing.T, collection *ebpf.Collection, index uint32) mupRateBucketV1 {
	t.Helper()
	var bucket mupRateBucketV1
	if err := collection.Maps["client_rate_buckets"].Lookup(index, &bucket); err != nil {
		t.Fatalf("read client bucket %d: %v", index, err)
	}
	return bucket
}

func readReflectCount(t *testing.T, collection *ebpf.Collection, slot uint32) uint32 {
	t.Helper()
	var reflect mupUpReflectV1
	if err := collection.Maps["up_reflect_members"].Lookup(slot, &reflect); err != nil {
		t.Fatalf("read reflect members of slot %d: %v", slot, err)
	}
	return reflect.Count
}

// A SetPath of the same path on a slot keeps its reflect members and the
// state of its bucket, and writes the new priority. A changed limit starts the
// bucket over, and a new path on the slot also clears its members.
func TestSetPathKeepsTheMembersAndTheBucketOfTheSamePath(t *testing.T) {
	collection := loadTestCollection(t)
	defer collection.Close()
	runtime := limitRuntime(collection)
	const slot = 2
	pathIndex, memberBase := clientBucketIndexes(slot)
	tenMbit := RateLimit{BitsPerSecond: 10_000_000}

	if err := runtime.SetPath(slot, limitedPath(9000, 3, tenMbit)); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	if bucket := readClientBucket(t, collection, pathIndex); !sameBucketLimit(bucket, rateBucket(tenMbit)) || bucket.TatNs != 0 {
		t.Fatalf("bucket = %+v, want a fresh bucket of 10 mbit", bucket)
	}
	if err := runtime.SetIngressReflect(slot, []netip.Addr{netip.MustParseAddr("203.0.113.9")}, false); err != nil {
		t.Fatalf("SetIngressReflect: %v", err)
	}
	used := rateBucket(tenMbit)
	used.TatNs = 12345
	putMapEntry(t, collection, "client_rate_buckets", pathIndex, used)

	// A new priority and weight on the same path.
	rewrite := limitedPath(9000, 0, tenMbit)
	rewrite.Weight = 4
	if err := runtime.SetPath(slot, rewrite); err != nil {
		t.Fatalf("SetPath again: %v", err)
	}
	if count := readReflectCount(t, collection, slot); count != 1 {
		t.Fatalf("reflect members = %d, want the member kept", count)
	}
	if bucket := readClientBucket(t, collection, pathIndex); bucket != used {
		t.Fatalf("bucket = %+v, want it kept as %+v", bucket, used)
	}
	var encoded mupPathConfigV1
	if err := collection.Maps["path_config"].Lookup(uint32(slot), &encoded); err != nil {
		t.Fatalf("read path: %v", err)
	}
	if encoded.Priority != 0 || encoded.Weight != 4 || encoded.Limit != limitFlagPath {
		t.Fatalf("path = %+v, want priority 0, weight 4 and the path limit", encoded)
	}

	// A new rate starts the bucket over and keeps the members.
	twentyMbit := RateLimit{BitsPerSecond: 20_000_000}
	if err := runtime.SetPath(slot, limitedPath(9000, 0, twentyMbit)); err != nil {
		t.Fatalf("SetPath with a new rate: %v", err)
	}
	if bucket := readClientBucket(t, collection, pathIndex); bucket != rateBucket(twentyMbit) {
		t.Fatalf("bucket = %+v, want a fresh bucket of 20 mbit", bucket)
	}
	if count := readReflectCount(t, collection, slot); count != 1 {
		t.Fatalf("reflect members = %d, want the member kept", count)
	}

	// A limit per member moves the bucket to the members.
	perMember := RateLimit{BitsPerSecond: 20_000_000, PerMember: true}
	if err := runtime.SetPath(slot, limitedPath(9000, 0, perMember)); err != nil {
		t.Fatalf("SetPath per member: %v", err)
	}
	if bucket := readClientBucket(t, collection, pathIndex); bucket != (mupRateBucketV1{}) {
		t.Fatalf("path bucket = %+v, want none", bucket)
	}
	for member := range uint32(MaxPool) {
		if bucket := readClientBucket(t, collection, memberBase+member); bucket != rateBucket(perMember) {
			t.Fatalf("bucket of member %d = %+v, want a fresh bucket", member, bucket)
		}
	}

	// Another path on the slot clears the members and starts the buckets
	// over, even with the same limit.
	putMapEntry(t, collection, "client_rate_buckets", memberBase, used)
	if err := runtime.SetPath(slot, limitedPath(9001, 0, perMember)); err != nil {
		t.Fatalf("SetPath of another path: %v", err)
	}
	if count := readReflectCount(t, collection, slot); count != 0 {
		t.Fatalf("reflect members = %d, want them cleared", count)
	}
	if bucket := readClientBucket(t, collection, memberBase); bucket != rateBucket(perMember) {
		t.Fatalf("bucket of member 0 = %+v, want a fresh bucket", bucket)
	}

	// A path without the limit and ClearPath empty the buckets.
	if err := runtime.SetPath(slot, limitedPath(9001, 0, RateLimit{})); err != nil {
		t.Fatalf("SetPath without a limit: %v", err)
	}
	if bucket := readClientBucket(t, collection, memberBase); bucket != (mupRateBucketV1{}) {
		t.Fatalf("bucket of member 0 = %+v, want none", bucket)
	}
	if err := runtime.SetPath(slot, limitedPath(9001, 0, tenMbit)); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	if err := runtime.ClearPath(slot); err != nil {
		t.Fatalf("ClearPath: %v", err)
	}
	if bucket := readClientBucket(t, collection, pathIndex); bucket != (mupRateBucketV1{}) {
		t.Fatalf("bucket after ClearPath = %+v, want none", bucket)
	}
}

// A different return IP or bridge makes another path, so the members go.
func TestSlotHoldsPathComparesTheTargetOfThePath(t *testing.T) {
	collection := loadTestCollection(t)
	defer collection.Close()
	maps := limitRuntime(collection).clientPathMaps()
	base := limitedPath(9000, 1, RateLimit{})
	if err := setClientPath(maps, 0, base); err != nil {
		t.Fatalf("setClientPath: %v", err)
	}
	changes := map[string]func(*PathSettings){
		"priority":  func(path *PathSettings) { path.Priority = 7 },
		"source":    func(path *PathSettings) { path.SourceIP = netip.MustParseAddr("192.0.2.21") },
		"return IP": func(path *PathSettings) { path.ReturnIP = netip.MustParseAddr("198.51.100.41") },
		"pool":      func(path *PathSettings) { path.ReturnPrefix = 28; path.ReturnIP = netip.MustParseAddr("198.51.100.32") },
		"bridge":    func(path *PathSettings) { path.ProxyBridge = netip.MustParseAddr("192.0.2.7") },
		"transport": func(path *PathSettings) { path.Transport = protocol.TransportUDP },
		"server":    func(path *PathSettings) { path.DestinationIP = netip.MustParseAddr("198.51.100.10") },
	}
	for name, change := range changes {
		path := base
		change(&path)
		same, _, err := slotHoldsPath(maps, 0, path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if want := name == "priority" || name == "source"; same != want {
			t.Errorf("%s: same path = %v, want %v", name, same, want)
		}
	}
}

func egressTestEntry(port uint16, limit RateLimit) EgressPathEntry {
	return EgressPathEntry{
		Client:     ClientKey{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), InstanceNonce: 7},
		PathID:     1,
		Server:     netip.MustParseAddr("203.0.113.5"),
		ServerPort: port,
		Transport:  protocol.TransportICMP,
		Ifindex:    1,
		Pool:       true,
		Members:    []netip.Addr{netip.MustParseAddr("198.51.100.40"), netip.MustParseAddr("198.51.100.41")},
		Limit:      limit,
	}
}

func readEgressBucket(t *testing.T, collection *ebpf.Collection, entry EgressPathEntry, member uint32) (mupRateBucketV1, bool) {
	t.Helper()
	key, err := encodeEgressPathKey(entry.Client, entry.PathID)
	if err != nil {
		t.Fatal(err)
	}
	var bucket mupRateBucketV1
	err = collection.Maps["server_rate_buckets"].Lookup(rateBucketKey(key, member), &bucket)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return bucket, false
	}
	if err != nil {
		t.Fatalf("read egress bucket: %v", err)
	}
	return bucket, true
}

func readEgressGroup(t *testing.T, collection *ebpf.Collection, client ClientKey) mupDownGroupV1 {
	t.Helper()
	key, err := encodeEgressGroupKey(client, 51821)
	if err != nil {
		t.Fatal(err)
	}
	var group mupDownGroupV1
	if err := collection.Maps["server_down_groups"].Lookup(key, &group); err != nil {
		t.Fatalf("read egress group: %v", err)
	}
	return group
}

// The server writes its egress paths every 2 seconds. The same limit keeps the
// state of the buckets, and a new limit or a new path starts them over. The
// limit mask of the group follows the paths.
func TestSetServerEgressPathKeepsTheBucketOfTheSameLimit(t *testing.T) {
	collection := loadTestCollection(t)
	defer collection.Close()
	runtime := limitRuntime(collection)
	tenMbit := RateLimit{BitsPerSecond: 10_000_000}
	entry := egressTestEntry(9300, tenMbit)
	group := EgressGroupEntry{Client: entry.Client, ListenPort: 51821, Mode: config.ModeFailover, PathMask: 0b11, HealthyMask: 0b11}
	if err := runtime.SetServerEgressGroup(group); err != nil {
		t.Fatalf("SetServerEgressGroup: %v", err)
	}
	if err := runtime.SetServerEgressPath(entry); err != nil {
		t.Fatalf("SetServerEgressPath: %v", err)
	}
	if mask := readEgressGroup(t, collection, entry.Client).LimitMask; mask != 0b10 {
		t.Fatalf("limit mask = %b, want path 1", mask)
	}
	if bucket, ok := readEgressBucket(t, collection, entry, 0); !ok || bucket != rateBucket(tenMbit) {
		t.Fatalf("bucket = %+v (%v), want a fresh bucket", bucket, ok)
	}
	if _, ok := readEgressBucket(t, collection, entry, 1); ok {
		t.Fatal("a limit of the whole path has a bucket of member 1")
	}
	key, _ := encodeEgressPathKey(entry.Client, entry.PathID)
	used := rateBucket(tenMbit)
	used.TatNs = 777
	putMapEntry(t, collection, "server_rate_buckets", rateBucketKey(key, 0), used)

	// A rewrite with other members keeps the bucket.
	entry.Members = entry.Members[:1]
	if err := runtime.SetServerEgressPath(entry); err != nil {
		t.Fatalf("SetServerEgressPath again: %v", err)
	}
	if bucket, _ := readEgressBucket(t, collection, entry, 0); bucket != used {
		t.Fatalf("bucket = %+v, want it kept as %+v", bucket, used)
	}

	// A limit per member has a bucket for each member index.
	entry.Limit.PerMember = true
	if err := runtime.SetServerEgressPath(entry); err != nil {
		t.Fatalf("SetServerEgressPath per member: %v", err)
	}
	for member := range uint32(MaxPool) {
		if bucket, ok := readEgressBucket(t, collection, entry, member); !ok || bucket != rateBucket(entry.Limit) {
			t.Fatalf("bucket of member %d = %+v (%v), want a fresh bucket", member, bucket, ok)
		}
	}

	// A new path on the key starts over.
	putMapEntry(t, collection, "server_rate_buckets", rateBucketKey(key, 0), used)
	entry = egressTestEntry(9301, entry.Limit)
	if err := runtime.SetServerEgressPath(entry); err != nil {
		t.Fatalf("SetServerEgressPath of a new path: %v", err)
	}
	if bucket, _ := readEgressBucket(t, collection, entry, 0); bucket != rateBucket(entry.Limit) {
		t.Fatalf("bucket = %+v, want a fresh bucket", bucket)
	}

	// Without the limit the buckets go, and so does the bit of the mask.
	entry.Limit = RateLimit{}
	if err := runtime.SetServerEgressPath(entry); err != nil {
		t.Fatalf("SetServerEgressPath without a limit: %v", err)
	}
	for member := range uint32(MaxPool) {
		if _, ok := readEgressBucket(t, collection, entry, member); ok {
			t.Fatalf("bucket of member %d is left", member)
		}
	}
	if mask := readEgressGroup(t, collection, entry.Client).LimitMask; mask != 0 {
		t.Fatalf("limit mask = %b, want none", mask)
	}

	// A group written after its path gets the mask, and a delete clears it.
	entry.Limit = tenMbit
	if err := runtime.SetServerEgressPath(entry); err != nil {
		t.Fatalf("SetServerEgressPath: %v", err)
	}
	if err := runtime.SetServerEgressGroup(group); err != nil {
		t.Fatalf("SetServerEgressGroup: %v", err)
	}
	if mask := readEgressGroup(t, collection, entry.Client).LimitMask; mask != 0b10 {
		t.Fatalf("limit mask = %b, want path 1", mask)
	}
	if err := runtime.DeleteServerEgressPath(entry.Client, entry.PathID); err != nil {
		t.Fatalf("DeleteServerEgressPath: %v", err)
	}
	if _, ok := readEgressBucket(t, collection, entry, 0); ok {
		t.Fatal("the bucket is left after the delete")
	}
	if mask := readEgressGroup(t, collection, entry.Client).LimitMask; mask != 0 {
		t.Fatalf("limit mask = %b, want none after the delete", mask)
	}
}

// The group gets its weights and its preferred path.
func TestSetServerEgressGroupWritesTheSharesAndThePreferredPath(t *testing.T) {
	collection := loadTestCollection(t)
	defer collection.Close()
	runtime := limitRuntime(collection)
	client := ClientKey{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), InstanceNonce: 7}
	if err := runtime.SetServerEgressGroup(EgressGroupEntry{
		Client: client, ListenPort: 51821, Mode: config.ModeFailover, PathMask: 0b11, HealthyMask: 0b11,
		HasPreferred: true, Preferred: 1,
	}); err != nil {
		t.Fatalf("SetServerEgressGroup: %v", err)
	}
	if group := readEgressGroup(t, collection, client); group.Flags != downGroupFlagPreferred || group.Preferred != 1 || group.Weights[0] != 1 {
		t.Fatalf("group = %+v, want the preferred path 1 and weights of 1", group)
	}
	if err := runtime.SetServerEgressGroup(EgressGroupEntry{
		Client: client, ListenPort: 51821, Mode: config.ModeBalancer, PathMask: 0b11, HealthyMask: 0b11,
		Weights: [MaxEgressPaths]uint8{1, 3},
	}); err != nil {
		t.Fatalf("SetServerEgressGroup: %v", err)
	}
	if group := readEgressGroup(t, collection, client); group.Flags != downGroupFlagWeighted || group.Weights[1] != 3 {
		t.Fatalf("group = %+v, want the weighted flag and weight 3", group)
	}
}
