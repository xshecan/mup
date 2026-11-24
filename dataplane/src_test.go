package dataplane

import (
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/protocol"
)

// keyedMap is a map fake that keeps the latest value of each key.
type keyedMap struct {
	values  map[interface{}]interface{}
	deleted []interface{}
}

func newKeyedMap() *keyedMap {
	return &keyedMap{values: make(map[interface{}]interface{})}
}

func (m *keyedMap) Update(key, value interface{}, _ ebpf.MapUpdateFlags) error {
	m.values[key] = value
	return nil
}

func (m *keyedMap) Delete(key interface{}) error {
	if _, ok := m.values[key]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.values, key)
	m.deleted = append(m.deleted, key)
	return nil
}

func (m *keyedMap) Lookup(key, valueOut interface{}) error {
	value, ok := m.values[key]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*valueOut.(*mupRegisteredPathValueV1) = value.(mupRegisteredPathValueV1)
	return nil
}

func srcClientSettings(paths []PathSettings, egresses []*EgressPathSettings) ClientSettings {
	var pathMask, downMask uint8
	for index := range paths {
		pathMask |= 1 << index
	}
	for index := range egresses {
		downMask |= 1 << index
	}
	return ClientSettings{
		InstanceNonce: 1,
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		Groups:        []GroupSettings{{ListenPort: 51820, Mode: config.ModeFailover, PathMask: pathMask, DownMask: downMask}},
		Paths:         paths,
		EgressPaths:   egresses,
	}
}

func srcPath(port uint16, transport protocol.TransportID, first, last uint16) PathSettings {
	return PathSettings{
		DestinationIP: netip.MustParseAddr("198.51.100.1"),
		SourceIP:      netip.MustParseAddr("192.0.2.10"),
		Ifindex:       2,
		ServerPort:    port,
		Transport:     transport,
		SrcFirst:      first,
		SrcLast:       last,
	}
}

func TestApplyClientSettingsWritesTheSourceRangeOfEverySlot(t *testing.T) {
	t.Parallel()

	var log []string
	pathSrc, downSrc := newKeyedMap(), newKeyedMap()
	maps := configurationMaps{
		client:  recordingMap{name: "client", log: &log},
		groups:  recordingMap{name: "group", log: &log},
		paths:   recordingMap{name: "path", log: &log},
		returns: recordingMap{name: "return", log: &log},
		state:   recordingMap{name: "state", log: &log},
		downs:   recordingMap{name: "down", log: &log},
		pathSrc: pathSrc,
		downSrc: downSrc,
	}
	settings := srcClientSettings(
		[]PathSettings{srcPath(5000, protocol.TransportUDP, 20000, 20999), srcPath(5001, protocol.TransportICMP, 0, 0)},
		[]*EgressPathSettings{{Server: netip.MustParseAddr("198.51.100.2"), ServerPort: 9000, Transport: protocol.TransportICMP, SrcFirst: 30000, SrcLast: 30000}},
	)
	if err := applyClientSettings(maps, settings); err != nil {
		t.Fatalf("applyClientSettings: %v", err)
	}
	if len(pathSrc.values) != config.MaxPaths || len(downSrc.values) != MaxEgressPaths {
		t.Fatalf("source range writes = %d paths and %d egress paths, want every slot", len(pathSrc.values), len(downSrc.values))
	}
	if got := pathSrc.values[uint32(0)]; got != (mupPathSrcV1{First: 20000, Last: 20999}) {
		t.Fatalf("range of path 0 = %#v", got)
	}
	for slot := uint32(1); slot < config.MaxPaths; slot++ {
		if got := pathSrc.values[slot]; got != (mupPathSrcV1{}) {
			t.Fatalf("range of path %d = %#v, want none", slot, got)
		}
	}
	if got := downSrc.values[uint32(0)]; got != (mupPathSrcV1{First: 30000, Last: 30000}) {
		t.Fatalf("range of egress path 0 = %#v", got)
	}
	if got := downSrc.values[uint32(1)]; got != (mupPathSrcV1{}) {
		t.Fatalf("range of egress path 1 = %#v, want none", got)
	}
}

func TestApplyClientSettingsRefusesAnInvalidSourceRangeBeforeAnyWrite(t *testing.T) {
	t.Parallel()

	var log []string
	maps := configurationMaps{
		client:  recordingMap{name: "client", log: &log},
		groups:  recordingMap{name: "group", log: &log},
		paths:   recordingMap{name: "path", log: &log},
		returns: recordingMap{name: "return", log: &log},
		state:   recordingMap{name: "state", log: &log},
		pathSrc: recordingMap{name: "src", log: &log},
	}
	settings := srcClientSettings([]PathSettings{srcPath(5000, protocol.TransportUDP, 2000, 1000)}, nil)
	if err := applyClientSettings(maps, settings); err == nil {
		t.Fatal("applyClientSettings accepted a range with FIRST above LAST")
	}
	if len(log) != 0 {
		t.Fatalf("writes before the error = %v", log)
	}
}

func TestApplyPathWritesTheSourceRangeAndClearPathResetsIt(t *testing.T) {
	t.Parallel()

	paths, returns, reflect, pathSrc := newKeyedMap(), newKeyedMap(), newKeyedMap(), newKeyedMap()
	if err := applyPath(paths, returns, reflect, pathSrc, 3, srcPath(5000, protocol.TransportICMP, 40000, 40010)); err != nil {
		t.Fatalf("applyPath: %v", err)
	}
	if got := pathSrc.values[uint32(3)]; got != (mupPathSrcV1{First: 40000, Last: 40010}) {
		t.Fatalf("range of slot 3 = %#v", got)
	}
	// A new path without a range in the slot drops the old range.
	if err := applyPath(paths, returns, reflect, pathSrc, 3, srcPath(5001, protocol.TransportICMP, 0, 0)); err != nil {
		t.Fatalf("applyPath without a range: %v", err)
	}
	if got := pathSrc.values[uint32(3)]; got != (mupPathSrcV1{}) {
		t.Fatalf("range of slot 3 after a path without a range = %#v", got)
	}
	if err := applyPath(paths, returns, reflect, pathSrc, 3, srcPath(5000, protocol.TransportUDP, 1, 65535)); err != nil {
		t.Fatalf("applyPath: %v", err)
	}
	if err := clearPath(paths, returns, reflect, pathSrc, 3); err != nil {
		t.Fatalf("clearPath: %v", err)
	}
	if got := pathSrc.values[uint32(3)]; got != (mupPathSrcV1{}) {
		t.Fatalf("range of a cleared slot = %#v", got)
	}
	if err := applyPath(paths, returns, reflect, pathSrc, 3, srcPath(5000, protocol.TransportUDP, 0, 10)); err == nil {
		t.Fatal("applyPath accepted a range that starts at 0")
	}
}

func TestApplyEgressPathWritesTheSourceRangeAndAClearResetsIt(t *testing.T) {
	t.Parallel()

	downs, downSrc := newKeyedMap(), newKeyedMap()
	egress := &EgressPathSettings{Server: netip.MustParseAddr("198.51.100.2"), ServerPort: 9000, Transport: protocol.TransportUDP, SrcFirst: 10000, SrcLast: 10100}
	if err := applyEgressPath(downs, downSrc, 2, egress); err != nil {
		t.Fatalf("applyEgressPath: %v", err)
	}
	if got := downSrc.values[uint32(2)]; got != (mupPathSrcV1{First: 10000, Last: 10100}) {
		t.Fatalf("range of egress slot 2 = %#v", got)
	}
	if got := downs.values[uint32(2)].(mupClientDownPathV1); got.ServerPort != 9000 {
		t.Fatalf("egress slot 2 = %#v", got)
	}
	if err := applyEgressPath(downs, downSrc, 2, nil); err != nil {
		t.Fatalf("applyEgressPath clear: %v", err)
	}
	if got := downSrc.values[uint32(2)]; got != (mupPathSrcV1{}) {
		t.Fatalf("range of a cleared egress slot = %#v", got)
	}
	if got := downs.values[uint32(2)]; got != (mupClientDownPathV1{}) {
		t.Fatalf("cleared egress slot = %#v", got)
	}
}

func TestEgressPathFromConfigKeepsTheSourceRange(t *testing.T) {
	t.Parallel()

	settings := EgressPathFromConfig(config.Path{
		Server: netip.MustParseAddr("198.51.100.2"), ServerPort: 9000, Transport: protocol.TransportICMP,
		SrcFirst: 30000, SrcLast: 30500,
	})
	if settings.SrcFirst != 30000 || settings.SrcLast != 30500 {
		t.Fatalf("settings = %#v, want the range 30000-30500", settings)
	}
}

func TestEncodeEgressPathEntryWritesTheSourceRangeOfEveryForm(t *testing.T) {
	t.Parallel()

	client := ClientKey{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), InstanceNonce: 7}
	base := EgressPathEntry{
		Client: client, PathID: 1, Server: netip.MustParseAddr("198.51.100.2"), ServerPort: 9000,
		Transport: protocol.TransportUDP, Ifindex: 3, SrcFirst: 20000, SrcLast: 20999,
	}
	returnIP := base
	returnIP.ReturnIP = netip.MustParseAddr("203.0.113.9")
	pool := base
	pool.Pool, pool.ReturnIP, pool.Members = true, netip.MustParseAddr("203.0.113.0"), []netip.Addr{netip.MustParseAddr("203.0.113.1")}
	bridge := base
	bridge.Bridge, bridge.LocalIP = true, netip.MustParseAddr("198.51.100.1")
	bridgeVia := bridge
	bridgeVia.BridgeVia, bridgeVia.ReturnIP = true, netip.MustParseAddr("203.0.113.9")
	icmp := base
	icmp.Transport = protocol.TransportICMP
	for name, entry := range map[string]EgressPathEntry{
		"direct": base, "return IP": returnIP, "pool": pool, "bridge": bridge, "bridge via": bridgeVia, "icmp": icmp,
	} {
		_, value, err := encodeEgressPathEntry(entry)
		if err != nil {
			t.Fatalf("%s: encodeEgressPathEntry: %v", name, err)
		}
		if value.SrcFirst != 20000 || value.SrcLast != 20999 || value.ServerPort != 9000 {
			t.Fatalf("%s: value = %#v, want the range 20000-20999 and port 9000", name, value)
		}
	}
	none := base
	none.SrcFirst, none.SrcLast = 0, 0
	if _, value, err := encodeEgressPathEntry(none); err != nil || value.SrcFirst != 0 || value.SrcLast != 0 {
		t.Fatalf("entry without a range = %#v, %v", value, err)
	}
	invalid := base
	invalid.SrcFirst, invalid.SrcLast = 20999, 20000
	if _, _, err := encodeEgressPathEntry(invalid); err == nil {
		t.Fatal("encodeEgressPathEntry accepted a range with FIRST above LAST")
	}
}

func srcRegistration(transport protocol.TransportID, port, pathID, first, last uint16) RegistrationSettings {
	return RegistrationSettings{
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		InstanceNonce: 99,
		ListenPort:    51820,
		PathCount:     1,
		ExpiresAtNS:   123456,
		Path: RegisteredPathSettings{
			SourceIP:   netip.MustParseAddr("192.0.2.10"),
			LocalIP:    netip.MustParseAddr("198.51.100.1"),
			ServerPort: port,
			Transport:  transport,
			PathID:     pathID,
			SrcFirst:   first,
			SrcLast:    last,
		},
	}
}

func TestEncodeRegistrationSettingsWritesTheSourceRangeAndTheServerPort(t *testing.T) {
	t.Parallel()

	_, _, pathKey, pathValue, err := encodeRegistrationSettings(srcRegistration(protocol.TransportICMP, 5000, 2, 20000, 20999))
	if err != nil {
		t.Fatalf("encodeRegistrationSettings: %v", err)
	}
	if pathKey.Tag != 0 || pathKey.ServerPort != 5000 {
		t.Fatalf("path key = %#v, want the exact key", pathKey)
	}
	if pathValue.SrcFirst != 20000 || pathValue.SrcLast != 20999 || pathValue.ServerPort != 5000 {
		t.Fatalf("path value = %#v", pathValue)
	}
	_, _, _, plain, err := encodeRegistrationSettings(srcRegistration(protocol.TransportUDP, 5001, 2, 0, 0))
	if err != nil {
		t.Fatalf("encodeRegistrationSettings without a range: %v", err)
	}
	if plain.SrcFirst != 0 || plain.SrcLast != 0 || plain.ServerPort != 5001 {
		t.Fatalf("path value without a range = %#v, want the server port alone", plain)
	}
	if _, _, _, _, err := encodeRegistrationSettings(srcRegistration(protocol.TransportUDP, 5001, 2, 0, 5)); err == nil {
		t.Fatal("encodeRegistrationSettings accepted a range that starts at 0")
	}
}

func TestTaggedRegisteredPathKeyExistsOnlyForAnICMPPathWithARange(t *testing.T) {
	t.Parallel()

	_, _, key, value, err := encodeRegistrationSettings(srcRegistration(protocol.TransportICMP, 5000, 2, 20000, 20999))
	if err != nil {
		t.Fatalf("encodeRegistrationSettings: %v", err)
	}
	tagged, ok := taggedRegisteredPathKey(key, value)
	want := mupRegisteredPathKeyV1{SourceIp: key.SourceIp, LocalIp: key.LocalIp, Transport: uint8(protocol.TransportICMP), Tag: 3}
	if !ok || tagged != want {
		t.Fatalf("tagged key = %#v, %v, want %#v", tagged, ok, want)
	}
	if twin := exactRegisteredPathKey(tagged, value); twin != key {
		t.Fatalf("exact twin = %#v, want %#v", twin, key)
	}
	for name, settings := range map[string]RegistrationSettings{
		"udp with a range": srcRegistration(protocol.TransportUDP, 5000, 2, 20000, 20999),
		"icmp without one": srcRegistration(protocol.TransportICMP, 5000, 2, 0, 0),
	} {
		_, _, key, value, err := encodeRegistrationSettings(settings)
		if err != nil {
			t.Fatalf("%s: encodeRegistrationSettings: %v", name, err)
		}
		if _, ok := taggedRegisteredPathKey(key, value); ok {
			t.Fatalf("%s has a tagged key", name)
		}
	}
}

func TestApplyRegistrationWritesTheTaggedKeyOnlyForAnICMPPathWithARange(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct {
		settings RegistrationSettings
		entries  int
	}{
		"icmp with a range":    {srcRegistration(protocol.TransportICMP, 5000, 2, 20000, 20999), 2},
		"udp with a range":     {srcRegistration(protocol.TransportUDP, 5000, 2, 20000, 20999), 1},
		"icmp without a range": {srcRegistration(protocol.TransportICMP, 5000, 2, 0, 0), 1},
	} {
		registrations, paths := newKeyedMap(), newKeyedMap()
		if err := applyRegistrationSettings(registrations, paths, test.settings); err != nil {
			t.Fatalf("%s: applyRegistrationSettings: %v", name, err)
		}
		if len(paths.values) != test.entries {
			t.Fatalf("%s: registered path entries = %#v, want %d", name, paths.values, test.entries)
		}
		_, _, key, value, _ := encodeRegistrationSettings(test.settings)
		if paths.values[key] != value {
			t.Fatalf("%s: exact entry = %#v, want %#v", name, paths.values[key], value)
		}
		if tagged, ok := taggedRegisteredPathKey(key, value); ok && paths.values[tagged] != value {
			t.Fatalf("%s: tagged entry = %#v, want the value of the exact entry", name, paths.values[tagged])
		}
	}
}

func TestApplyRegistrationDeletesTheTaggedKeyThatThePathNoLongerHas(t *testing.T) {
	t.Parallel()

	registrations, paths := newKeyedMap(), newKeyedMap()
	ranged := srcRegistration(protocol.TransportICMP, 5000, 2, 20000, 20999)
	if err := applyRegistrationSettings(registrations, paths, ranged); err != nil {
		t.Fatalf("applyRegistrationSettings: %v", err)
	}
	// The same path with a new range keeps one tagged entry with the new range.
	changed := srcRegistration(protocol.TransportICMP, 5000, 2, 21000, 21999)
	if err := applyRegistrationSettings(registrations, paths, changed); err != nil {
		t.Fatalf("applyRegistrationSettings with a new range: %v", err)
	}
	_, _, key, value, _ := encodeRegistrationSettings(changed)
	tagged, _ := taggedRegisteredPathKey(key, value)
	if len(paths.values) != 2 || paths.values[tagged] != value {
		t.Fatalf("entries after a new range = %#v", paths.values)
	}
	// A new path ID moves the tagged entry to the new tag.
	moved := srcRegistration(protocol.TransportICMP, 5000, 4, 21000, 21999)
	if err := applyRegistrationSettings(registrations, paths, moved); err != nil {
		t.Fatalf("applyRegistrationSettings with a new path ID: %v", err)
	}
	_, _, _, movedValue, _ := encodeRegistrationSettings(moved)
	movedTagged, _ := taggedRegisteredPathKey(key, movedValue)
	if _, ok := paths.values[tagged]; ok || paths.values[movedTagged] != movedValue || len(paths.values) != 2 {
		t.Fatalf("entries after a new path ID = %#v", paths.values)
	}
	// Without a range the path has its exact entry alone.
	plain := srcRegistration(protocol.TransportICMP, 5000, 4, 0, 0)
	if err := applyRegistrationSettings(registrations, paths, plain); err != nil {
		t.Fatalf("applyRegistrationSettings without a range: %v", err)
	}
	if len(paths.values) != 1 {
		t.Fatalf("entries after the range went away = %#v, want the exact entry alone", paths.values)
	}
}

func TestApplyRegistrationKeepsATaggedKeyThatAnotherPortOwns(t *testing.T) {
	t.Parallel()

	registrations, paths := newKeyedMap(), newKeyedMap()
	// The path moved from port 5000 to port 5001, so the tagged entry
	// follows port 5001. A late REGISTER without a range on port 5000 must
	// leave it.
	for _, settings := range []RegistrationSettings{
		srcRegistration(protocol.TransportICMP, 5000, 2, 20000, 20999),
		srcRegistration(protocol.TransportICMP, 5001, 2, 20000, 20999),
		srcRegistration(protocol.TransportICMP, 5000, 2, 0, 0),
	} {
		if err := applyRegistrationSettings(registrations, paths, settings); err != nil {
			t.Fatalf("applyRegistrationSettings: %v", err)
		}
	}
	_, _, key, value, _ := encodeRegistrationSettings(srcRegistration(protocol.TransportICMP, 5001, 2, 20000, 20999))
	tagged, _ := taggedRegisteredPathKey(key, value)
	if paths.values[tagged] != value || len(paths.deleted) != 0 {
		t.Fatalf("entries = %#v, deleted = %#v, want the tagged entry of port 5001", paths.values, paths.deleted)
	}
}

func TestStaleTaggedPathsFindsATaggedEntryWithoutItsTwin(t *testing.T) {
	t.Parallel()

	_, _, key, value, err := encodeRegistrationSettings(srcRegistration(protocol.TransportICMP, 5000, 2, 20000, 20999))
	if err != nil {
		t.Fatalf("encodeRegistrationSettings: %v", err)
	}
	tagged, _ := taggedRegisteredPathKey(key, value)
	if stale := staleTaggedPaths(map[mupRegisteredPathKeyV1]mupRegisteredPathValueV1{key: value, tagged: value}); len(stale) != 0 {
		t.Fatalf("stale = %#v, want none for a tagged entry with its twin", stale)
	}
	if stale := staleTaggedPaths(map[mupRegisteredPathKeyV1]mupRegisteredPathValueV1{tagged: value}); len(stale) != 1 || stale[0] != tagged {
		t.Fatalf("stale = %#v, want the tagged entry without its twin", stale)
	}
	changed := value
	changed.SrcFirst = 21000
	if stale := staleTaggedPaths(map[mupRegisteredPathKeyV1]mupRegisteredPathValueV1{key: changed, tagged: value}); len(stale) != 1 {
		t.Fatalf("stale = %#v, want the tagged entry whose twin changed", stale)
	}
}

func TestDecodeKeepsTheSourceRangeOfRegisteredPathsAndRoutes(t *testing.T) {
	t.Parallel()

	_, _, key, value, err := encodeRegistrationSettings(srcRegistration(protocol.TransportICMP, 5000, 2, 20000, 20999))
	if err != nil {
		t.Fatalf("encodeRegistrationSettings: %v", err)
	}
	if path := decodeRegisteredPath(key, value, 0); path.SrcFirst != 20000 || path.SrcLast != 20999 || path.ServerPort != 5000 {
		t.Fatalf("registered path = %#v", path)
	}
	route := decodeServerRoute(mupServerReverseValueV1{RouteValue: mupServerRouteValueV1{ServerPort: 5000, SrcFirst: 20000, SrcLast: 20999}}, 0)
	if route.SrcFirst != 20000 || route.SrcLast != 20999 || route.ServerPort != 5000 {
		t.Fatalf("server route = %#v", route)
	}
}
