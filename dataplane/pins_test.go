package dataplane

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
)

// recordRelease adds the map layouts of this build to the released versions,
// under the version it names. Run it after each tag:
//
//	go test ./dataplane -run TestChangedPinsAreRebuilt -record-release v0.4.2
var recordRelease = flag.String("record-release", "", "record the pinned map layouts of this build as a released version")

const releasedMapsFile = "testdata/released_maps.json"

type mapLayout struct {
	Type    uint32 `json:"type"`
	Key     uint32 `json:"key"`
	Value   uint32 `json:"value"`
	Entries uint32 `json:"entries"`
	Flags   uint32 `json:"flags"`
}

func pinnedLayouts(t *testing.T) map[string]mapLayout {
	t.Helper()
	spec, err := loadMup()
	if err != nil {
		t.Fatalf("loadMup: %v", err)
	}
	layouts := map[string]mapLayout{}
	for name, m := range spec.Maps {
		if m.Pinning == ebpf.PinByName {
			layouts[name] = mapLayout{Type: uint32(m.Type), Key: m.KeySize, Value: m.ValueSize, Entries: m.MaxEntries, Flags: m.Flags}
		}
	}
	return layouts
}

// TestChangedPinsAreRebuilt makes sure that this build starts over the pins of
// every released version. A pinned map whose layout changed since a release
// must be in rebuiltPins, because the loader keeps every other pin, and the
// kernel refuses a pin with another layout.
func TestChangedPinsAreRebuilt(t *testing.T) {
	content, err := os.ReadFile(releasedMapsFile)
	if err != nil {
		t.Fatalf("read %s: %v", releasedMapsFile, err)
	}
	var released map[string]map[string]mapLayout
	if err := json.Unmarshal(content, &released); err != nil {
		t.Fatalf("parse %s: %v", releasedMapsFile, err)
	}
	current := pinnedLayouts(t)
	for _, name := range rebuiltPins {
		if _, ok := current[name]; !ok {
			t.Errorf("rebuiltPins names %s, which is not a pinned map", name)
		}
	}
	for version, maps := range released {
		for name, old := range maps {
			layout, ok := current[name]
			if !ok || layout == old || slices.Contains(rebuiltPins, name) {
				continue
			}
			t.Errorf("map %s changed since %s, from %+v to %+v, but it is not in rebuiltPins: keep its layout, or add it if the daemon can lose its content", name, version, old, layout)
		}
	}

	if *recordRelease == "" {
		return
	}
	released[*recordRelease] = current
	encoded, err := json.MarshalIndent(released, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Clean(releasedMapsFile), append(encoded, '\n'), 0o644); err != nil {
		t.Fatalf("write %s: %v", releasedMapsFile, err)
	}
}
