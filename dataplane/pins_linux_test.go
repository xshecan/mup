//go:build linux

package dataplane

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestLoadStartsOverChangedPins loads this build over the pins of v0.4.0,
// which had 16-byte path slots and 23 drop counters. The loader replaces
// these pins, so the start does not fail on their layout.
func TestLoadStartsOverChangedPins(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading over pins needs root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("remove memlock limit: %v", err)
	}
	root, err := os.MkdirTemp("/sys/fs/bpf", "mup-test-pins-")
	if err != nil {
		t.Skipf("no bpffs at /sys/fs/bpf: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	for _, old := range []*ebpf.MapSpec{
		{Name: "path_config", Type: ebpf.Array, KeySize: 4, ValueSize: 16, MaxEntries: 8},
		{Name: "stats", Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 23},
	} {
		pinned, err := ebpf.NewMap(old)
		if err != nil {
			t.Skipf("create map %s: %v", old.Name, err)
		}
		err = pinned.Pin(filepath.Join(root, old.Name))
		_ = pinned.Close()
		if err != nil {
			t.Fatalf("pin map %s: %v", old.Name, err)
		}
	}

	runtime, err := Load(Config{PinRoot: root})
	if err != nil {
		t.Fatalf("Load over the pins of v0.4.0: %v", err)
	}
	defer runtime.Close()
	paths, err := runtime.objects.PathConfig.Info()
	if err != nil || paths.ValueSize != 24 {
		t.Fatalf("path_config value size = %d (%v), want 24", paths.ValueSize, err)
	}
	stats, err := runtime.objects.Stats.Info()
	if err != nil || stats.MaxEntries != uint32(dropReasonCount) {
		t.Fatalf("stats entries = %d (%v), want %d", stats.MaxEntries, err, dropReasonCount)
	}
}
