package dataplane

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestMupCollectionSpec(t *testing.T) {
	t.Parallel()

	spec, err := loadMup()
	if err != nil {
		t.Fatalf("loadMup: %v", err)
	}
	for _, name := range []string{"mup_client_ingress", "mup_server_ingress", "mup_test_parse"} {
		program := spec.Programs[name]
		if program == nil {
			t.Fatalf("missing program %q", name)
		}
		if program.Type != ebpf.SchedCLS {
			t.Fatalf("program %q type = %v, want SchedCLS", name, program.Type)
		}
	}

	wantMaps := map[string]struct {
		typeID     ebpf.MapType
		maxEntries uint32
	}{
		"client_config":            {ebpf.Array, 1},
		"server_config":            {ebpf.Array, 1},
		"server_ports":             {ebpf.Array, 1},
		"registration_by_key":      {ebpf.Hash, 4096},
		"registered_paths":         {ebpf.Hash, 32768},
		"client_peer_by_endpoint":  {ebpf.Hash, 4096},
		"client_endpoint_by_token": {ebpf.Hash, 4096},
		"free_peer_tokens":         {ebpf.Queue, 4095},
		"server_route_by_key":      {ebpf.Hash, 41000},
		"server_route_by_port":     {ebpf.Hash, 41000},
		"free_target_ports":        {ebpf.Queue, 41000},
		"path_config":              {ebpf.Array, 8},
		"path_returns":             {ebpf.Array, 8},
		"path_groups":              {ebpf.Hash, 8},
		"path_state":               {ebpf.Array, 1},
		"duplicate_cache":          {ebpf.LRUHash, 16384},
		"encap_programs":           {ebpf.ProgramArray, 3},
		"stats":                    {ebpf.PerCPUArray, 23},
		"events":                   {ebpf.RingBuf, 256 * 1024},
		"event_limits":             {ebpf.Array, 23},
	}
	for name, want := range wantMaps {
		m := spec.Maps[name]
		if m == nil {
			t.Errorf("missing map %q", name)
			continue
		}
		if m.Type != want.typeID || m.MaxEntries != want.maxEntries {
			t.Errorf("map %q = (%v, %d), want (%v, %d)", name, m.Type, m.MaxEntries, want.typeID, want.maxEntries)
		}
		if m.Pinning != ebpf.PinByName {
			t.Errorf("map %q pinning = %v, want PinByName", name, m.Pinning)
		}
	}
}
