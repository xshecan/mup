package dataplane

import (
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/protocol"
)

type recordingMap struct {
	name string
	log  *[]string
}

func (m recordingMap) Update(_, _ interface{}, _ ebpf.MapUpdateFlags) error {
	*m.log = append(*m.log, m.name)
	return nil
}

func TestApplyClientSettingsPublishesHealthyStateLast(t *testing.T) {
	t.Parallel()

	var log []string
	maps := configurationMaps{
		client: recordingMap{name: "client", log: &log},
		groups: recordingMap{name: "group", log: &log},
		paths:  recordingMap{name: "path", log: &log},
		state:  recordingMap{name: "state", log: &log},
	}
	settings := ClientSettings{
		InstanceNonce: 1,
		AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
		HealthyMask:   1,
		Groups:        []GroupSettings{{ListenPort: 51820, Mode: config.ModeFallback, PathMask: 1}},
		Paths: []PathSettings{{
			DestinationIP: netip.MustParseAddr("198.51.100.1"),
			SourceIP:      netip.MustParseAddr("203.0.113.1"),
			Ifindex:       2,
			ServerPort:    5000,
			Transport:     protocol.TransportUDP,
		}},
	}
	if err := applyClientSettings(maps, settings); err != nil {
		t.Fatalf("applyClientSettings: %v", err)
	}
	if len(log) != 12 {
		t.Fatalf("update count = %d, want 12: %v", len(log), log)
	}
	if log[0] != "state" || log[len(log)-1] != "state" {
		t.Fatalf("state publication order = %v", log)
	}
	if log[9] != "group" || log[10] != "client" {
		t.Fatalf("group and client config update order = %v", log)
	}
}

type valueMap struct {
	value interface{}
}

func (m *valueMap) Update(_, value interface{}, _ ebpf.MapUpdateFlags) error {
	m.value = value
	return nil
}

func TestApplyPathState(t *testing.T) {
	t.Parallel()

	target := &valueMap{}
	if err := applyPathState(target, 0b101, 12); err != nil {
		t.Fatalf("applyPathState: %v", err)
	}
	state, ok := target.value.(mupPathStateV1)
	if !ok || state.HealthyMask != 0b101 || state.Generation != 12 {
		t.Fatalf("state = %#v", target.value)
	}
}
