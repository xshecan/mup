//go:build linux

package dataplane

import (
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
)

func counterRuntime(collection *ebpf.Collection) *Runtime {
	return &Runtime{objects: mupObjects{mupMaps: mupMaps{
		ClientPathCounters: collection.Maps["client_path_counters"],
		ServerPathCounters: collection.Maps["server_path_counters"],
	}}}
}

// perCPUCounters gives CPU i the counter i+1 packets and 10*(i+1) bytes, and
// returns their sum.
func perCPUCounters(t *testing.T) ([]mupPathCounterV1, PathCounter) {
	t.Helper()
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("PossibleCPU: %v", err)
	}
	values := make([]mupPathCounterV1, cpus)
	var sum PathCounter
	for index := range values {
		values[index] = mupPathCounterV1{Packets: uint64(index + 1), Bytes: uint64(10 * (index + 1))}
		sum.Packets += values[index].Packets
		sum.Bytes += values[index].Bytes
	}
	return values, sum
}

func TestServerPathCounterMethods(t *testing.T) {
	collection := loadTestCollection(t)
	defer collection.Close()
	runtime := counterRuntime(collection)
	client := ClientKey{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), InstanceNonce: 7}

	if _, ok, err := runtime.ServerPathCounter(client, 2, PathCounterEgress); err != nil || ok {
		t.Fatalf("ServerPathCounter before ensure = ok %v (%v), want no entry", ok, err)
	}
	if err := runtime.EnsureServerPathCounter(client, 2, PathCounterEgress); err != nil {
		t.Fatalf("EnsureServerPathCounter: %v", err)
	}
	counter, ok, err := runtime.ServerPathCounter(client, 2, PathCounterEgress)
	if err != nil || !ok || counter != (PathCounter{}) {
		t.Fatalf("ServerPathCounter after ensure = %+v, ok %v (%v), want a zero entry", counter, ok, err)
	}

	// The sum covers every CPU, and a second ensure keeps the values.
	key, err := encodeServerPathCounterKey(client, 2, PathCounterEgress)
	if err != nil {
		t.Fatalf("encodeServerPathCounterKey: %v", err)
	}
	values, sum := perCPUCounters(t)
	if err := collection.Maps["server_path_counters"].Update(key, values, ebpf.UpdateExist); err != nil {
		t.Fatalf("write per-CPU counters: %v", err)
	}
	if err := runtime.EnsureServerPathCounter(client, 2, PathCounterEgress); err != nil {
		t.Fatalf("second EnsureServerPathCounter: %v", err)
	}
	if counter, ok, err = runtime.ServerPathCounter(client, 2, PathCounterEgress); err != nil || !ok || counter != sum {
		t.Fatalf("ServerPathCounter = %+v, ok %v (%v), want the sum %+v", counter, ok, err, sum)
	}
	// The other direction of the same path is another counter.
	if _, ok, err := runtime.ServerPathCounter(client, 2, PathCounterIngress); err != nil || ok {
		t.Fatalf("ingress counter = ok %v (%v), want no entry", ok, err)
	}

	if err := runtime.DeleteServerPathCounter(client, 2, PathCounterEgress); err != nil {
		t.Fatalf("DeleteServerPathCounter: %v", err)
	}
	if _, ok, err := runtime.ServerPathCounter(client, 2, PathCounterEgress); err != nil || ok {
		t.Fatalf("ServerPathCounter after delete = ok %v (%v), want no entry", ok, err)
	}
	if err := runtime.DeleteServerPathCounter(client, 2, PathCounterEgress); err != nil {
		t.Fatalf("DeleteServerPathCounter of a missing counter: %v", err)
	}
}

func TestServerPathCounterRefusesABadKey(t *testing.T) {
	collection := loadTestCollection(t)
	defer collection.Close()
	runtime := counterRuntime(collection)
	client := ClientKey{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), InstanceNonce: 7}
	for name, call := range map[string]func() error{
		"ingress path 8": func() error { return runtime.EnsureServerPathCounter(client, 8, PathCounterIngress) },
		"egress path 8":  func() error { return runtime.EnsureServerPathCounter(client, 8, PathCounterEgress) },
		"direction 2":    func() error { return runtime.EnsureServerPathCounter(client, 0, 2) },
		"no nonce": func() error {
			return runtime.EnsureServerPathCounter(ClientKey{AdvertisedIP: client.AdvertisedIP}, 0, PathCounterIngress)
		},
		"no address": func() error {
			return runtime.DeleteServerPathCounter(ClientKey{InstanceNonce: 7}, 0, PathCounterIngress)
		},
	} {
		if err := call(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if entries := serverCounterEntries(t, collection); entries != 0 {
		t.Fatalf("server path counters = %d, want none", entries)
	}
}

func TestClientPathCountersSumTheCPUs(t *testing.T) {
	collection := loadTestCollection(t)
	defer collection.Close()
	runtime := counterRuntime(collection)
	values, sum := perCPUCounters(t)
	for _, index := range []uint32{3, clientEgressCounterBase + 5} {
		if err := collection.Maps["client_path_counters"].Update(index, values, ebpf.UpdateExist); err != nil {
			t.Fatalf("write per-CPU counters %d: %v", index, err)
		}
	}
	ingress, egress, err := runtime.ClientPathCounters()
	if err != nil {
		t.Fatalf("ClientPathCounters: %v", err)
	}
	for slot, counter := range ingress {
		want := PathCounter{}
		if slot == 3 {
			want = sum
		}
		if counter != want {
			t.Errorf("ingress slot %d = %+v, want %+v", slot, counter, want)
		}
	}
	for slot, counter := range egress {
		want := PathCounter{}
		if slot == 5 {
			want = sum
		}
		if counter != want {
			t.Errorf("egress slot %d = %+v, want %+v", slot, counter, want)
		}
	}
}
