//go:build linux

package dataplane

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/xshecan/mup/protocol"
)

func TestBPFWireGuardValidation(t *testing.T) {
	collection := loadTestCollection(t)
	defer collection.Close()

	local := ethernetUDPFixture(t, false, false)
	tunneled := ethernetUDPFixture(t, true, false)
	control := ethernetUDPFixture(t, false, true)
	tests := []struct {
		name    string
		program string
		packet  []byte
		want    uint32
	}{
		{name: "local", program: "mup_test_validate_local", packet: local, want: uint32(protocol.DropNone)},
		{name: "tunneled", program: "mup_test_validate_tunneled", packet: tunneled, want: uint32(protocol.DropNone)},
		{name: "control", program: "mup_test_control", packet: control, want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			program := collection.Programs[tt.program]
			if program == nil {
				t.Fatalf("missing program %q", tt.program)
			}
			got, _, err := program.Test(tt.packet)
			if err != nil {
				t.Fatalf("program test: %v", err)
			}
			if got != tt.want {
				t.Fatalf("return value = %d, want %d", got, tt.want)
			}
		})
	}
}

func loadTestCollection(t *testing.T) *ebpf.Collection {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("remove memlock limit: %v", err)
	}
	spec, err := loadMup()
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	for _, mapSpec := range spec.Maps {
		mapSpec.Pinning = ebpf.PinNone
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		// The verifier rejects a program with EACCES too, so a rejection
		// must fail here, not look like missing privileges.
		var verifierError *ebpf.VerifierError
		if errors.As(err, &verifierError) {
			t.Fatalf("verifier rejected a program: %v", err)
		}
		if errors.Is(err, ebpf.ErrNotSupported) ||
			errors.Is(err, unix.EPERM) ||
			errors.Is(err, unix.EACCES) {
			t.Skipf("kernel or privileges do not support required BPF features: %v", err)
		}
		t.Fatalf("load collection into kernel: %v", err)
	}
	return collection
}

func ethernetUDPFixture(t *testing.T, tunneled, control bool) []byte {
	t.Helper()
	var payload []byte
	if control {
		payload = make([]byte, protocol.ControlFrameLength)
		err := protocol.EncodeControlFrame(payload, protocol.ControlFrame{
			Type:          protocol.ControlRegister,
			Transport:     protocol.TransportUDP,
			ListenPort:    51820,
			ServerPort:    5000,
			AdvertisedIP:  netip.MustParseAddr("192.0.2.10"),
			InstanceNonce: 1,
		})
		if err != nil {
			t.Fatalf("encode control frame: %v", err)
		}
	} else {
		payload = make([]byte, protocol.HandshakeInitiationLength)
		payload[0] = protocol.MessageHandshakeInitiation
		if tunneled {
			payload[3] = 1
		}
	}

	frame := make([]byte, 14+20+8+len(payload))
	frame[12], frame[13] = 0x08, 0x00
	ip := frame[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64
	ip[9] = protocol.IPProtocolUDP
	copy(ip[12:16], netip.MustParseAddr("192.0.2.10").AsSlice())
	copy(ip[16:20], netip.MustParseAddr("198.51.100.1").AsSlice())
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:2], 51820)
	binary.BigEndian.PutUint16(udp[2:4], 5000)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	return frame
}

func TestVerifierComplexity(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("remove memlock limit: %v", err)
	}
	spec, err := loadMup()
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	for name := range spec.Programs {
		t.Run(name, func(t *testing.T) {
			single := spec.Copy()
			for _, mapSpec := range single.Maps {
				mapSpec.Pinning = ebpf.PinNone
			}
			for other := range single.Programs {
				if other != name {
					delete(single.Programs, other)
				}
			}
			collection, err := ebpf.NewCollectionWithOptions(single, ebpf.CollectionOptions{
				Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats},
			})
			if err != nil {
				var verifierError *ebpf.VerifierError
				if errors.As(err, &verifierError) && len(verifierError.Log) > 0 {
					t.Fatalf("verifier rejected %s: %s", name, strings.Join(verifierError.Log[max(0, len(verifierError.Log)-4):], " | "))
				}
				if errors.Is(err, ebpf.ErrNotSupported) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
					t.Skipf("kernel or privileges do not support required BPF features: %v", err)
				}
				t.Fatalf("load %s: %v", name, err)
			}
			defer collection.Close()
			t.Logf("%s: %s", name, collection.Programs[name].VerifierLog)
		})
	}
}

func TestZeroPerCPUCountersClearsTheDrops(t *testing.T) {
	collection := loadTestCollection(t)
	defer collection.Close()
	stats := collection.Maps["stats"]
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("PossibleCPU: %v", err)
	}
	values := make([]uint64, cpus)
	for index := range values {
		values[index] = uint64(index + 3)
	}
	for _, reason := range []uint32{uint32(protocol.DropNoPath), uint32(protocol.DropBridgeSize)} {
		if err := stats.Update(reason, values, ebpf.UpdateExist); err != nil {
			t.Fatalf("write counter %d: %v", reason, err)
		}
	}
	if err := zeroPerCPUCounters(stats, dropReasonCount); err != nil {
		t.Fatalf("zeroPerCPUCounters: %v", err)
	}
	for reason := range dropReasonCount {
		if count := dropCount(t, collection, protocol.DropReason(reason)); count != 0 {
			t.Fatalf("counter %d = %d after the reset", reason, count)
		}
	}
}
