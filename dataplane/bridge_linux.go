//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
)

// ConfigureBridge writes the configuration of a bridge: its server, its ports,
// the senders of wrapped replies, and the addresses of the host.
func (r *Runtime) ConfigureBridge(settings BridgeSettings) error {
	configuration, err := encodeBridgeConfig(settings)
	if err != nil {
		return err
	}
	senders, err := bridgeSenders(settings)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("configure bridge: MUP dataplane is closed")
	}
	if err := clearMap[mupBridgeAllowKeyV1, uint8](r.objects.BridgeAllow); err != nil {
		return fmt.Errorf("clear bridge senders: %w", err)
	}
	for _, sender := range senders {
		if err := r.objects.BridgeAllow.Update(sender, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("write bridge sender: %w", err)
		}
	}
	if err := r.setBridgeAddressesLocked(settings.Addresses); err != nil {
		return err
	}
	// The configuration goes last, because it turns the program on.
	if err := r.objects.BridgeConfig.Update(uint32(0), configuration, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("write bridge configuration: %w", err)
	}
	return nil
}

// SetBridgeAddresses writes the IPv4 addresses of the bridge host. The bridge
// takes packets only to these addresses.
func (r *Runtime) SetBridgeAddresses(addresses []netip.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("set bridge addresses: MUP dataplane is closed")
	}
	return r.setBridgeAddressesLocked(addresses)
}

func (r *Runtime) setBridgeAddressesLocked(addresses []netip.Addr) error {
	want := make(map[uint32]struct{}, len(addresses))
	for _, address := range addresses {
		word, err := requiredIPv4Word(address, "bridge address")
		if err != nil {
			continue
		}
		want[word] = struct{}{}
	}
	if len(want) > MaxBridgeAddresses {
		return fmt.Errorf("the bridge host has %d IPv4 addresses, more than %d", len(want), MaxBridgeAddresses)
	}
	current, err := mapEntries[uint32, uint8](r.objects.BridgeAddresses)
	if err != nil && !errors.Is(err, ebpf.ErrIterationAborted) {
		return fmt.Errorf("list bridge addresses: %w", err)
	}
	for word := range current {
		if _, keep := want[word]; keep {
			continue
		}
		if err := deleteEntry(r.objects.BridgeAddresses, word); err != nil {
			return fmt.Errorf("delete bridge address %s: %w", ipv4FromWord(word), err)
		}
	}
	for word := range want {
		if _, exists := current[word]; exists {
			continue
		}
		if err := r.objects.BridgeAddresses.Update(word, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("write bridge address %s: %w", ipv4FromWord(word), err)
		}
	}
	return nil
}

// AttachBridge attaches the bridge program to the TCX ingress hook of each
// interface.
func (r *Runtime) AttachBridge(ifindexes []int) error {
	return r.attachIngress("bridge", r.objects.MupBridgeIngress, ifindexes)
}

// BridgeCounters returns the packets and bytes that the bridge sent, summed
// over the CPUs.
func (r *Runtime) BridgeCounters() (BridgeCounters, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return BridgeCounters{}, errors.New("read bridge counters: MUP dataplane is closed")
	}
	var totals [4]uint64
	for index := range totals {
		var values []uint64
		if err := r.objects.BridgeCounters.Lookup(uint32(index), &values); err != nil {
			return BridgeCounters{}, fmt.Errorf("read bridge counter %d: %w", index, err)
		}
		for _, value := range values {
			totals[index] += value
		}
	}
	return BridgeCounters{IngressPackets: totals[0], IngressBytes: totals[1], EgressPackets: totals[2], EgressBytes: totals[3]}, nil
}
