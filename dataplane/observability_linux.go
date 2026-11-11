//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/ringbuf"
)

func (r *Runtime) Snapshot() (StatsSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return StatsSnapshot{}, errors.New("snapshot dataplane: MUP dataplane is closed")
	}

	var snapshot StatsSnapshot
	for reason := 0; reason < dropReasonCount; reason++ {
		var perCPU []uint64
		if err := r.objects.Stats.Lookup(uint32(reason), &perCPU); err != nil {
			return StatsSnapshot{}, fmt.Errorf("read drop counter %d: %w", reason, err)
		}
		snapshot.Drops[reason] = aggregatePerCPU(perCPU)
	}

	var err error
	if snapshot.Registrations, err = countEntries[mupClientKeyV1, mupRegistrationValueV1](
		r.objects.RegistrationByKey, "registrations"); err != nil {
		return StatsSnapshot{}, err
	}
	if snapshot.RegisteredPaths, err = countEntries[mupRegisteredPathKeyV1, mupRegisteredPathValueV1](
		r.objects.RegisteredPaths, "registered paths"); err != nil {
		return StatsSnapshot{}, err
	}
	if snapshot.ClientRoutes, err = countEntries[mupPeerEndpointKeyV1, mupPeerTokenValueV1](
		r.objects.ClientPeerByEndpoint, "client routes"); err != nil {
		return StatsSnapshot{}, err
	}
	if snapshot.ServerRoutes, err = countEntries[mupServerRouteKeyV1, mupServerRouteValueV1](
		r.objects.ServerRouteByKey, "server routes"); err != nil {
		return StatsSnapshot{}, err
	}
	if snapshot.DuplicateEntries, err = countEntries[mupDuplicateKeyV1, uint64](
		r.objects.DuplicateCache, "duplicate entries"); err != nil {
		return StatsSnapshot{}, err
	}
	snapshot.PeerQuarantined = uint64(r.peerQuarantine.Len())
	snapshot.PortsQuarantined = uint64(r.portQuarantine.Len())
	snapshot.PeerTokensAvailable = availableResources(
		uint64(peerTokenPoolSize),
		snapshot.ClientRoutes,
		snapshot.PeerQuarantined,
	)
	snapshot.TargetPortsAvailable = availableResources(
		uint64(targetPortPoolSize),
		snapshot.ServerRoutes,
		snapshot.PortsQuarantined,
	)
	var pathState mupPathStateV1
	if err := r.objects.PathState.Lookup(uint32(0), &pathState); err != nil {
		return StatsSnapshot{}, fmt.Errorf("read path state: %w", err)
	}
	snapshot.HealthyMask = pathState.HealthyMask
	snapshot.PathGeneration = pathState.Generation
	return snapshot, nil
}

func (r *Runtime) ConsumeEvents(ctx context.Context, consume func(Event)) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return errors.New("consume dataplane events: MUP dataplane is closed")
	}
	reader, err := ringbuf.NewReader(r.objects.Events)
	r.mu.Unlock()
	if err != nil {
		return fmt.Errorf("open dataplane event reader: %w", err)
	}
	defer reader.Close()

	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = reader.Close()
		case <-stopped:
		}
	}()
	defer close(stopped)

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) && ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read dataplane event: %w", err)
		}
		event, err := decodeEvent(record.RawSample)
		if err != nil {
			return err
		}
		consume(event)
	}
}
