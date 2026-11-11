package dataplane

import (
	"encoding/binary"
	"fmt"

	"github.com/xshecan/mup/protocol"
)

const (
	dropReasonCount = int(protocol.DropDownstreamSource) + 1
	eventRecordSize = 32
)

type StatsSnapshot struct {
	Drops                [dropReasonCount]uint64
	Registrations        uint64
	RegisteredPaths      uint64
	ClientRoutes         uint64
	ServerRoutes         uint64
	DuplicateEntries     uint64
	PeerQuarantined      uint64
	PortsQuarantined     uint64
	PeerTokensAvailable  uint64
	TargetPortsAvailable uint64
	HealthyMask          uint32
	PathGeneration       uint32
}

type Event struct {
	TimestampNS uint64
	Reason      protocol.DropReason
	Ifindex     uint32
}

func aggregatePerCPU(values []uint64) uint64 {
	var total uint64
	for _, value := range values {
		total += value
	}
	return total
}

func availableResources(total, used, quarantined uint64) uint64 {
	if used >= total || quarantined >= total-used {
		return 0
	}
	return total - used - quarantined
}

func decodeEvent(raw []byte) (Event, error) {
	if len(raw) != eventRecordSize {
		return Event{}, fmt.Errorf("decode dataplane event: size %d, want %d", len(raw), eventRecordSize)
	}
	reason := protocol.DropReason(binary.NativeEndian.Uint32(raw[8:12]))
	if int(reason) >= dropReasonCount {
		return Event{}, fmt.Errorf("decode dataplane event: invalid reason %d", reason)
	}
	return Event{
		TimestampNS: binary.NativeEndian.Uint64(raw[0:8]),
		Reason:      reason,
		Ifindex:     binary.NativeEndian.Uint32(raw[12:16]),
	}, nil
}
