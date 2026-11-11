package protocol

import "fmt"

const (
	MaxPathID          = 7
	ControlFrameLength = 48

	ControlVersion uint8  = 1
	MaxPeerToken   uint32 = 4095
	ControlMagic   uint32 = 0x4d555043
)

type TransportID uint8

const (
	TransportUDP TransportID = iota
	TransportICMP
)

func (t TransportID) String() string {
	switch t {
	case TransportUDP:
		return "udp"
	case TransportICMP:
		return "icmp"
	default:
		return fmt.Sprintf("transport(%d)", uint8(t))
	}
}

type ControlType uint8

const (
	ControlRegister ControlType = iota + 1
	ControlRegisterACK
	ControlProbe
	ControlProbeReply
	ControlDeregister
	ControlError
)

type ControlStatus uint16

const (
	ControlStatusOK ControlStatus = iota
	ControlStatusMalformed
	ControlStatusSourceMismatch
	ControlStatusPortMismatch
	ControlStatusTransportMismatch
	ControlStatusPathIDInvalid
	ControlStatusCapacityExhausted
)

const ControlFlagReturnIP uint8 = 1 << 0

type DropReason uint32

const (
	DropNone DropReason = iota
	DropMalformedIPv4
	DropIPv4Options
	DropIPv4Fragment
	DropMalformedL4
	DropWireGuardType
	DropWireGuardLength
	DropWireGuardReserved
	DropNotRegistered
	DropPathMismatch
	DropTransport
	DropPeerTokenPool
	DropTargetPortPool
	DropMapInvariant
	DropRouteMiss
	DropNoPath
	DropDuplicate
	DropFIB
	DropNeighbor
	DropTailCall
	DropChecksum
	DropReturnPolicy
	DropDownstreamSource
)

// dropReasonNames matches the MUP_DROP_* names in bpf/include/mup_abi.h.
var dropReasonNames = [...]string{
	DropNone:              "NONE",
	DropMalformedIPv4:     "MALFORMED_IPV4",
	DropIPv4Options:       "IPV4_OPTIONS",
	DropIPv4Fragment:      "IPV4_FRAGMENT",
	DropMalformedL4:       "MALFORMED_L4",
	DropWireGuardType:     "WG_TYPE",
	DropWireGuardLength:   "WG_LENGTH",
	DropWireGuardReserved: "WG_RESERVED",
	DropNotRegistered:     "NOT_REGISTERED",
	DropPathMismatch:      "PATH_MISMATCH",
	DropTransport:         "TRANSPORT",
	DropPeerTokenPool:     "PEER_TOKEN_POOL",
	DropTargetPortPool:    "TARGET_PORT_POOL",
	DropMapInvariant:      "MAP_INVARIANT",
	DropRouteMiss:         "ROUTE_MISS",
	DropNoPath:            "NO_PATH",
	DropDuplicate:         "DUPLICATE",
	DropFIB:               "FIB",
	DropNeighbor:          "NEIGHBOR",
	DropTailCall:          "TAIL_CALL",
	DropChecksum:          "CHECKSUM",
	DropReturnPolicy:      "RETURN_POLICY",
	DropDownstreamSource:  "DOWNSTREAM_SOURCE",
}

func (r DropReason) String() string {
	if int(r) < len(dropReasonNames) {
		return dropReasonNames[r]
	}
	return fmt.Sprintf("REASON_%d", uint32(r))
}
