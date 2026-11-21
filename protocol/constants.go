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
	// ControlDownRegister declares one down path of a group: a way that the
	// server sends replies to the client. The client sends it on its up
	// paths, and each server that owns the address of the down path keeps it.
	ControlDownRegister
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
	// ControlStatusNoReflector answers a REGISTER of a path with a return
	// pool that has no healthy reflector. The server keeps the registration,
	// but it cannot return replies on the path, so the client counts the
	// path as missed.
	ControlStatusNoReflector
)

const (
	// ControlFlagReturnIP marks a route with one return IP.
	ControlFlagReturnIP uint8 = 1 << 0
	// ControlFlagReturnPool marks a route with a return pool. The return IP
	// is the pool base, and ReturnPrefix is its prefix length.
	ControlFlagReturnPool uint8 = 1 << 1
	// ControlFlagBalancePerPacket picks the per-packet balance mode of a
	// return pool. A pool without it uses the per-peer mode.
	ControlFlagBalancePerPacket uint8 = 1 << 2
	// ControlFlagDownPath marks a PROBE or a PROBE_REPLY of a down path. Its
	// path ID is then the ID of the down path.
	ControlFlagDownPath uint8 = 1 << 3
	// ControlFlagBridge marks a DOWN_REGISTER of a down path through a MUP
	// bridge. The down server field then holds the bridge address, and the
	// server wraps the replies of the path for the bridge.
	ControlFlagBridge uint8 = 1 << 4
	// ControlFlagUpReflect marks a REGISTER of an up path that reflects the
	// upstream through its return IP, with ControlFlagReturnIP, or through one
	// member of its pool, with ControlFlagReturnPool. The server then accepts
	// the reflected upstream from that source, and it does not reflect the
	// replies of the path.
	ControlFlagUpReflect uint8 = 1 << 5
)

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
	DropSourceLimit
	DropDownstreamSource
	DropBridgeSource
	DropBridgePacket
	DropBridgeSize
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
	DropSourceLimit:       "SOURCE_LIMIT",
	DropDownstreamSource:  "DOWNSTREAM_SOURCE",
	DropBridgeSource:      "BRIDGE_SOURCE",
	DropBridgePacket:      "BRIDGE_PACKET",
	DropBridgeSize:        "BRIDGE_SIZE",
}

func (r DropReason) String() string {
	if int(r) < len(dropReasonNames) {
		return dropReasonNames[r]
	}
	return fmt.Sprintf("REASON_%d", uint32(r))
}
