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
	// ControlEgressRegister declares one egress path of a group: a way that the
	// server sends replies to the client. The client sends it on its ingress
	// paths, and each server that owns the address of the egress path keeps it.
	ControlEgressRegister
	// ControlMeasure measures an ingress path. The client sends it on each
	// ingress path with the count code of the data packets that it sent on
	// the path. A server that does not know the type drops it.
	ControlMeasure
	// ControlMeasureReply answers a MEASURE. It is a copy of the MEASURE with
	// the count code of the data packets that the server received on the
	// path, and the server sends it like a REGISTER_ACK.
	ControlMeasureReply
	// ControlEgressLimit carries the rate limit of one egress path. The client
	// sends it right after each EGRESS_REGISTER of a path with a limit, in the
	// same way. Its first 36 bytes are those of the EGRESS_REGISTER with no
	// flag, and the rate and its flags follow. A server that does not know the
	// type drops it and applies no limit.
	ControlEgressLimit
)

// EgressLimitPerMember is the flag of an EGRESS_LIMIT that gives each member
// of the via of the path its own limit of the rate.
const EgressLimitPerMember uint32 = 1 << 0

// MinEgressLimitKbps and MaxEgressLimitKbps are the smallest and the largest
// rate of an EGRESS_LIMIT in kilobits per second, 8 kbit and 100 gbit. A rate
// of zero removes the limit.
const (
	MinEgressLimitKbps uint32 = 8
	MaxEgressLimitKbps uint32 = 100_000_000
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
	// ControlFlagEgressPath marks a PROBE or a PROBE_REPLY of an egress path. Its
	// path ID is then the ID of the egress path.
	ControlFlagEgressPath uint8 = 1 << 3
	// ControlFlagBridge marks an EGRESS_REGISTER of an egress path through a MUP
	// bridge. The egress server field then holds the bridge address, and the
	// server wraps the replies of the path for the bridge.
	ControlFlagBridge uint8 = 1 << 4
	// ControlFlagIngressReflect marks a REGISTER of an ingress path that reflects the
	// ingress through its return IP, with ControlFlagReturnIP, or through one
	// member of its pool, with ControlFlagReturnPool. The server then accepts
	// the reflected ingress from that source, and it does not reflect the
	// replies of the path.
	ControlFlagIngressReflect uint8 = 1 << 5
	// ControlFlagBridgeVia marks an EGRESS_REGISTER of an egress path through a
	// MUP bridge whose return IP or pool applies to the leg from the server to
	// the bridge. The server sends the wrapped reply with the member as its
	// source, and the bridge sends the reply from its own address. It needs
	// ControlFlagBridge and ControlFlagReturnIP or ControlFlagReturnPool.
	ControlFlagBridgeVia uint8 = 1 << 6
	// ControlFlagSourceRange marks a REGISTER or an EGRESS_REGISTER of a path with a
	// source range. The frame then holds the first and the last value of the
	// range, and every data packet of the path takes its source port or its
	// ICMP identifier from it. The control frames keep the fixed port.
	ControlFlagSourceRange uint8 = 1 << 7
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
	DropEgressSource
	DropBridgeSource
	DropBridgePacket
	DropBridgeSize
	// DropRateLimit drops a data packet when no path of its group has room
	// for it under the bandwidth limits of the paths.
	DropRateLimit
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
	DropEgressSource:      "EGRESS_SOURCE",
	DropBridgeSource:      "BRIDGE_SOURCE",
	DropBridgePacket:      "BRIDGE_PACKET",
	DropBridgeSize:        "BRIDGE_SIZE",
	DropRateLimit:         "RATE_LIMIT",
}

func (r DropReason) String() string {
	if int(r) < len(dropReasonNames) {
		return dropReasonNames[r]
	}
	return fmt.Sprintf("REASON_%d", uint32(r))
}
