package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

var (
	ErrControlType        = errors.New("invalid mup control type")
	ErrControlMagic       = errors.New("invalid mup control magic")
	ErrControlFlags       = errors.New("invalid mup control flags")
	ErrControlStatus      = errors.New("invalid mup control status")
	ErrControlPathID      = errors.New("invalid mup control path ID")
	ErrControlVersion     = errors.New("unsupported mup control version")
	ErrControlAddress     = errors.New("invalid mup control IPv4 address")
	ErrControlReserved    = errors.New("nonzero mup control reserved field")
	ErrControlLength      = errors.New("invalid mup control frame length")
	ErrControlTransport   = errors.New("invalid mup control transport")
	ErrControlPrefix      = errors.New("invalid mup control pool prefix")
	ErrControlMode        = errors.New("invalid mup control egress mode")
	ErrControlSourceRange = errors.New("invalid mup control source range")
	ErrControlRate        = errors.New("invalid mup control rate limit")
	ErrZeroInstanceNonce  = errors.New("instance nonce must be nonzero")
)

// allControlFlags holds every defined control flag bit.
const allControlFlags = ControlFlagReturnIP | ControlFlagReturnPool | ControlFlagBalancePerPacket | ControlFlagEgressPath | ControlFlagBridge | ControlFlagIngressReflect | ControlFlagBridgeVia | ControlFlagSourceRange

// MaxEgressMode is the largest egress mode of a EGRESS_REGISTER: 0 is failover, 1
// is balancer, and 2 is repeater.
const MaxEgressMode = 2

type ControlFrame struct {
	Flags         uint8
	PathID        uint16
	ServerPort    uint16
	Sequence      uint32
	ListenPort    uint16
	LeaseSeconds  uint32
	InstanceNonce uint64
	Type          ControlType
	Status        ControlStatus
	Transport     TransportID
	AdvertisedIP  netip.Addr
	ReturnIP      netip.Addr
	ReturnPrefix  uint8
	// EgressMode and EgressServer are set only in a EGRESS_REGISTER. EgressMode is the
	// egress mode of the group, at offset 18. EgressServer is the server
	// address of the egress path, at offset 44. In a direct egress path, it is the
	// source of the replies. With ControlFlagBridge, EgressServer is the address
	// of a bridge.
	EgressMode   uint8
	EgressServer netip.Addr
	// SrcFirst and SrcLast are the source range of the path. They are on the
	// wire only with ControlFlagSourceRange. In a REGISTER they are at offsets
	// 44 to 47, the bytes of the egress server. In a EGRESS_REGISTER they are at
	// offsets 36 to 39, the bytes of the sequence, so Sequence must be zero.
	SrcFirst uint16
	SrcLast  uint16
	// PeerCount is the count code of the data packets that the server received
	// on the path, at offset 44. Only a MEASURE_REPLY carries it. In a PROBE
	// and a PROBE_REPLY of an egress path, in a MEASURE and in a
	// MEASURE_REPLY, LeaseSeconds holds the count code of the sender instead
	// of a lease, and zero there means no count.
	PeerCount uint32
	// LimitKbps and LimitFlags are the rate limit of an egress path in
	// kilobits per second and its flags, at offsets 36 and 40. Only an
	// EGRESS_LIMIT carries them, and its sequence and lease are zero. A rate
	// of zero removes the limit.
	LimitKbps  uint32
	LimitFlags uint32
}

func EncodeControlFrame(dst []byte, frame ControlFrame) error {
	if len(dst) != ControlFrameLength {
		return fmt.Errorf("%w: got %d, want %d", ErrControlLength, len(dst), ControlFrameLength)
	}
	if err := validateControlFrame(frame); err != nil {
		return err
	}
	clear(dst)
	binary.BigEndian.PutUint32(dst[0:4], ControlMagic)
	dst[4] = ControlVersion
	dst[5] = byte(frame.Type)
	dst[6] = byte(frame.Transport)
	dst[7] = frame.Flags
	binary.BigEndian.PutUint16(dst[8:10], ControlFrameLength)
	binary.BigEndian.PutUint16(dst[10:12], uint16(frame.Status))
	binary.BigEndian.PutUint16(dst[12:14], frame.PathID)
	binary.BigEndian.PutUint16(dst[14:16], frame.ListenPort)
	binary.BigEndian.PutUint16(dst[16:18], frame.ServerPort)
	advertised := frame.AdvertisedIP.As4()
	copy(dst[20:24], advertised[:])
	if frame.Flags&(ControlFlagReturnIP|ControlFlagReturnPool) != 0 {
		returnIP := frame.ReturnIP.As4()
		copy(dst[24:28], returnIP[:])
	}
	if frame.Flags&ControlFlagReturnPool != 0 {
		dst[19] = frame.ReturnPrefix
	}
	binary.BigEndian.PutUint64(dst[28:36], frame.InstanceNonce)
	binary.BigEndian.PutUint32(dst[36:40], frame.Sequence)
	binary.BigEndian.PutUint32(dst[40:44], frame.LeaseSeconds)
	if frame.Type == ControlEgressLimit {
		binary.BigEndian.PutUint32(dst[36:40], frame.LimitKbps)
		binary.BigEndian.PutUint32(dst[40:44], frame.LimitFlags)
	}
	if frame.Type == ControlEgressRegister {
		dst[18] = frame.EgressMode
		server := frame.EgressServer.As4()
		copy(dst[44:48], server[:])
	}
	if frame.Type == ControlMeasureReply {
		binary.BigEndian.PutUint32(dst[44:48], frame.PeerCount)
	}
	if frame.Flags&ControlFlagSourceRange != 0 {
		offset := 44
		if frame.Type == ControlEgressRegister {
			offset = 36
		}
		binary.BigEndian.PutUint16(dst[offset:offset+2], frame.SrcFirst)
		binary.BigEndian.PutUint16(dst[offset+2:offset+4], frame.SrcLast)
	}
	return nil
}

func DecodeControlFrame(src []byte) (ControlFrame, error) {
	if len(src) != ControlFrameLength {
		return ControlFrame{}, fmt.Errorf("%w: got %d, want %d", ErrControlLength, len(src), ControlFrameLength)
	}
	if binary.BigEndian.Uint32(src[0:4]) != ControlMagic {
		return ControlFrame{}, ErrControlMagic
	}
	if src[4] != ControlVersion {
		return ControlFrame{}, ErrControlVersion
	}
	if binary.BigEndian.Uint16(src[8:10]) != ControlFrameLength {
		return ControlFrame{}, ErrControlLength
	}
	ranged := src[7]&ControlFlagSourceRange != 0
	frameType := ControlType(src[5])
	// The bytes from offset 44 hold the egress server of a EGRESS_REGISTER,
	// the source range of a REGISTER, and the peer count of a MEASURE_REPLY.
	tail := frameType == ControlEgressRegister || frameType == ControlMeasureReply ||
		ranged && frameType == ControlRegister
	if frameType != ControlEgressRegister && src[18] != 0 ||
		!tail && (src[44] != 0 || src[45] != 0 || src[46] != 0 || src[47] != 0) {
		return ControlFrame{}, ErrControlReserved
	}
	frame := ControlFrame{
		Type:          ControlType(src[5]),
		Transport:     TransportID(src[6]),
		Flags:         src[7],
		Status:        ControlStatus(binary.BigEndian.Uint16(src[10:12])),
		PathID:        binary.BigEndian.Uint16(src[12:14]),
		ListenPort:    binary.BigEndian.Uint16(src[14:16]),
		ServerPort:    binary.BigEndian.Uint16(src[16:18]),
		AdvertisedIP:  netip.AddrFrom4([4]byte(src[20:24])),
		InstanceNonce: binary.BigEndian.Uint64(src[28:36]),
		Sequence:      binary.BigEndian.Uint32(src[36:40]),
		LeaseSeconds:  binary.BigEndian.Uint32(src[40:44]),
	}
	if frame.Flags&(ControlFlagReturnIP|ControlFlagReturnPool) != 0 {
		frame.ReturnIP = netip.AddrFrom4([4]byte(src[24:28]))
	} else if src[24] != 0 || src[25] != 0 || src[26] != 0 || src[27] != 0 {
		return ControlFrame{}, ErrControlReserved
	}
	if frame.Flags&ControlFlagReturnPool != 0 {
		frame.ReturnPrefix = src[19]
	} else if src[19] != 0 {
		return ControlFrame{}, ErrControlReserved
	}
	if frame.Type == ControlMeasureReply {
		frame.PeerCount = binary.BigEndian.Uint32(src[44:48])
	}
	if frame.Type == ControlEgressLimit {
		frame.LimitKbps, frame.LimitFlags = frame.Sequence, frame.LeaseSeconds
		frame.Sequence, frame.LeaseSeconds = 0, 0
	}
	if frame.Type == ControlEgressRegister {
		frame.EgressMode = src[18]
		frame.EgressServer = netip.AddrFrom4([4]byte(src[44:48]))
	}
	if ranged {
		switch frame.Type {
		case ControlRegister:
			frame.SrcFirst = binary.BigEndian.Uint16(src[44:46])
			frame.SrcLast = binary.BigEndian.Uint16(src[46:48])
		case ControlEgressRegister:
			frame.SrcFirst = binary.BigEndian.Uint16(src[36:38])
			frame.SrcLast = binary.BigEndian.Uint16(src[38:40])
			frame.Sequence = 0
		}
	}
	if err := validateControlFrame(frame); err != nil {
		return ControlFrame{}, err
	}
	return frame, nil
}

func GenerateInstanceNonce(source io.Reader) (uint64, error) {
	var buf [8]byte
	if _, err := io.ReadFull(source, buf[:]); err != nil {
		return 0, fmt.Errorf("read instance nonce: %w", err)
	}
	nonce := binary.BigEndian.Uint64(buf[:])
	if nonce == 0 {
		return 0, ErrZeroInstanceNonce
	}
	return nonce, nil
}

func RandomInstanceNonce() (uint64, error) {
	return GenerateInstanceNonce(rand.Reader)
}

func validateControlFrame(frame ControlFrame) error {
	if frame.Type < ControlRegister || frame.Type > ControlEgressLimit {
		return ErrControlType
	}
	if frame.Type == ControlEgressLimit {
		// The rate and its flags take the bytes of the sequence and the
		// lease, and the frame has no flag of its own.
		if frame.Flags != 0 || frame.LimitFlags&^EgressLimitPerMember != 0 {
			return ErrControlFlags
		}
		if frame.Sequence != 0 || frame.LeaseSeconds != 0 {
			return ErrControlReserved
		}
		if frame.LimitKbps == 0 && frame.LimitFlags != 0 {
			return ErrControlFlags
		}
		if frame.LimitKbps != 0 && (frame.LimitKbps < MinEgressLimitKbps || frame.LimitKbps > MaxEgressLimitKbps) {
			return ErrControlRate
		}
	} else if frame.LimitKbps != 0 || frame.LimitFlags != 0 {
		return ErrControlReserved
	}
	if frame.Transport != TransportUDP && frame.Transport != TransportICMP {
		return ErrControlTransport
	}
	if frame.Flags&^allControlFlags != 0 {
		return ErrControlFlags
	}
	if frame.Flags&ControlFlagReturnIP != 0 && frame.Flags&ControlFlagReturnPool != 0 {
		return ErrControlFlags
	}
	if frame.Flags&ControlFlagBalancePerPacket != 0 && frame.Flags&ControlFlagReturnPool == 0 {
		return ErrControlFlags
	}
	if frame.Flags&ControlFlagEgressPath != 0 &&
		frame.Type != ControlProbe && frame.Type != ControlProbeReply {
		return ErrControlFlags
	}
	if frame.Flags&ControlFlagBridge != 0 && frame.Type != ControlEgressRegister {
		return ErrControlFlags
	}
	if frame.Flags&ControlFlagBridgeVia != 0 &&
		(frame.Flags&ControlFlagBridge == 0 || frame.Flags&(ControlFlagReturnIP|ControlFlagReturnPool) == 0) {
		return ErrControlFlags
	}
	// A MEASURE and its reply have no flag, or the flags of a REGISTER of
	// one member of an ingress reflect path.
	measure := frame.Type == ControlMeasure || frame.Type == ControlMeasureReply
	if measure && frame.Flags != 0 && frame.Flags != ControlFlagIngressReflect|ControlFlagReturnIP {
		return ErrControlFlags
	}
	if frame.PeerCount != 0 && frame.Type != ControlMeasureReply {
		return ErrControlReserved
	}
	if frame.Flags&ControlFlagIngressReflect != 0 {
		if frame.Type != ControlRegister && frame.Type != ControlRegisterACK && !measure {
			return ErrControlFlags
		}
		if frame.Flags&(ControlFlagReturnIP|ControlFlagReturnPool) == 0 {
			return ErrControlFlags
		}
	}
	if frame.Flags&ControlFlagSourceRange != 0 {
		if frame.Type != ControlRegister && frame.Type != ControlEgressRegister {
			return ErrControlFlags
		}
		if frame.SrcFirst < 1 || frame.SrcFirst > frame.SrcLast {
			return ErrControlSourceRange
		}
		if frame.Type == ControlEgressRegister && frame.Sequence != 0 {
			return ErrControlReserved
		}
	} else if frame.SrcFirst != 0 || frame.SrcLast != 0 {
		return ErrControlFlags
	}
	if frame.Type == ControlEgressRegister {
		if !frame.EgressServer.Is4() || frame.EgressServer.IsUnspecified() {
			return ErrControlAddress
		}
		if frame.EgressMode > MaxEgressMode {
			return ErrControlMode
		}
	} else if frame.EgressMode != 0 || frame.EgressServer.IsValid() {
		return ErrControlReserved
	}
	if frame.Status > ControlStatusNoReflector {
		return ErrControlStatus
	}
	if frame.PathID > MaxPathID {
		return ErrControlPathID
	}
	if !frame.AdvertisedIP.Is4() || frame.AdvertisedIP.IsUnspecified() {
		return ErrControlAddress
	}
	if frame.Flags&(ControlFlagReturnIP|ControlFlagReturnPool) != 0 {
		if !frame.ReturnIP.Is4() || frame.ReturnIP.IsUnspecified() {
			return ErrControlAddress
		}
	} else if frame.ReturnIP.IsValid() {
		return ErrControlFlags
	}
	if frame.Flags&ControlFlagReturnPool != 0 {
		if frame.ReturnPrefix < 1 || frame.ReturnPrefix > 31 {
			return ErrControlPrefix
		}
	} else if frame.ReturnPrefix != 0 {
		return ErrControlFlags
	}
	if frame.InstanceNonce == 0 {
		return ErrZeroInstanceNonce
	}
	return nil
}
