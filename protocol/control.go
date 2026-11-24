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
	if frame.Type == ControlEgressRegister {
		dst[18] = frame.EgressMode
		server := frame.EgressServer.As4()
		copy(dst[44:48], server[:])
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
	if ControlType(src[5]) != ControlEgressRegister &&
		(src[18] != 0 || (!ranged || ControlType(src[5]) != ControlRegister) &&
			(src[44] != 0 || src[45] != 0 || src[46] != 0 || src[47] != 0)) {
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
	if frame.Type < ControlRegister || frame.Type > ControlEgressRegister {
		return ErrControlType
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
	if frame.Flags&ControlFlagIngressReflect != 0 {
		if frame.Type != ControlRegister && frame.Type != ControlRegisterACK {
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
