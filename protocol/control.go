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
	ErrControlType       = errors.New("invalid mup control type")
	ErrControlMagic      = errors.New("invalid mup control magic")
	ErrControlFlags      = errors.New("invalid mup control flags")
	ErrControlStatus     = errors.New("invalid mup control status")
	ErrControlPathID     = errors.New("invalid mup control path ID")
	ErrControlVersion    = errors.New("unsupported mup control version")
	ErrControlAddress    = errors.New("invalid mup control IPv4 address")
	ErrControlReserved   = errors.New("nonzero mup control reserved field")
	ErrControlLength     = errors.New("invalid mup control frame length")
	ErrControlTransport  = errors.New("invalid mup control transport")
	ErrZeroInstanceNonce = errors.New("instance nonce must be nonzero")
)

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
	if frame.Flags&ControlFlagReturnIP != 0 {
		returnIP := frame.ReturnIP.As4()
		copy(dst[24:28], returnIP[:])
	}
	binary.BigEndian.PutUint64(dst[28:36], frame.InstanceNonce)
	binary.BigEndian.PutUint32(dst[36:40], frame.Sequence)
	binary.BigEndian.PutUint32(dst[40:44], frame.LeaseSeconds)
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
	if src[18] != 0 || src[19] != 0 || src[44] != 0 || src[45] != 0 || src[46] != 0 || src[47] != 0 {
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
	if frame.Flags&ControlFlagReturnIP != 0 {
		frame.ReturnIP = netip.AddrFrom4([4]byte(src[24:28]))
	} else if src[24] != 0 || src[25] != 0 || src[26] != 0 || src[27] != 0 {
		return ControlFrame{}, ErrControlReserved
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
	if frame.Type < ControlRegister || frame.Type > ControlError {
		return ErrControlType
	}
	if frame.Transport != TransportUDP && frame.Transport != TransportICMP {
		return ErrControlTransport
	}
	if frame.Flags&^ControlFlagReturnIP != 0 {
		return ErrControlFlags
	}
	if frame.Status > ControlStatusCapacityExhausted {
		return ErrControlStatus
	}
	if frame.PathID > MaxPathID {
		return ErrControlPathID
	}
	if !frame.AdvertisedIP.Is4() || frame.AdvertisedIP.IsUnspecified() {
		return ErrControlAddress
	}
	if frame.Flags&ControlFlagReturnIP != 0 {
		if !frame.ReturnIP.Is4() || frame.ReturnIP.IsUnspecified() {
			return ErrControlAddress
		}
	} else if frame.ReturnIP.IsValid() {
		return ErrControlFlags
	}
	if frame.InstanceNonce == 0 {
		return ErrZeroInstanceNonce
	}
	return nil
}
