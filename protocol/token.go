package protocol

import (
	"errors"
	"fmt"
)

var ErrPeerTokenRange = errors.New("peer token outside v1 range")

func EncodePeerToken(token uint32) ([3]byte, error) {
	if token == 0 || token > MaxPeerToken {
		return [3]byte{}, fmt.Errorf("%w: %d", ErrPeerTokenRange, token)
	}
	return [3]byte{byte(token >> 16), byte(token >> 8), byte(token)}, nil
}

func DecodePeerToken(reserved [3]byte) (uint32, error) {
	token := uint32(reserved[0])<<16 | uint32(reserved[1])<<8 | uint32(reserved[2])
	if token == 0 || token > MaxPeerToken {
		return 0, fmt.Errorf("%w: %d", ErrPeerTokenRange, token)
	}
	return token, nil
}

func InsertPeerToken(packet []byte, token uint32) error {
	if err := ValidateWireGuard(packet, false); err != nil {
		return err
	}
	encoded, err := EncodePeerToken(token)
	if err != nil {
		return err
	}
	copy(packet[1:4], encoded[:])
	return nil
}

func ClearPeerToken(packet []byte) error {
	if err := ValidateWireGuard(packet, true); err != nil {
		return err
	}
	clear(packet[1:4])
	return nil
}

func PeerToken(packet []byte) (uint32, error) {
	if len(packet) < 4 {
		return 0, ErrWireGuardLength
	}
	return DecodePeerToken([3]byte{packet[1], packet[2], packet[3]})
}
