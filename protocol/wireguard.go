package protocol

import "errors"

const (
	MessageHandshakeInitiation byte = 1
	MessageHandshakeResponse   byte = 2
	MessageCookieReply         byte = 3
	MessageTransportData       byte = 4

	HandshakeInitiationLength = 148
	HandshakeResponseLength   = 92
	TransportDataMinLength    = 32
	CookieReplyLength         = 64
)

var (
	ErrWireGuardType     = errors.New("unsupported wireguard message type")
	ErrWireGuardLength   = errors.New("invalid wireguard message length")
	ErrWireGuardReserved = errors.New("invalid wireguard reserved bytes")
)

func ValidateWireGuard(packet []byte, expectPeerToken bool) error {
	if len(packet) < 4 {
		return ErrWireGuardLength
	}

	switch packet[0] {
	case MessageHandshakeInitiation:
		if len(packet) != HandshakeInitiationLength {
			return ErrWireGuardLength
		}
	case MessageHandshakeResponse:
		if len(packet) != HandshakeResponseLength {
			return ErrWireGuardLength
		}
	case MessageCookieReply:
		if len(packet) != CookieReplyLength {
			return ErrWireGuardLength
		}
	case MessageTransportData:
		if len(packet) < TransportDataMinLength {
			return ErrWireGuardLength
		}
	default:
		return ErrWireGuardType
	}

	reserved := [3]byte{packet[1], packet[2], packet[3]}
	if expectPeerToken {
		if _, err := DecodePeerToken(reserved); err != nil {
			return err
		}
		return nil
	}
	if reserved != [3]byte{} {
		return ErrWireGuardReserved
	}
	return nil
}
