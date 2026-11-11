package protocol

const DuplicateIdentityLength = 24

func DuplicateIdentity(wireguard []byte) ([DuplicateIdentityLength]byte, error) {
	var identity [DuplicateIdentityLength]byte
	if err := ValidateWireGuard(wireguard, true); err != nil {
		return identity, err
	}
	copy(identity[:], wireguard[:DuplicateIdentityLength])
	return identity, nil
}
