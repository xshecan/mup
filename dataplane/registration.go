package dataplane

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/protocol"
)

type RegistrationSettings struct {
	AdvertisedIP  netip.Addr
	InstanceNonce uint64
	ReturnIP      netip.Addr
	ReturnPrefix  uint8
	Balance       config.Balance
	ListenPort    uint16
	PathCount     uint8
	ExpiresAtNS   uint64
	Path          RegisteredPathSettings
	// IngressReflect marks a path that reflects the ingress. The path source is the
	// via host, not the advertised IP, so the server accepts the reflected
	// ingress from it. The path carries no reply reflection.
	IngressReflect bool
}

type ClientKey struct {
	AdvertisedIP  netip.Addr
	InstanceNonce uint64
}

type RegisteredPathSettings struct {
	SourceIP   netip.Addr
	LocalIP    netip.Addr
	ServerPort uint16
	Transport  protocol.TransportID
	PathID     uint16
}

func encodeRegistrationSettings(settings RegistrationSettings) (
	mupClientKeyV1,
	mupRegistrationValueV1,
	mupRegisteredPathKeyV1,
	mupRegisteredPathValueV1,
	error,
) {
	var key mupClientKeyV1
	var value mupRegistrationValueV1
	var pathKey mupRegisteredPathKeyV1
	var pathValue mupRegisteredPathValueV1

	advertisedIP, err := requiredIPv4Word(settings.AdvertisedIP, "registration advertised IP")
	if err != nil {
		return key, value, pathKey, pathValue, err
	}
	if settings.InstanceNonce == 0 || settings.ListenPort == 0 || settings.ExpiresAtNS == 0 {
		return key, value, pathKey, pathValue, errors.New("registration nonce, listen port, and expiry must be nonzero")
	}
	if settings.PathCount == 0 || settings.PathCount > config.MaxPaths {
		return key, value, pathKey, pathValue, fmt.Errorf("registration path count must be between 1 and %d", config.MaxPaths)
	}
	if !settings.IngressReflect && settings.Path.SourceIP != settings.AdvertisedIP {
		return key, value, pathKey, pathValue, errors.New("registered path source must equal advertised IP")
	}
	sourceIP, err := requiredIPv4Word(settings.Path.SourceIP, "registered path source IP")
	if err != nil {
		return key, value, pathKey, pathValue, err
	}
	localIP, err := requiredIPv4Word(settings.Path.LocalIP, "registered path local IP")
	if err != nil {
		return key, value, pathKey, pathValue, err
	}
	if settings.Path.ServerPort == 0 || settings.Path.PathID > protocol.MaxPathID ||
		settings.Path.Transport > protocol.TransportICMP {
		return key, value, pathKey, pathValue, errors.New("registered path server port, path ID, or transport is invalid")
	}

	var returnIP uint32
	var flags uint8
	var prefix uint8
	// An ingress reflect path carries no reply reflection. Its return flags describe
	// the ingress reflect, so the server records only the ingress reflect flag on
	// the path, and keys the path by the via source above.
	if !settings.IngressReflect {
		if settings.ReturnPrefix != 0 {
			returnIP, err = requiredIPv4Word(settings.ReturnIP, "registration return pool base")
			if err != nil {
				return key, value, pathKey, pathValue, err
			}
			flags = protocol.ControlFlagReturnPool
			if settings.Balance == config.BalancePerPacket {
				flags |= protocol.ControlFlagBalancePerPacket
			}
			prefix = settings.ReturnPrefix
		} else if settings.ReturnIP.IsValid() {
			returnIP, err = requiredIPv4Word(settings.ReturnIP, "registration return IP")
			if err != nil {
				return key, value, pathKey, pathValue, err
			}
			flags = protocol.ControlFlagReturnIP
		}
	}
	pathFlags := flags
	if settings.IngressReflect {
		pathFlags |= protocol.ControlFlagIngressReflect
	}
	key = mupClientKeyV1{
		AdvertisedIp:  advertisedIP,
		InstanceNonce: settings.InstanceNonce,
	}
	value = mupRegistrationValueV1{
		ReturnIp:    returnIP,
		ListenPort:  settings.ListenPort,
		Flags:       flags,
		PathCount:   settings.PathCount,
		ExpiresAtNs: settings.ExpiresAtNS,
	}
	pathKey = mupRegisteredPathKeyV1{
		SourceIp:   sourceIP,
		LocalIp:    localIP,
		ServerPort: settings.Path.ServerPort,
		Transport:  uint8(settings.Path.Transport),
	}
	pathValue = mupRegisteredPathValueV1{
		Client:      key,
		ExpiresAtNs: settings.ExpiresAtNS,
		PathId:      settings.Path.PathID,
		Flags:       pathFlags,
		Prefix:      prefix,
		ReturnIp:    returnIP,
		ListenPort:  settings.ListenPort,
	}
	return key, value, pathKey, pathValue, nil
}

func applyRegistrationSettings(registrations, paths configurationMap, settings RegistrationSettings) error {
	key, value, pathKey, pathValue, err := encodeRegistrationSettings(settings)
	if err != nil {
		return err
	}
	if err := registrations.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update client registration: %w", err)
	}
	if err := paths.Update(pathKey, pathValue, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update registered path: %w", err)
	}
	return nil
}

type deletingMap interface {
	Delete(key interface{}) error
}

func revokeRegistration(registrations deletingMap, client ClientKey) error {
	advertisedIP, err := requiredIPv4Word(client.AdvertisedIP, "client advertised IP")
	if err != nil {
		return err
	}
	if client.InstanceNonce == 0 {
		return errors.New("client instance nonce must be nonzero")
	}
	key := mupClientKeyV1{
		AdvertisedIp:  advertisedIP,
		InstanceNonce: client.InstanceNonce,
	}
	if err := registrations.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete client registration: %w", err)
	}
	return nil
}
