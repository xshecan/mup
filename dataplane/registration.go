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

// RegisteredPathSettings is one path of a REGISTER. SrcFirst and SrcLast are
// the source range of the path, or zero for none. An ICMP path with a range
// also gets a tagged entry, because its identifiers are random values of the
// range.
type RegisteredPathSettings struct {
	SourceIP   netip.Addr
	LocalIP    netip.Addr
	ServerPort uint16
	Transport  protocol.TransportID
	PathID     uint16
	SrcFirst   uint16
	SrcLast    uint16
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
	src, err := encodePathSrc("registered path", settings.Path.SrcFirst, settings.Path.SrcLast)
	if err != nil {
		return key, value, pathKey, pathValue, err
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
		SrcFirst:    src.First,
		SrcLast:     src.Last,
		ServerPort:  settings.Path.ServerPort,
	}
	return key, value, pathKey, pathValue, nil
}

// taggedRegisteredPathKey returns the tagged key of a registered path: the
// exact key with a server port of 0 and the tag of the path, its path ID plus
// one. Only an ICMP path with a source range has one, because the server finds
// its tagged Echo packets by the tag, not by the identifier.
func taggedRegisteredPathKey(key mupRegisteredPathKeyV1, value mupRegisteredPathValueV1) (mupRegisteredPathKeyV1, bool) {
	if key.Tag != 0 || key.Transport != uint8(protocol.TransportICMP) || value.SrcFirst == 0 || value.PathId > protocol.MaxPathID {
		return mupRegisteredPathKeyV1{}, false
	}
	key.ServerPort = 0
	key.Tag = uint8(value.PathId + 1)
	return key, true
}

// exactRegisteredPathKey returns the exact twin of a tagged key, with the
// server port that the tagged value holds.
func exactRegisteredPathKey(key mupRegisteredPathKeyV1, value mupRegisteredPathValueV1) mupRegisteredPathKeyV1 {
	key.ServerPort = value.ServerPort
	key.Tag = 0
	return key
}

// staleTaggedPaths returns the tagged keys whose exact twin is not in paths,
// or whose twin holds another value. A tagged key lives only with its twin,
// and Go writes both with one value.
func staleTaggedPaths(paths map[mupRegisteredPathKeyV1]mupRegisteredPathValueV1) []mupRegisteredPathKeyV1 {
	var stale []mupRegisteredPathKeyV1
	for key, value := range paths {
		if key.Tag == 0 {
			continue
		}
		if twin, ok := paths[exactRegisteredPathKey(key, value)]; ok && twin == value {
			continue
		}
		stale = append(stale, key)
	}
	return stale
}

// registeredPathMap is the map of the registered paths. A REGISTER reads the
// old entry of its path, so it can delete a tagged entry that the path no
// longer has.
type registeredPathMap interface {
	configurationMap
	deletingMap
	Lookup(key, valueOut interface{}) error
}

// applyRegistrationSettings writes a registration and its path. The exact key
// of the path holds its server port and tag 0. An ICMP path with a source
// range also has a tagged key with the same value. When the REGISTER drops the
// range, or moves the path to another path ID, the tagged key of the old entry
// goes away.
func applyRegistrationSettings(registrations configurationMap, paths registeredPathMap, settings RegistrationSettings) error {
	key, value, pathKey, pathValue, err := encodeRegistrationSettings(settings)
	if err != nil {
		return err
	}
	var old mupRegisteredPathValueV1
	hasOld := true
	if err := paths.Lookup(pathKey, &old); errors.Is(err, ebpf.ErrKeyNotExist) {
		hasOld = false
	} else if err != nil {
		return fmt.Errorf("look up registered path: %w", err)
	}
	if err := registrations.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update client registration: %w", err)
	}
	if err := paths.Update(pathKey, pathValue, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update registered path: %w", err)
	}
	tagged, hasTagged := taggedRegisteredPathKey(pathKey, pathValue)
	if hasTagged {
		if err := paths.Update(tagged, pathValue, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update tagged registered path: %w", err)
		}
	}
	if !hasOld {
		return nil
	}
	oldTagged, hadTagged := taggedRegisteredPathKey(pathKey, old)
	if !hadTagged || (hasTagged && oldTagged == tagged) {
		return nil
	}
	// Another path of the same source can own the old tagged key now. Only
	// a tagged entry that still points at this server port goes away.
	var current mupRegisteredPathValueV1
	if err := paths.Lookup(oldTagged, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("look up old tagged registered path: %w", err)
	}
	if exactRegisteredPathKey(oldTagged, current) != pathKey {
		return nil
	}
	if err := paths.Delete(oldTagged); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete old tagged registered path: %w", err)
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
