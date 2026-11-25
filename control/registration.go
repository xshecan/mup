package control

import (
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/xshecan/mup/protocol"
)

var (
	ErrRegistrationType      = errors.New("control frame is not REGISTER")
	ErrRegistrationSource    = errors.New("observed source does not match advertised IP")
	ErrRegistrationPort      = errors.New("registration port does not match server port")
	ErrRegistrationTransport = errors.New("outer transport does not match registration transport")
	ErrRegistrationPath      = errors.New("invalid registration path")
	ErrMeasureType           = errors.New("control frame is not MEASURE")
	ErrMeasureUnknown        = errors.New("MEASURE is not on a registered path of its client")
)

type ClientKey struct {
	AdvertisedIP  netip.Addr
	InstanceNonce uint64
}

type PathKey struct {
	Local      netip.Addr
	Source     netip.Addr
	Transport  protocol.TransportID
	ServerPort uint16
}

type RegistrationRequest struct {
	Frame protocol.ControlFrame
	Path  PathKey
}

type RegistrationResult struct {
	Key       ClientKey
	ExpiresAt time.Time
	Replaced  *ClientKey
}

type ClientRegistration struct {
	Key        ClientKey
	ReturnIP   netip.Addr
	ExpiresAt  time.Time
	ListenPort uint16
}

type pathRegistration struct {
	pathID    uint16
	client    ClientKey
	expiresAt time.Time
	// ingressReflect marks a path that a reflected REGISTER made, so its
	// source is a via host of the client.
	ingressReflect bool
}

type Registry struct {
	firstPort uint16
	lastPort  uint16

	mu    sync.RWMutex
	lease time.Duration

	owners  map[netip.Addr]ClientKey
	paths   map[PathKey]pathRegistration
	clients map[ClientKey]ClientRegistration
}

// NewRegistry accepts REGISTER frames for the server ports from firstPort to
// lastPort.
func NewRegistry(firstPort, lastPort uint16, lease time.Duration) *Registry {
	return &Registry{
		firstPort: firstPort, lastPort: lastPort, lease: lease,
		owners:  make(map[netip.Addr]ClientKey),
		paths:   make(map[PathKey]pathRegistration),
		clients: make(map[ClientKey]ClientRegistration),
	}
}

func (r *Registry) Register(now time.Time, request RegistrationRequest) (RegistrationResult, error) {
	if err := r.validate(request); err != nil {
		return RegistrationResult{}, err
	}
	key := ClientKey{
		AdvertisedIP:  request.Frame.AdvertisedIP,
		InstanceNonce: request.Frame.InstanceNonce,
	}
	expiresAt := now.Add(r.lease)

	r.mu.Lock()
	defer r.mu.Unlock()

	var replaced *ClientKey
	if owner, exists := r.owners[key.AdvertisedIP]; exists && owner != key {
		old := owner
		replaced = &old
		r.removeClientLocked(owner)
	}
	r.owners[key.AdvertisedIP] = key
	r.clients[key] = ClientRegistration{
		Key:        key,
		ReturnIP:   request.Frame.ReturnIP,
		ListenPort: request.Frame.ListenPort,
		ExpiresAt:  expiresAt,
	}
	r.paths[request.Path] = pathRegistration{
		client:         key,
		pathID:         request.Frame.PathID,
		expiresAt:      expiresAt,
		ingressReflect: request.Frame.Flags&protocol.ControlFlagIngressReflect != 0,
	}
	return RegistrationResult{Key: key, Replaced: replaced, ExpiresAt: expiresAt}, nil
}

func (r *Registry) ResolvePath(now time.Time, path PathKey) (ClientKey, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, exists := r.paths[path]
	if !exists || !now.Before(entry.expiresAt) {
		return ClientKey{}, false
	}
	return entry.client, true
}

// IsReflectPathOf reports whether path is a live ingress reflect path of
// client. A control frame that arrives on such a path comes from a via host
// of the client, not from its advertised IP.
func (r *Registry) IsReflectPathOf(now time.Time, path PathKey, client ClientKey) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, exists := r.paths[path]
	return exists && entry.ingressReflect && entry.client == client && now.Before(entry.expiresAt)
}

// Expire forgets expired paths and every client without a live path. It
// returns the forgotten clients.
func (r *Registry) Expire(now time.Time) []ClientKey {
	r.mu.Lock()
	defer r.mu.Unlock()

	live := make(map[ClientKey]struct{}, len(r.clients))
	for path, entry := range r.paths {
		if !now.Before(entry.expiresAt) {
			delete(r.paths, path)
			continue
		}
		live[entry.client] = struct{}{}
	}
	var expired []ClientKey
	for key := range r.clients {
		if _, exists := live[key]; exists {
			continue
		}
		expired = append(expired, key)
		delete(r.clients, key)
		if r.owners[key.AdvertisedIP] == key {
			delete(r.owners, key.AdvertisedIP)
		}
	}
	return expired
}

// Measure checks a MEASURE with the rules of a REGISTER, and it accepts the
// frame only on a live path that its client registered with the same path ID
// and the same kind. It creates and refreshes nothing.
func (r *Registry) Measure(now time.Time, request RegistrationRequest) (ClientKey, error) {
	if request.Frame.Type != protocol.ControlMeasure {
		return ClientKey{}, ErrMeasureType
	}
	if err := r.validatePath(request); err != nil {
		return ClientKey{}, err
	}
	key := ClientKey{AdvertisedIP: request.Frame.AdvertisedIP, InstanceNonce: request.Frame.InstanceNonce}
	ingressReflect := request.Frame.Flags&protocol.ControlFlagIngressReflect != 0
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, exists := r.paths[request.Path]
	if !exists || !now.Before(entry.expiresAt) || entry.client != key ||
		entry.pathID != request.Frame.PathID || entry.ingressReflect != ingressReflect {
		return ClientKey{}, ErrMeasureUnknown
	}
	return key, nil
}

// PathIDs returns the path IDs of the live paths of each client as a mask,
// with bit n for path ID n.
func (r *Registry) PathIDs(now time.Time) map[ClientKey]uint8 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make(map[ClientKey]uint8, len(r.clients))
	for _, entry := range r.paths {
		if now.Before(entry.expiresAt) && entry.pathID <= protocol.MaxPathID {
			ids[entry.client] |= 1 << entry.pathID
		}
	}
	return ids
}

func (r *Registry) validate(request RegistrationRequest) error {
	if request.Frame.Type != protocol.ControlRegister {
		return ErrRegistrationType
	}
	return r.validatePath(request)
}

// validatePath checks the source, the port, the transport and the path ID of
// a REGISTER or a MEASURE.
func (r *Registry) validatePath(request RegistrationRequest) error {
	// An ingress reflect REGISTER arrives from the via host, so its source is the
	// via, not the advertised IP. The server keys the path by the via source.
	if request.Frame.Flags&protocol.ControlFlagIngressReflect == 0 && request.Path.Source != request.Frame.AdvertisedIP {
		return ErrRegistrationSource
	}
	if request.Frame.ServerPort < r.firstPort || request.Frame.ServerPort > r.lastPort ||
		request.Path.ServerPort != request.Frame.ServerPort {
		return ErrRegistrationPort
	}
	if request.Path.Transport != request.Frame.Transport {
		return ErrRegistrationTransport
	}
	if !request.Path.Source.Is4() || !request.Path.Local.Is4() || request.Frame.PathID > protocol.MaxPathID {
		return ErrRegistrationPath
	}
	return nil
}

func (r *Registry) removeClientLocked(key ClientKey) {
	delete(r.clients, key)
	if r.owners[key.AdvertisedIP] == key {
		delete(r.owners, key.AdvertisedIP)
	}
	for path, entry := range r.paths {
		if entry.client == key {
			delete(r.paths, path)
		}
	}
}
