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
}

type Registry struct {
	serverPort uint16

	mu    sync.RWMutex
	lease time.Duration

	owners  map[netip.Addr]ClientKey
	paths   map[PathKey]pathRegistration
	clients map[ClientKey]ClientRegistration
}

func NewRegistry(serverPort uint16, lease time.Duration) *Registry {
	return &Registry{
		serverPort: serverPort, lease: lease,
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
		client:    key,
		pathID:    request.Frame.PathID,
		expiresAt: expiresAt,
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

func (r *Registry) validate(request RegistrationRequest) error {
	if request.Frame.Type != protocol.ControlRegister {
		return ErrRegistrationType
	}
	if request.Path.Source != request.Frame.AdvertisedIP {
		return ErrRegistrationSource
	}
	if request.Frame.ServerPort != r.serverPort || request.Path.ServerPort != r.serverPort {
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
