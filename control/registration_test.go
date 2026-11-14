package control

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/xshecan/mup/protocol"
)

func TestRegistrationGroupsPathsByClientKey(t *testing.T) {
	t.Parallel()

	now := time.Unix(100, 0)
	registry := NewRegistry(5000, 5000, 30*time.Second)
	clientIP := netip.MustParseAddr("192.0.2.10")
	first := registrationRequest(clientIP, netip.MustParseAddr("198.51.100.1"), protocol.TransportUDP, 99, 0)
	second := registrationRequest(clientIP, netip.MustParseAddr("198.51.100.2"), protocol.TransportICMP, 99, 1)

	firstResult, err := registry.Register(now, first)
	if err != nil {
		t.Fatalf("register first path: %v", err)
	}
	secondResult, err := registry.Register(now, second)
	if err != nil {
		t.Fatalf("register second path: %v", err)
	}
	if firstResult.Key != secondResult.Key {
		t.Fatalf("paths have different client keys: %#v and %#v", firstResult.Key, secondResult.Key)
	}
	if _, ok := registry.ResolvePath(now, first.Path); !ok {
		t.Fatal("first path was not published")
	}
	if key, ok := registry.ResolvePath(now, second.Path); !ok || key != firstResult.Key {
		t.Fatalf("second path resolved to %#v, %v", key, ok)
	}
}

func TestRegistrationNewNonceReplacesSameAdvertisedIP(t *testing.T) {
	t.Parallel()

	now := time.Unix(200, 0)
	registry := NewRegistry(5000, 5000, 30*time.Second)
	clientIP := netip.MustParseAddr("192.0.2.10")
	oldRequest := registrationRequest(clientIP, netip.MustParseAddr("198.51.100.1"), protocol.TransportUDP, 1, 0)
	oldResult, err := registry.Register(now, oldRequest)
	if err != nil {
		t.Fatalf("register old instance: %v", err)
	}
	newRequest := registrationRequest(clientIP, netip.MustParseAddr("198.51.100.2"), protocol.TransportUDP, 2, 0)
	newResult, err := registry.Register(now.Add(time.Second), newRequest)
	if err != nil {
		t.Fatalf("register new instance: %v", err)
	}
	if newResult.Replaced == nil || *newResult.Replaced != oldResult.Key {
		t.Fatalf("replaced = %#v, want %#v", newResult.Replaced, oldResult.Key)
	}
	if _, ok := registry.ResolvePath(now.Add(time.Second), oldRequest.Path); ok {
		t.Fatal("old path remained active after nonce replacement")
	}
	if key, ok := registry.ResolvePath(now.Add(time.Second), newRequest.Path); !ok || key != newResult.Key {
		t.Fatalf("new path resolved to %#v, %v", key, ok)
	}
}

func TestRegistrationExpiresPathsAndClient(t *testing.T) {
	t.Parallel()

	now := time.Unix(300, 0)
	registry := NewRegistry(5000, 5000, 30*time.Second)
	request := registrationRequest(
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("198.51.100.1"),
		protocol.TransportUDP,
		3,
		0,
	)
	result, err := registry.Register(now, request)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if expired := registry.Expire(now.Add(29 * time.Second)); len(expired) != 0 {
		t.Fatalf("expired early: %#v", expired)
	}
	expired := registry.Expire(now.Add(30 * time.Second))
	if len(expired) != 1 || expired[0] != result.Key {
		t.Fatalf("expired = %#v, want [%#v]", expired, result.Key)
	}
	if _, ok := registry.ResolvePath(now.Add(30*time.Second), request.Path); ok {
		t.Fatal("expired path still resolves")
	}
}

func TestRegistrationValidatesObservedPath(t *testing.T) {
	t.Parallel()

	now := time.Unix(400, 0)
	registry := NewRegistry(5000, 5000, 30*time.Second)
	request := registrationRequest(
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("198.51.100.1"),
		protocol.TransportUDP,
		4,
		0,
	)
	request.Path.Source = netip.MustParseAddr("192.0.2.11")
	if _, err := registry.Register(now, request); !errors.Is(err, ErrRegistrationSource) {
		t.Fatalf("Register error = %v, want %v", err, ErrRegistrationSource)
	}
	request.Path.Source = request.Frame.AdvertisedIP
	request.Path.ServerPort = 5001
	if _, err := registry.Register(now, request); !errors.Is(err, ErrRegistrationPort) {
		t.Fatalf("Register error = %v, want %v", err, ErrRegistrationPort)
	}
	request.Path.ServerPort = 5000
	request.Path.Transport = protocol.TransportICMP
	if _, err := registry.Register(now, request); !errors.Is(err, ErrRegistrationTransport) {
		t.Fatalf("Register error = %v, want %v", err, ErrRegistrationTransport)
	}
}

func registrationRequest(clientIP, localIP netip.Addr, transport protocol.TransportID, nonce uint64, pathID uint16) RegistrationRequest {
	return RegistrationRequest{
		Frame: protocol.ControlFrame{
			Type:          protocol.ControlRegister,
			Transport:     transport,
			PathID:        pathID,
			ListenPort:    51820,
			ServerPort:    5000,
			AdvertisedIP:  clientIP,
			InstanceNonce: nonce,
		},
		Path: PathKey{
			Source:     clientIP,
			Local:      localIP,
			ServerPort: 5000,
			Transport:  transport,
		},
	}
}

func TestRegistrationAcceptsEachPortOfTheRange(t *testing.T) {
	t.Parallel()

	now := time.Unix(400, 0)
	registry := NewRegistry(5000, 6000, 30*time.Second)
	clientIP := netip.MustParseAddr("192.0.2.10")
	for _, port := range []uint16{5000, 5500, 6000} {
		request := registrationRequest(clientIP, netip.MustParseAddr("198.51.100.1"), protocol.TransportUDP, 7, 0)
		request.Frame.ServerPort, request.Path.ServerPort = port, port
		if _, err := registry.Register(now, request); err != nil {
			t.Fatalf("register port %d: %v", port, err)
		}
	}
	for _, port := range []uint16{4999, 6001} {
		request := registrationRequest(clientIP, netip.MustParseAddr("198.51.100.1"), protocol.TransportUDP, 7, 0)
		request.Frame.ServerPort, request.Path.ServerPort = port, port
		if _, err := registry.Register(now, request); !errors.Is(err, ErrRegistrationPort) {
			t.Fatalf("register port %d error = %v, want %v", port, err, ErrRegistrationPort)
		}
	}
	request := registrationRequest(clientIP, netip.MustParseAddr("198.51.100.1"), protocol.TransportUDP, 7, 0)
	request.Frame.ServerPort = 5001
	if _, err := registry.Register(now, request); !errors.Is(err, ErrRegistrationPort) {
		t.Fatalf("register with another frame port error = %v, want %v", err, ErrRegistrationPort)
	}
}

func TestRegistrationRejectsAFrameForAnotherPortOfTheRange(t *testing.T) {
	t.Parallel()

	now := time.Unix(500, 0)
	registry := NewRegistry(5000, 5001, 30*time.Second)
	request := registrationRequest(
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("198.51.100.1"),
		protocol.TransportUDP,
		8,
		0,
	)
	request.Frame.ServerPort, request.Path.ServerPort = 5001, 5000
	if _, err := registry.Register(now, request); !errors.Is(err, ErrRegistrationPort) {
		t.Fatalf("Register error = %v, want %v", err, ErrRegistrationPort)
	}
	if _, ok := registry.ResolvePath(now, request.Path); ok {
		t.Fatal("rejected path was published")
	}
}
