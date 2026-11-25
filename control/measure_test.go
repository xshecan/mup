package control

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/xshecan/mup/protocol"
)

func measureRequest(request RegistrationRequest) RegistrationRequest {
	request.Frame.Type = protocol.ControlMeasure
	return request
}

func TestMeasureNeedsARegisteredPath(t *testing.T) {
	t.Parallel()

	now := time.Unix(100, 0)
	registry := NewRegistry(5000, 5000, 30*time.Second)
	clientIP := netip.MustParseAddr("192.0.2.10")
	local := netip.MustParseAddr("198.51.100.1")
	register := registrationRequest(clientIP, local, protocol.TransportUDP, 7, 2)
	if _, err := registry.Measure(now, measureRequest(register)); !errors.Is(err, ErrMeasureUnknown) {
		t.Fatalf("Measure before REGISTER error = %v, want %v", err, ErrMeasureUnknown)
	}
	if _, err := registry.Register(now, register); err != nil {
		t.Fatalf("Register: %v", err)
	}
	key, err := registry.Measure(now, measureRequest(register))
	if err != nil || key != (ClientKey{AdvertisedIP: clientIP, InstanceNonce: 7}) {
		t.Fatalf("Measure = %#v, %v", key, err)
	}

	otherID := measureRequest(register)
	otherID.Frame.PathID = 3
	otherNonce := measureRequest(register)
	otherNonce.Frame.InstanceNonce = 8
	otherLocal := measureRequest(register)
	otherLocal.Path.Local = netip.MustParseAddr("198.51.100.9")
	reflected := measureRequest(register)
	reflected.Frame.Flags = protocol.ControlFlagIngressReflect | protocol.ControlFlagReturnIP
	reflected.Frame.ReturnIP = netip.MustParseAddr("203.0.113.9")
	for name, request := range map[string]RegistrationRequest{
		"other path ID": otherID, "other nonce": otherNonce, "other local address": otherLocal, "reflect flag": reflected,
	} {
		if _, err := registry.Measure(now, request); !errors.Is(err, ErrMeasureUnknown) {
			t.Fatalf("%s: Measure error = %v, want %v", name, err, ErrMeasureUnknown)
		}
	}
	if _, err := registry.Measure(now.Add(30*time.Second), measureRequest(register)); !errors.Is(err, ErrMeasureUnknown) {
		t.Fatalf("Measure after the lease error = %v, want %v", err, ErrMeasureUnknown)
	}
}

func TestMeasureKeepsTheRulesOfARegister(t *testing.T) {
	t.Parallel()

	now := time.Unix(100, 0)
	registry := NewRegistry(5000, 5000, 30*time.Second)
	clientIP := netip.MustParseAddr("192.0.2.10")
	register := registrationRequest(clientIP, netip.MustParseAddr("198.51.100.1"), protocol.TransportUDP, 7, 2)
	if _, err := registry.Register(now, register); err != nil {
		t.Fatalf("Register: %v", err)
	}
	spoofed := measureRequest(register)
	spoofed.Path.Source = netip.MustParseAddr("192.0.2.99")
	port := measureRequest(register)
	port.Path.ServerPort = 5001
	transport := measureRequest(register)
	transport.Path.Transport = protocol.TransportICMP
	for name, tt := range map[string]struct {
		request RegistrationRequest
		err     error
	}{
		"source":    {spoofed, ErrRegistrationSource},
		"port":      {port, ErrRegistrationPort},
		"transport": {transport, ErrRegistrationTransport},
		"register":  {register, ErrMeasureType},
	} {
		if _, err := registry.Measure(now, tt.request); !errors.Is(err, tt.err) {
			t.Fatalf("%s: Measure error = %v, want %v", name, err, tt.err)
		}
	}
}

func TestMeasureOnAnIngressReflectPath(t *testing.T) {
	t.Parallel()

	now := time.Unix(100, 0)
	registry := NewRegistry(5000, 5000, 30*time.Second)
	clientIP := netip.MustParseAddr("192.0.2.10")
	member := netip.MustParseAddr("203.0.113.9")
	register := registrationRequest(clientIP, netip.MustParseAddr("198.51.100.1"), protocol.TransportICMP, 7, 4)
	register.Frame.Flags = protocol.ControlFlagIngressReflect | protocol.ControlFlagReturnIP
	register.Frame.ReturnIP = member
	register.Path.Source = member
	if _, err := registry.Register(now, register); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := registry.Measure(now, measureRequest(register)); err != nil {
		t.Fatalf("Measure through the member: %v", err)
	}
	plain := measureRequest(register)
	plain.Frame.Flags, plain.Frame.ReturnIP = 0, netip.Addr{}
	if _, err := registry.Measure(now, plain); !errors.Is(err, ErrRegistrationSource) {
		t.Fatalf("Measure without the reflect flag error = %v, want %v", err, ErrRegistrationSource)
	}
}

func TestPathIDsListsTheLivePaths(t *testing.T) {
	t.Parallel()

	now := time.Unix(100, 0)
	registry := NewRegistry(5000, 5000, 30*time.Second)
	clientIP := netip.MustParseAddr("192.0.2.10")
	for index, pathID := range []uint16{0, 3} {
		local := netip.AddrFrom4([4]byte{198, 51, 100, byte(index + 1)})
		if _, err := registry.Register(now.Add(time.Duration(index)*10*time.Second), registrationRequest(clientIP, local, protocol.TransportUDP, 7, pathID)); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	key := ClientKey{AdvertisedIP: clientIP, InstanceNonce: 7}
	if got := registry.PathIDs(now.Add(20 * time.Second)); got[key] != 0b1001 || len(got) != 1 {
		t.Fatalf("PathIDs = %#v, want paths 0 and 3", got)
	}
	if got := registry.PathIDs(now.Add(35 * time.Second)); got[key] != 0b1000 {
		t.Fatalf("PathIDs after the first lease = %#v, want path 3", got)
	}
}
