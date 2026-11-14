//go:build linux

package app

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/control"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/protocol"
)

var loopback = netip.MustParseAddr("127.0.0.1")

func listenLoopback(t *testing.T, address string) *net.UDPConn {
	t.Helper()
	connection, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(address)))
	if err != nil {
		t.Fatalf("listen %s: %v", address, err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

func freeListenPort(t *testing.T) uint16 {
	t.Helper()
	connection := listenLoopback(t, "127.0.0.1:0")
	port := uint16(connection.LocalAddr().(*net.UDPAddr).Port)
	_ = connection.Close()
	return port
}

func loopbackRegistration(server *net.UDPConn, listenPort uint16, pathID uint16, interfaceName string) pathRegistration {
	endpoint := server.LocalAddr().(*net.UDPAddr).AddrPort()
	return pathRegistration{
		advertisedIP: loopback,
		listenPort:   listenPort,
		path: config.Path{
			Server:     endpoint.Addr().Unmap(),
			ServerPort: endpoint.Port(),
			Interface:  interfaceName,
			Transport:  protocol.TransportUDP,
		},
		nonce:  1,
		pathID: pathID,
	}
}

type runningPath struct {
	outcomes chan probeOutcome
	cancel   context.CancelFunc
	done     chan error
}

func startLoopbackPath(t *testing.T, sockets *udpControlSockets, registration pathRegistration) *runningPath {
	t.Helper()
	path, err := openUDPPathConn(sockets, registration)
	if err != nil {
		t.Fatalf("openUDPPathConn: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	running := &runningPath{outcomes: make(chan probeOutcome, 16), cancel: cancel, done: make(chan error, 1)}
	go func() {
		running.done <- path.Run(ctx, func(ctx context.Context, sequence uint32, _ time.Time, success bool) error {
			select {
			case running.outcomes <- probeOutcome{sequence: sequence, success: success}:
			default:
			}
			return nil
		})
	}()
	t.Cleanup(func() { running.stop(t) })
	return running
}

func (p *runningPath) stop(t *testing.T) {
	t.Helper()
	p.cancel()
	select {
	case <-p.done:
		p.done <- nil
	case <-time.After(5 * time.Second):
		t.Fatal("the path did not stop")
	}
}

func readRegister(t *testing.T, server *net.UDPConn) ([]byte, *net.UDPAddr) {
	t.Helper()
	buffer := make([]byte, 128)
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	count, source, err := server.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("read REGISTER: %v", err)
	}
	return buffer[:count], source
}

func sendTo(t *testing.T, connection *net.UDPConn, packet []byte, destination *net.UDPAddr) {
	t.Helper()
	if _, err := connection.WriteToUDP(packet, destination); err != nil {
		t.Fatalf("send: %v", err)
	}
}

func waitOutcome(t *testing.T, path *runningPath) probeOutcome {
	t.Helper()
	select {
	case outcome := <-path.outcomes:
		return outcome
	case <-time.After(5 * time.Second):
		t.Fatal("the path did not report")
		return probeOutcome{}
	}
}

func TestUDPPathRegistersFromTheListenPort(t *testing.T) {
	t.Parallel()

	for _, interfaceName := range []string{"", "lo"} {
		t.Run("interface="+interfaceName, func(t *testing.T) {
			t.Parallel()
			server := listenLoopback(t, "127.0.0.1:0")
			listenPort := freeListenPort(t)
			path := startLoopbackPath(t, newUDPControlSockets(listenUDPControl), loopbackRegistration(server, listenPort, 0, interfaceName))

			register, source := readRegister(t, server)
			if source.AddrPort() != netip.AddrPortFrom(loopback, listenPort) {
				t.Fatalf("REGISTER came from %s, want the listen port %d", source, listenPort)
			}
			sendTo(t, server, testACK(t, register, nil), source)
			if outcome := waitOutcome(t, path); !outcome.success || outcome.sequence != 1 {
				t.Fatalf("outcome = %+v, want success for sequence 1", outcome)
			}
		})
	}
}

func TestUDPPathsOfAGroupShareTheListenPort(t *testing.T) {
	t.Parallel()

	serverA := listenLoopback(t, "127.0.0.1:0")
	serverB := listenLoopback(t, "127.0.0.1:0")
	listenPort := freeListenPort(t)
	sockets := newUDPControlSockets(listenUDPControl)
	pathA := startLoopbackPath(t, sockets, loopbackRegistration(serverA, listenPort, 0, ""))
	pathB := startLoopbackPath(t, sockets, loopbackRegistration(serverB, listenPort, 1, ""))
	sockets.mu.Lock()
	count := len(sockets.sockets)
	sockets.mu.Unlock()
	if count != 1 {
		t.Fatalf("the group has %d control sockets, want 1", count)
	}

	registerA, sourceA := readRegister(t, serverA)
	registerB, sourceB := readRegister(t, serverB)
	if sourceA.Port != int(listenPort) || sourceB.Port != int(listenPort) {
		t.Fatalf("REGISTER frames came from ports %d and %d, want %d", sourceA.Port, sourceB.Port, listenPort)
	}
	sendTo(t, serverB, testACK(t, registerB, nil), sourceB)
	sendTo(t, serverA, testACK(t, registerA, nil), sourceA)
	if outcome := waitOutcome(t, pathA); !outcome.success {
		t.Fatal("path A missed its ACK")
	}
	if outcome := waitOutcome(t, pathB); !outcome.success {
		t.Fatal("path B missed its ACK")
	}
}

func TestUDPPathIgnoresACKsOfOtherSourcesAndPaths(t *testing.T) {
	t.Parallel()

	server := listenLoopback(t, "127.0.0.1:0")
	serverPort := server.LocalAddr().(*net.UDPAddr).Port
	otherPort := listenLoopback(t, "127.0.0.1:0")
	otherAddress := listenLoopback(t, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), uint16(serverPort)).String())
	path := startLoopbackPath(t, newUDPControlSockets(listenUDPControl), loopbackRegistration(server, freeListenPort(t), 2, ""))

	register, source := readRegister(t, server)
	sendTo(t, otherPort, testACK(t, register, nil), source)
	sendTo(t, otherAddress, testACK(t, register, nil), source)
	sendTo(t, server, testACK(t, register, func(f *protocol.ControlFrame) { f.PathID = 3 }), source)
	sendTo(t, server, testACK(t, register, func(f *protocol.ControlFrame) { f.Sequence++ }), source)
	if outcome := waitOutcome(t, path); outcome.success || outcome.sequence != 1 {
		t.Fatalf("outcome = %+v, want a miss for sequence 1", outcome)
	}

	register, retrySource := readRegister(t, server)
	if retrySource.Port != source.Port {
		t.Fatalf("retry came from port %d, want %d", retrySource.Port, source.Port)
	}
	sendTo(t, server, testACK(t, register, nil), retrySource)
	if outcome := waitOutcome(t, path); !outcome.success || outcome.sequence != 2 {
		t.Fatalf("outcome = %+v, want success for sequence 2", outcome)
	}
}

func TestUDPPathKeepsWorkingAfterAnotherPathCloses(t *testing.T) {
	t.Parallel()

	serverA := listenLoopback(t, "127.0.0.1:0")
	serverB := listenLoopback(t, "127.0.0.1:0")
	listenPort := freeListenPort(t)
	sockets := newUDPControlSockets(listenUDPControl)
	pathA := startLoopbackPath(t, sockets, loopbackRegistration(serverA, listenPort, 0, ""))
	pathB := startLoopbackPath(t, sockets, loopbackRegistration(serverB, listenPort, 1, ""))

	readRegister(t, serverA)
	readRegister(t, serverB)
	pathA.stop(t)

	register, source := readRegister(t, serverB)
	if source.Port != int(listenPort) {
		t.Fatalf("REGISTER came from port %d, want %d", source.Port, listenPort)
	}
	sendTo(t, serverB, testACK(t, register, nil), source)
	for {
		if outcome := waitOutcome(t, pathB); outcome.success {
			break
		}
	}

	pathB.stop(t)
	rebound, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(loopback, listenPort)))
	if err != nil {
		t.Fatalf("the listen port stayed bound after the last path closed: %v", err)
	}
	_ = rebound.Close()

	serverC := listenLoopback(t, "127.0.0.1:0")
	pathC := startLoopbackPath(t, sockets, loopbackRegistration(serverC, listenPort, 0, ""))
	register, source = readRegister(t, serverC)
	if source.Port != int(listenPort) {
		t.Fatalf("REGISTER after reopen came from port %d, want %d", source.Port, listenPort)
	}
	sendTo(t, serverC, testACK(t, register, nil), source)
	if outcome := waitOutcome(t, pathC); !outcome.success {
		t.Fatal("the reopened path missed its ACK")
	}
}

type recordingSink struct {
	registered []dataplane.RegistrationSettings
}

func (s *recordingSink) RegisterPath(settings dataplane.RegistrationSettings) error {
	s.registered = append(s.registered, settings)
	return nil
}

func (s *recordingSink) RevokeRegistration(dataplane.ClientKey) error {
	return nil
}

func TestAcceptRegistrationUsesTheReceivingPort(t *testing.T) {
	t.Parallel()

	client := netip.MustParseAddr("192.0.2.10")
	local := netip.MustParseAddr("198.51.100.1")
	frame, err := registrationFrame(pathRegistration{
		advertisedIP: client,
		listenPort:   51820,
		path:         config.Path{Server: local, ServerPort: 5001, Transport: protocol.TransportUDP},
		nonce:        1,
	}, 1)
	if err != nil {
		t.Fatalf("registrationFrame: %v", err)
	}
	registry := control.NewRegistry(5000, 5001, 30*time.Second)
	sink := &recordingSink{}

	if _, err := acceptRegistration(frame, protocol.TransportUDP, 5000, client, local, registry, sink); !errors.Is(err, control.ErrRegistrationPort) {
		t.Fatalf("acceptRegistration on another port error = %v, want %v", err, control.ErrRegistrationPort)
	}
	if len(sink.registered) != 0 {
		t.Fatalf("rejected frame reached the dataplane: %#v", sink.registered)
	}
	if _, err := acceptRegistration(frame, protocol.TransportUDP, 5001, client, local, registry, sink); err != nil {
		t.Fatalf("acceptRegistration on the named port: %v", err)
	}
	if len(sink.registered) != 1 || sink.registered[0].Path.ServerPort != 5001 {
		t.Fatalf("registered = %#v, want one path on port 5001", sink.registered)
	}
}
