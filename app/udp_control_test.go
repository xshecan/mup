package app

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/protocol"
)

var errStopPath = errors.New("stop path")

type fakeDatagram struct {
	data    []byte
	peer    netip.AddrPort
	ifindex int
}

type fakeUDPControlConn struct {
	local  netip.AddrPort
	inbox  chan fakeDatagram
	sent   chan fakeDatagram
	closed chan struct{}
	once   sync.Once
}

func (c *fakeUDPControlConn) readControl(buffer []byte) (int, netip.AddrPort, int, error) {
	select {
	case <-c.closed:
		return 0, netip.AddrPort{}, 0, net.ErrClosed
	case datagram := <-c.inbox:
		return copy(buffer, datagram.data), datagram.peer, datagram.ifindex, nil
	}
}

func (c *fakeUDPControlConn) writeControl(frame []byte, destination netip.AddrPort, ifindex int) error {
	select {
	case <-c.closed:
		return net.ErrClosed
	case c.sent <- fakeDatagram{data: append([]byte(nil), frame...), peer: destination, ifindex: ifindex}:
		return nil
	}
}

func (c *fakeUDPControlConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *fakeUDPControlConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

type fakeUDPListener struct {
	mu    sync.Mutex
	conns []*fakeUDPControlConn
	err   error
}

func (l *fakeUDPListener) listen(local netip.AddrPort) (udpControlConn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return nil, l.err
	}
	conn := &fakeUDPControlConn{
		local:  local,
		inbox:  make(chan fakeDatagram, 16),
		sent:   make(chan fakeDatagram, 16),
		closed: make(chan struct{}),
	}
	l.conns = append(l.conns, conn)
	return conn, nil
}

func (l *fakeUDPListener) opened() []*fakeUDPControlConn {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]*fakeUDPControlConn(nil), l.conns...)
}

var (
	testAdvertisedIP = netip.MustParseAddr("192.0.2.10")
	testServerA      = netip.MustParseAddrPort("198.51.100.1:5000")
	testServerB      = netip.MustParseAddrPort("198.51.100.2:5000")
)

func testUDPRegistration(server netip.AddrPort, pathID uint16) pathRegistration {
	return pathRegistration{
		advertisedIP: testAdvertisedIP,
		listenPort:   51820,
		path:         config.Path{Server: server.Addr(), ServerPort: server.Port(), Transport: protocol.TransportUDP},
		nonce:        7,
		pathID:       pathID,
	}
}

func answerRegister(register []byte, change func(*protocol.ControlFrame)) ([]byte, error) {
	frame, err := protocol.DecodeControlFrame(register)
	if err != nil {
		return nil, err
	}
	frame.Type = protocol.ControlRegisterACK
	frame.Status = protocol.ControlStatusOK
	if change != nil {
		change(&frame)
	}
	ack := make([]byte, protocol.ControlFrameLength)
	if err := protocol.EncodeControlFrame(ack, frame); err != nil {
		return nil, err
	}
	return ack, nil
}

func testACK(t *testing.T, register []byte, change func(*protocol.ControlFrame)) []byte {
	t.Helper()
	ack, err := answerRegister(register, change)
	if err != nil {
		t.Fatalf("answer REGISTER: %v", err)
	}
	return ack
}

type probeOutcome struct {
	sequence uint32
	success  bool
}

func runOneRound(path pathConn) <-chan probeOutcome {
	outcomes := make(chan probeOutcome, 1)
	go func() {
		_ = path.Run(context.Background(), func(_ context.Context, sequence uint32, _, _ time.Time, result registerResult) error {
			outcomes <- probeOutcome{sequence: sequence, success: result == registerAcked}
			return errStopPath
		})
	}()
	return outcomes
}

func receiveSent(t *testing.T, conn *fakeUDPControlConn) fakeDatagram {
	t.Helper()
	select {
	case datagram := <-conn.sent:
		return datagram
	case <-time.After(5 * time.Second):
		t.Fatal("no REGISTER was sent")
		return fakeDatagram{}
	}
}

func receiveOutcome(t *testing.T, outcomes <-chan probeOutcome) probeOutcome {
	t.Helper()
	select {
	case outcome := <-outcomes:
		return outcome
	case <-time.After(5 * time.Second):
		t.Fatal("the path did not report")
		return probeOutcome{}
	}
}

func TestUDPControlReplyMatchesOnlyItsACK(t *testing.T) {
	t.Parallel()

	registration := testUDPRegistration(testServerA, 2)
	register, err := registrationFrame(registration, 9)
	if err != nil {
		t.Fatalf("registrationFrame: %v", err)
	}
	reply := func(source netip.AddrPort, ifindex int, change func(*protocol.ControlFrame)) udpControlReply {
		result := udpControlReply{source: source, ifindex: ifindex}
		copy(result.frame[:], testACK(t, register, change))
		return result
	}
	tests := []struct {
		name    string
		reply   udpControlReply
		ifindex int
		want    bool
	}{
		{"matching", reply(testServerA, 4, nil), 0, true},
		{"matching on the interface of the path", reply(testServerA, 4, nil), 4, true},
		{"another interface", reply(testServerA, 5, nil), 4, false},
		{"another source address", reply(netip.AddrPortFrom(testServerB.Addr(), testServerA.Port()), 4, nil), 0, false},
		{"another source port", reply(netip.AddrPortFrom(testServerA.Addr(), 5001), 4, nil), 0, false},
		{"another path ID", reply(testServerA, 4, func(f *protocol.ControlFrame) { f.PathID = 3 }), 0, false},
		{"another sequence", reply(testServerA, 4, func(f *protocol.ControlFrame) { f.Sequence = 8 }), 0, false},
		{"another nonce", reply(testServerA, 4, func(f *protocol.ControlFrame) { f.InstanceNonce = 8 }), 0, false},
		{"a REGISTER", reply(testServerA, 4, func(f *protocol.ControlFrame) { f.Type = protocol.ControlRegister }), 0, false},
	}
	for _, test := range tests {
		result, ok := test.reply.answer(registration, test.ifindex, 9)
		if got := ok && result == registerAcked; got != test.want {
			t.Errorf("%s: answer = %v %v, want an ACK %v", test.name, result, ok, test.want)
		}
	}
}

func TestUDPPathsOfAGroupShareOneSocket(t *testing.T) {
	t.Parallel()

	listener := &fakeUDPListener{}
	sockets := newUDPControlSockets(listener.listen)
	first, err := sockets.openPath(testUDPRegistration(testServerA, 0), 0)
	if err != nil {
		t.Fatalf("openPath 0: %v", err)
	}
	second, err := sockets.openPath(testUDPRegistration(testServerB, 1), 0)
	if err != nil {
		t.Fatalf("openPath 1: %v", err)
	}
	conns := listener.opened()
	if len(conns) != 1 || conns[0].local != netip.AddrPortFrom(testAdvertisedIP, 51820) {
		t.Fatalf("opened %d sockets, want one on the listen port", len(conns))
	}
	conn := conns[0]

	firstOutcomes := runOneRound(first)
	secondOutcomes := runOneRound(second)
	sent := map[netip.AddrPort][]byte{}
	for range 2 {
		datagram := receiveSent(t, conn)
		sent[datagram.peer] = datagram.data
	}
	conn.inbox <- fakeDatagram{data: testACK(t, sent[testServerB], nil), peer: testServerB}
	conn.inbox <- fakeDatagram{data: testACK(t, sent[testServerA], nil), peer: testServerA}
	if outcome := receiveOutcome(t, firstOutcomes); !outcome.success {
		t.Fatal("path 0 missed its ACK")
	}
	if outcome := receiveOutcome(t, secondOutcomes); !outcome.success {
		t.Fatal("path 1 missed its ACK")
	}
}

func TestUDPPathSkipsACKsThatDoNotMatch(t *testing.T) {
	t.Parallel()

	listener := &fakeUDPListener{}
	sockets := newUDPControlSockets(listener.listen)
	path, err := sockets.openPath(testUDPRegistration(testServerA, 0), 3)
	if err != nil {
		t.Fatalf("openPath: %v", err)
	}
	conn := listener.opened()[0]
	register, err := registrationFrame(path.registration, 1)
	if err != nil {
		t.Fatalf("registrationFrame: %v", err)
	}
	conn.inbox <- fakeDatagram{data: testACK(t, register, nil), peer: testServerA, ifindex: 3}
	time.Sleep(50 * time.Millisecond)

	outcomes := runOneRound(path)
	datagram := receiveSent(t, conn)
	if datagram.ifindex != 3 {
		t.Fatalf("REGISTER left on interface %d, want 3", datagram.ifindex)
	}
	for _, foreign := range []fakeDatagram{
		{data: testACK(t, datagram.data, func(f *protocol.ControlFrame) { f.Sequence = 0 }), peer: testServerA, ifindex: 3},
		{data: testACK(t, datagram.data, nil), peer: testServerB, ifindex: 3},
		{data: testACK(t, datagram.data, nil), peer: testServerA, ifindex: 4},
		{data: datagram.data[:20], peer: testServerA, ifindex: 3},
		{data: make([]byte, protocol.ControlFrameLength), peer: testServerA, ifindex: 3},
	} {
		conn.inbox <- foreign
	}
	select {
	case outcome := <-outcomes:
		t.Fatalf("the path reported %+v before its ACK", outcome)
	case <-time.After(100 * time.Millisecond):
	}
	conn.inbox <- fakeDatagram{data: testACK(t, datagram.data, nil), peer: testServerA, ifindex: 3}
	if outcome := receiveOutcome(t, outcomes); !outcome.success || outcome.sequence != 1 {
		t.Fatalf("outcome = %+v, want success for sequence 1", outcome)
	}
}

func TestUDPPathMissesWithoutAnACK(t *testing.T) {
	t.Parallel()

	listener := &fakeUDPListener{}
	sockets := newUDPControlSockets(listener.listen)
	path, err := sockets.openPath(testUDPRegistration(testServerA, 0), 0)
	if err != nil {
		t.Fatalf("openPath: %v", err)
	}
	outcomes := runOneRound(path)
	receiveSent(t, listener.opened()[0])
	if outcome := receiveOutcome(t, outcomes); outcome.success {
		t.Fatal("the path succeeded without an ACK")
	}
}

func TestUDPControlSocketClosesWithItsLastPath(t *testing.T) {
	t.Parallel()

	listener := &fakeUDPListener{}
	sockets := newUDPControlSockets(listener.listen)
	first, err := sockets.openPath(testUDPRegistration(testServerA, 0), 0)
	if err != nil {
		t.Fatalf("openPath 0: %v", err)
	}
	second, err := sockets.openPath(testUDPRegistration(testServerB, 1), 0)
	if err != nil {
		t.Fatalf("openPath 1: %v", err)
	}
	socket := first.socket
	if err := first.Close(); err != nil {
		t.Fatalf("Close 0: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("second Close 0: %v", err)
	}
	conn := listener.opened()[0]
	if conn.isClosed() {
		t.Fatal("the socket closed while path 1 still uses it")
	}

	outcomes := runOneRound(second)
	datagram := receiveSent(t, conn)
	conn.inbox <- fakeDatagram{data: testACK(t, datagram.data, nil), peer: testServerB}
	if outcome := receiveOutcome(t, outcomes); !outcome.success {
		t.Fatal("path 1 missed its ACK after path 0 closed")
	}
	select {
	case <-socket.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the reader did not stop after the last path closed")
	}
	if !conn.isClosed() {
		t.Fatal("the socket stayed open after the last path closed")
	}
	sockets.mu.Lock()
	remaining := len(sockets.sockets)
	sockets.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("%d sockets remain, want 0", remaining)
	}

	third, err := sockets.openPath(testUDPRegistration(testServerA, 0), 0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if len(listener.opened()) != 2 || third.socket == socket {
		t.Fatal("the reopened path did not get a new socket")
	}
	if err := third.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestUDPPathGetsItsACKWhileAnOldPathHasItsID(t *testing.T) {
	t.Parallel()

	listener := &fakeUDPListener{}
	sockets := newUDPControlSockets(listener.listen)
	old, err := sockets.openPath(testUDPRegistration(testServerA, 0), 0)
	if err != nil {
		t.Fatalf("openPath old: %v", err)
	}
	defer old.Close()
	current, err := sockets.openPath(testUDPRegistration(testServerB, 0), 0)
	if err != nil {
		t.Fatalf("openPath new: %v", err)
	}
	outcomes := runOneRound(current)
	conn := listener.opened()[0]
	datagram := receiveSent(t, conn)
	conn.inbox <- fakeDatagram{data: testACK(t, datagram.data, nil), peer: testServerB}
	if outcome := receiveOutcome(t, outcomes); !outcome.success {
		t.Fatal("the new path missed its ACK")
	}
}

func TestUDPControlSocketNamesTheListenPortWhenTheBindFails(t *testing.T) {
	t.Parallel()

	bindErr := errors.New("address already in use")
	listener := &fakeUDPListener{err: bindErr}
	sockets := newUDPControlSockets(listener.listen)
	_, err := sockets.openPath(testUDPRegistration(testServerA, 0), 0)
	if !errors.Is(err, bindErr) {
		t.Fatalf("openPath error = %v, want %v", err, bindErr)
	}
	if !strings.Contains(err.Error(), "192.0.2.10:51820") || !strings.Contains(err.Error(), "listen port") {
		t.Fatalf("openPath error = %q, want the address and the listen port rule", err)
	}
	sockets.mu.Lock()
	defer sockets.mu.Unlock()
	if len(sockets.sockets) != 0 {
		t.Fatal("a failed bind left a socket")
	}
}

func TestUDPPathsRunAndCloseConcurrently(t *testing.T) {
	t.Parallel()

	listener := &fakeUDPListener{}
	sockets := newUDPControlSockets(listener.listen)
	var group sync.WaitGroup
	for round := range 20 {
		paths := make([]*udpPathConn, 0, 3)
		for id := range 3 {
			path, err := sockets.openPath(testUDPRegistration(testServerA, uint16(id)), 0)
			if err != nil {
				t.Fatalf("round %d: openPath %d: %v", round, id, err)
			}
			paths = append(paths, path)
		}
		conn := listener.opened()[round]
		ctx, cancel := context.WithCancel(context.Background())
		for _, path := range paths {
			group.Add(1)
			go func() {
				defer group.Done()
				_ = path.Run(ctx, func(context.Context, uint32, time.Time, time.Time, registerResult) error { return nil })
			}()
		}
		go func() {
			for {
				select {
				case datagram := <-conn.sent:
					ack, err := answerRegister(datagram.data, nil)
					if err != nil {
						continue
					}
					select {
					case conn.inbox <- fakeDatagram{data: ack, peer: testServerA}:
					case <-conn.closed:
						return
					}
				case <-conn.closed:
					return
				}
			}
		}()
		_ = paths[0].Close()
		cancel()
		group.Wait()
		if !conn.isClosed() {
			t.Fatalf("round %d: the socket stayed open", round)
		}
	}
}

// An ingress path of a group with separate egress paths sends the EGRESS_REGISTER
// frames before its REGISTER, and it takes its ACK from any source, because
// the ACK can arrive on any egress path.
func TestSplitUDPPathTakesItsACKFromAEgressPath(t *testing.T) {
	t.Parallel()

	listener := &fakeUDPListener{}
	sockets := newUDPControlSockets(listener.listen)
	registration := testUDPRegistration(testServerA, 0)
	registration.egresses = newEgressSet(config.ModeFallback)
	registration.egresses.set(0, config.Path{Server: testServerA.Addr(), ServerPort: 9200, Transport: protocol.TransportUDP})
	path, err := sockets.openPath(registration, 0)
	if err != nil {
		t.Fatalf("openPath: %v", err)
	}
	conn := listener.opened()[0]
	outcomes := runOneRound(path)
	egress := receiveSent(t, conn)
	if frame, err := protocol.DecodeControlFrame(egress.data); err != nil || frame.Type != protocol.ControlEgressRegister || egress.peer != testServerA {
		t.Fatalf("first frame = %+v to %s (%v), want a EGRESS_REGISTER to the server", frame, egress.peer, err)
	}
	register := receiveSent(t, conn)
	conn.inbox <- fakeDatagram{data: testACK(t, register.data, nil), peer: netip.MustParseAddrPort("203.0.113.4:9200")}
	if outcome := receiveOutcome(t, outcomes); !outcome.success || outcome.sequence != 1 {
		t.Fatalf("outcome = %+v, want success for sequence 1", outcome)
	}
}

// An egress path probe that arrives on the UDP socket goes to the handler of
// the client, and an ordinary path never sees it.
func TestUDPSocketPassesEgressProbes(t *testing.T) {
	t.Parallel()

	listener := &fakeUDPListener{}
	sockets := newUDPControlSockets(listener.listen)
	probes := make(chan egressProbe, 1)
	handle := func(probe egressProbe) { probes <- probe }
	sockets.onProbe.Store(&handle)
	socket, err := sockets.acquire(netip.AddrPortFrom(testAdvertisedIP, 51820))
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer sockets.release(socket)
	frame := protocol.ControlFrame{
		Type: protocol.ControlProbe, Transport: protocol.TransportUDP, Flags: protocol.ControlFlagEgressPath,
		PathID: 3, Sequence: 5, InstanceNonce: 7, AdvertisedIP: testAdvertisedIP,
	}
	packet := make([]byte, protocol.ControlFrameLength)
	if err := protocol.EncodeControlFrame(packet, frame); err != nil {
		t.Fatalf("encode: %v", err)
	}
	listener.opened()[0].inbox <- fakeDatagram{data: packet, peer: netip.MustParseAddrPort("203.0.113.4:9300")}
	select {
	case probe := <-probes:
		if probe.frame.PathID != 3 || probe.source != netip.MustParseAddr("203.0.113.4") || probe.port != 9300 || probe.transport != protocol.TransportUDP {
			t.Fatalf("probe = %+v", probe)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the probe did not reach the handler")
	}
}
