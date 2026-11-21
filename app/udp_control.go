package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xshecan/mup/protocol"
)

const (
	udpControlBufferLength = protocol.ControlFrameLength + 1

	udpReplyQueueLength = 4

	udpReadErrorPause = 10 * time.Millisecond
)

type udpControlConn interface {
	readControl(buffer []byte) (count int, source netip.AddrPort, ifindex int, err error)
	writeControl(frame []byte, destination netip.AddrPort, ifindex int) error
	Close() error
}

type udpControlListener func(local netip.AddrPort) (udpControlConn, error)

type udpControlReply struct {
	frame   [protocol.ControlFrameLength]byte
	source  netip.AddrPort
	ifindex int
}

// answer reads the result of a reply that answers the REGISTER with this
// sequence. ok is false for a reply that does not answer it.
func (r udpControlReply) answer(registration pathRegistration, ifindex int, sequence uint32) (registerResult, bool) {
	if r.source != registration.path.Endpoint() {
		return registerMissed, false
	}
	if ifindex > 0 && r.ifindex != ifindex {
		return registerMissed, false
	}
	return registrationACKResult(r.frame[:], registration.nonce, registration.pathID, sequence)
}

type udpControlSockets struct {
	listen udpControlListener
	// router passes the REGISTER_ACK frames of the up paths of groups with
	// separate down paths, and onProbe takes the probes of down paths.
	router  *ackRouter
	onProbe atomic.Pointer[func(downProbe)]

	mu      sync.Mutex
	sockets map[netip.AddrPort]*udpControlSocket
}

func newUDPControlSockets(listen udpControlListener) *udpControlSockets {
	return &udpControlSockets{listen: listen, router: &ackRouter{}, sockets: map[netip.AddrPort]*udpControlSocket{}}
}

type udpControlSocket struct {
	local   netip.AddrPort
	conn    udpControlConn
	owner   *udpControlSockets
	closing atomic.Bool
	done    chan struct{}

	references int

	mu      sync.Mutex
	waiters []*udpControlWaiter
}

type udpControlWaiter struct {
	pathID       uint16
	registration pathRegistration
	ifindex      int
	replies      chan udpControlReply
}

func (s *udpControlSockets) acquire(local netip.AddrPort) (*udpControlSocket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if socket := s.sockets[local]; socket != nil {
		socket.references++
		return socket, nil
	}
	conn, err := s.listen(local)
	if err != nil {
		return nil, fmt.Errorf("the control frames of a path leave from the listen port of its group, so the client must bind %s: %w", local, err)
	}
	socket := &udpControlSocket{local: local, conn: conn, owner: s, done: make(chan struct{}), references: 1}
	s.sockets[local] = socket
	go socket.read()
	return socket, nil
}

func (s *udpControlSockets) release(socket *udpControlSocket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	socket.references--
	if socket.references > 0 {
		return
	}
	delete(s.sockets, socket.local)
	socket.closing.Store(true)
	_ = socket.conn.Close()
	<-socket.done
}

func (s *udpControlSocket) read() {
	defer close(s.done)
	buffer := make([]byte, udpControlBufferLength)
	for {
		count, source, ifindex, err := s.conn.readControl(buffer)
		if s.closing.Load() || errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			time.Sleep(udpReadErrorPause)
			continue
		}
		if count != protocol.ControlFrameLength {
			continue
		}
		frame, err := protocol.DecodeControlFrame(buffer[:count])
		if err != nil {
			continue
		}
		if frame.Type == protocol.ControlProbe && frame.Flags&protocol.ControlFlagDownPath != 0 {
			if handle := s.owner.onProbe.Load(); handle != nil {
				(*handle)(downProbe{
					frame:     frame,
					source:    source.Addr().Unmap(),
					transport: protocol.TransportUDP,
					port:      source.Port(),
					received:  time.Now(),
				})
			}
			continue
		}
		if frame.Type == protocol.ControlProbe {
			s.respondToProbe(frame, source.Addr().Unmap())
			continue
		}
		if frame.Type == protocol.ControlRegisterACK {
			s.owner.router.post(frame.PathID, buffer[:count])
		}
		reply := udpControlReply{
			source:  netip.AddrPortFrom(source.Addr().Unmap(), source.Port()),
			ifindex: ifindex,
		}
		copy(reply.frame[:], buffer[:count])
		s.deliver(frame.PathID, reply)
	}
}

// respondToProbe answers a reflector probe. The server sent it spoofed from the
// reflector, so the reflector is the packet source. The client confirms it only
// when the probe is for this client and the reflector is in the path's pool, and
// it answers the real server, not the spoofed source.
func (s *udpControlSocket) respondToProbe(frame protocol.ControlFrame, reflector netip.Addr) {
	s.mu.Lock()
	var registration pathRegistration
	ifindex := 0
	found := false
	for _, waiter := range s.waiters {
		if waiter.pathID == frame.PathID {
			registration = waiter.registration
			ifindex = waiter.ifindex
			found = true
			break
		}
	}
	s.mu.Unlock()
	if !found || !registration.path.IsPool() {
		return
	}
	if frame.AdvertisedIP != registration.advertisedIP || frame.InstanceNonce != registration.nonce {
		return
	}
	if !netip.PrefixFrom(registration.path.ReturnIP, int(registration.path.ReturnPrefix)).Contains(reflector) {
		return
	}
	reply, err := probeReplyFrame(registration, reflector, frame.Sequence)
	if err != nil {
		return
	}
	_ = s.conn.writeControl(reply, registration.path.Endpoint(), ifindex)
}

func (s *udpControlSocket) deliver(pathID uint16, reply udpControlReply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, waiter := range s.waiters {
		if waiter.pathID != pathID {
			continue
		}
		select {
		case waiter.replies <- reply:
		default:
		}
	}
}

func (s *udpControlSocket) subscribe(registration pathRegistration, ifindex int) *udpControlWaiter {
	waiter := &udpControlWaiter{
		pathID:       registration.pathID,
		registration: registration,
		ifindex:      ifindex,
		replies:      make(chan udpControlReply, udpReplyQueueLength),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.waiters = append(s.waiters, waiter)
	return waiter
}

func (s *udpControlSocket) unsubscribe(waiter *udpControlWaiter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for index, current := range s.waiters {
		if current == waiter {
			s.waiters = append(s.waiters[:index], s.waiters[index+1:]...)
			return
		}
	}
}

type udpPathConn struct {
	registration pathRegistration
	destination  netip.AddrPort
	ifindex      int
	sockets      *udpControlSockets
	socket       *udpControlSocket
	waiter       *udpControlWaiter
	// routed takes the ACK of an up path of a group with separate down
	// paths, which can arrive on any down path.
	routed *ackWaiter

	closeOnce sync.Once
	closed    chan struct{}
}

func openUDPPathConn(sockets *udpControlSockets, registration pathRegistration) (*udpPathConn, error) {
	ifindex := 0
	if name := registration.path.Interface; name != "" {
		networkInterface, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("find interface of UDP control path %d: %w", registration.pathID, err)
		}
		ifindex = networkInterface.Index
	}
	return sockets.openPath(registration, ifindex)
}

func (s *udpControlSockets) openPath(registration pathRegistration, ifindex int) (*udpPathConn, error) {
	socket, err := s.acquire(netip.AddrPortFrom(registration.advertisedIP, registration.listenPort))
	if err != nil {
		return nil, err
	}
	conn := &udpPathConn{
		registration: registration,
		destination:  registration.path.Endpoint(),
		ifindex:      ifindex,
		sockets:      s,
		socket:       socket,
		waiter:       socket.subscribe(registration, ifindex),
		closed:       make(chan struct{}),
	}
	if registration.downs != nil {
		conn.routed = s.router.subscribe(registration.pathID)
	}
	return conn, nil
}

func (s *udpPathConn) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.socket.unsubscribe(s.waiter)
		if s.routed != nil {
			s.sockets.router.unsubscribe(s.routed)
		}
		s.sockets.release(s.socket)
	})
	return nil
}

func (s *udpPathConn) Run(ctx context.Context, report probeReporter) error {
	defer s.Close()
	var sequence uint32
	for {
		sequence++
		sentAt := time.Now()
		frame, err := registrationFrame(s.registration, sequence)
		if err != nil {
			return err
		}
		result, err := s.register(ctx, frame, sentAt, sequence)
		if err != nil {
			return err
		}
		if err := report(ctx, sequence, sentAt, result); err != nil {
			return err
		}
		if err := sleepContext(ctx, registrationDelay(result == registerAcked)); err != nil {
			return err
		}
	}
}

func (s *udpPathConn) register(ctx context.Context, frame []byte, sentAt time.Time, sequence uint32) (registerResult, error) {
	select {
	case <-s.closed:
		return registerMissed, net.ErrClosed
	default:
	}
	s.drain()
	for _, down := range s.registration.downFrames(sequence) {
		_ = s.socket.conn.writeControl(down, s.destination, s.ifindex)
	}
	if err := s.socket.conn.writeControl(frame, s.destination, s.ifindex); err != nil {
		return registerMissed, nil
	}
	var routed chan []byte
	if s.routed != nil {
		routed = s.routed.replies
	}
	timer := time.NewTimer(time.Until(sentAt.Add(controlReplyTimeout)))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return registerMissed, nil
		case <-s.closed:
			return registerMissed, net.ErrClosed
		case <-timer.C:
			return registerMissed, nil
		case reply := <-s.waiter.replies:
			if result, ok := reply.answer(s.registration, s.ifindex, sequence); ok {
				return result, nil
			}
		case reply := <-routed:
			if result, ok := registrationACKResult(reply, s.registration.nonce, s.registration.pathID, sequence); ok {
				return result, nil
			}
		}
	}
}

func (s *udpPathConn) drain() {
	for {
		select {
		case <-s.waiter.replies:
		default:
			if s.routed != nil {
				drainRouted(s.routed)
			}
			return
		}
	}
}

func drainRouted(waiter *ackWaiter) {
	for {
		select {
		case <-waiter.replies:
		default:
			return
		}
	}
}
