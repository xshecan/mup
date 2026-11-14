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

func (r udpControlReply) matches(registration pathRegistration, ifindex int, sequence uint32) bool {
	if r.source != registration.path.Endpoint() {
		return false
	}
	if ifindex > 0 && r.ifindex != ifindex {
		return false
	}
	return validateRegistrationACK(r.frame[:], registration.nonce, registration.pathID, sequence) == nil
}

type udpControlSockets struct {
	listen udpControlListener

	mu      sync.Mutex
	sockets map[netip.AddrPort]*udpControlSocket
}

func newUDPControlSockets(listen udpControlListener) *udpControlSockets {
	return &udpControlSockets{listen: listen, sockets: map[netip.AddrPort]*udpControlSocket{}}
}

type udpControlSocket struct {
	local   netip.AddrPort
	conn    udpControlConn
	closing atomic.Bool
	done    chan struct{}

	references int

	mu      sync.Mutex
	waiters []*udpControlWaiter
}

type udpControlWaiter struct {
	pathID  uint16
	replies chan udpControlReply
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
	socket := &udpControlSocket{local: local, conn: conn, done: make(chan struct{}), references: 1}
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
		reply := udpControlReply{
			source:  netip.AddrPortFrom(source.Addr().Unmap(), source.Port()),
			ifindex: ifindex,
		}
		copy(reply.frame[:], buffer[:count])
		s.deliver(frame.PathID, reply)
	}
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

func (s *udpControlSocket) subscribe(pathID uint16) *udpControlWaiter {
	waiter := &udpControlWaiter{pathID: pathID, replies: make(chan udpControlReply, udpReplyQueueLength)}
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
	return &udpPathConn{
		registration: registration,
		destination:  registration.path.Endpoint(),
		ifindex:      ifindex,
		sockets:      s,
		socket:       socket,
		waiter:       socket.subscribe(registration.pathID),
		closed:       make(chan struct{}),
	}, nil
}

func (s *udpPathConn) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.socket.unsubscribe(s.waiter)
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
		success, err := s.register(ctx, frame, sentAt, sequence)
		if err != nil {
			return err
		}
		if err := report(ctx, sequence, sentAt, success); err != nil {
			return err
		}
		if err := sleepContext(ctx, registrationDelay(success)); err != nil {
			return err
		}
	}
}

func (s *udpPathConn) register(ctx context.Context, frame []byte, sentAt time.Time, sequence uint32) (bool, error) {
	select {
	case <-s.closed:
		return false, net.ErrClosed
	default:
	}
	s.drain()
	if err := s.socket.conn.writeControl(frame, s.destination, s.ifindex); err != nil {
		return false, nil
	}
	timer := time.NewTimer(time.Until(sentAt.Add(controlReplyTimeout)))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return false, nil
		case <-s.closed:
			return false, net.ErrClosed
		case <-timer.C:
			return false, nil
		case reply := <-s.waiter.replies:
			if reply.matches(s.registration, s.ifindex, sequence) {
				return true, nil
			}
		}
	}
}

func (s *udpPathConn) drain() {
	for {
		select {
		case <-s.waiter.replies:
		default:
			return
		}
	}
}
