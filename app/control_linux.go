//go:build linux

package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/control"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/protocol"
)

const (
	// Raw ICMP reads include an IPv4 header of up to 60 bytes.
	icmpControlBufferLength = 60 + 8 + protocol.ControlFrameLength + 1
)

type syscallConnection interface {
	SyscallConn() (syscall.RawConn, error)
}

// linuxClientControls owns the control sockets of a client. The UDP sockets
// of the groups take the frames on UDP paths. One raw ICMP socket takes the
// frames on the ICMP egress paths, and the ACKs of the ICMP ingress paths, of the
// groups with separate egress paths.
type linuxClientControls struct {
	sockets *udpControlSockets

	mu   sync.Mutex
	icmp *net.IPConn
	// raw sends the frames that go through a bridge or a via host. It opens
	// on first use.
	raw     int
	rawOpen bool
	// turns holds the next member turn of each ingress reflect path.
	turns map[uint16]uint
}

func newClientPathOpener() clientControls {
	return &linuxClientControls{sockets: newUDPControlSockets(listenUDPControl)}
}

func (c *linuxClientControls) open(registration pathRegistration) (pathConn, error) {
	if registration.ingressReflect {
		return openIngressReflectPathConn(registration, c.sockets.router)
	}
	if registration.path.Transport == protocol.TransportUDP {
		return openUDPPathConn(c.sockets, registration)
	}
	conn, err := openICMPPathConn(registration)
	if err != nil {
		return nil, err
	}
	if registration.egresses != nil {
		// The ACK of this path can arrive on any egress path, and the shared
		// ICMP socket reads it, so this socket only sends.
		if err := dropAllInput(conn.connection); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("filter ICMP control path %d: %w", registration.pathID, err)
		}
		conn.router = c.sockets.router
		conn.routed = c.sockets.router.subscribe(registration.pathID)
	}
	return conn, nil
}

func (c *linuxClientControls) listenEgress(listen egressListen, handle func(egressProbe)) (func(), error) {
	connection, err := net.ListenIP("ip4:icmp", &net.IPAddr{IP: net.IP(listen.advertisedIP.AsSlice())})
	if err != nil {
		return nil, fmt.Errorf("open the ICMP socket of the egress paths: %w", err)
	}
	sockets := make([]*udpControlSocket, 0, len(listen.listenPorts))
	release := func() {
		for _, socket := range sockets {
			c.sockets.release(socket)
		}
	}
	for _, port := range listen.listenPorts {
		socket, err := c.sockets.acquire(netip.AddrPortFrom(listen.advertisedIP, port))
		if err != nil {
			release()
			_ = connection.Close()
			return nil, err
		}
		sockets = append(sockets, socket)
	}
	c.sockets.onProbe.Store(&handle)
	c.mu.Lock()
	c.icmp = connection
	c.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		readEgressICMP(connection, listen.nonce, c.sockets.router, handle)
	}()
	return func() {
		c.sockets.onProbe.Store(nil)
		c.mu.Lock()
		c.icmp = nil
		c.mu.Unlock()
		_ = connection.Close()
		<-done
		release()
	}, nil
}

// readEgressICMP reads the Echo Replies to the client. A REGISTER_ACK goes to
// the ingress path that waits for it and to handle, which measures the egress
// path. An egress path probe goes to handle.
func readEgressICMP(connection *net.IPConn, nonce uint64, router *ackRouter, handle func(egressProbe)) {
	buffer := make([]byte, icmpControlBufferLength)
	for {
		count, _, _, source, err := connection.ReadMsgIP(buffer, nil)
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			time.Sleep(udpReadErrorPause)
			continue
		}
		echo, err := parseICMPEcho(stripIPv4Header(buffer[:count]))
		if err != nil || echo.echoType != icmpEchoReply || len(echo.payload) != protocol.ControlFrameLength {
			continue
		}
		frame, err := protocol.DecodeControlFrame(echo.payload)
		if err != nil || frame.InstanceNonce != nonce {
			continue
		}
		received := time.Now()
		switch {
		case frame.Type == protocol.ControlRegisterACK:
			router.post(frame.PathID, echo.payload)
			handle(egressProbe{
				frame:     frame,
				source:    ipAddress(source.IP),
				transport: protocol.TransportICMP,
				port:      echo.identifier,
				received:  received,
			})
		case frame.Type == protocol.ControlProbe && frame.Flags&protocol.ControlFlagEgressPath != 0:
			handle(egressProbe{
				frame:     frame,
				source:    ipAddress(source.IP),
				transport: protocol.TransportICMP,
				port:      echo.identifier,
				received:  received,
			})
		}
	}
}

func (c *linuxClientControls) sendIngress(registration pathRegistration, frame []byte) error {
	if registration.path.BridgeReflect() {
		return c.sendIngressViaBridge(registration, frame)
	}
	if registration.ingressReflect {
		return c.sendIngressReflected(registration, frame)
	}
	ifindex := 0
	if name := registration.path.Interface; name != "" {
		networkInterface, err := net.InterfaceByName(name)
		if err != nil {
			return err
		}
		ifindex = networkInterface.Index
	}
	if registration.path.Transport == protocol.TransportUDP {
		socket, err := c.sockets.acquire(netip.AddrPortFrom(registration.advertisedIP, registration.listenPort))
		if err != nil {
			return err
		}
		defer c.sockets.release(socket)
		return socket.conn.writeControl(frame, registration.path.Endpoint(), ifindex)
	}
	c.mu.Lock()
	connection := c.icmp
	c.mu.Unlock()
	if connection == nil {
		return errors.New("the ICMP socket of the egress paths is closed")
	}
	echo := marshalICMPEcho(icmpEchoRequest, registration.path.ServerPort, 0, frame)
	var oob []byte
	if ifindex > 0 {
		oob = unix.PktInfo4(&unix.Inet4Pktinfo{Ifindex: int32(ifindex), Spec_dst: registration.advertisedIP.As4()})
	}
	_, _, err := connection.WriteMsgIP(echo, oob, &net.IPAddr{IP: net.IP(registration.path.Server.AsSlice())})
	return err
}

// sendIngressViaBridge sends a control frame on an ingress path that reflects through a
// bridge. Such a client does not reach the server directly, which is the
// reason for the bridge, so a frame that it sends straight to the server is
// lost. The bridge emits the frame to the server from the advertised IP.
func (c *linuxClientControls) sendIngressViaBridge(registration pathRegistration, frame []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.bindRawLocked(registration); err != nil {
		return err
	}
	packet := bridgeControlPacket(registration, frame, 0)
	return unix.Sendto(c.raw, packet, 0, &unix.SockaddrInet4{Addr: registration.path.ProxyBridge.As4()})
}

// sendIngressReflected sends a control frame on an ingress reflect path without
// a bridge. Such a client does not reach the server directly, so it reflects
// the frame like the REGISTER of the path, through one member. It takes the
// healthy members in turn, or the candidates in turn while none is healthy.
func (c *linuxClientControls) sendIngressReflected(registration pathRegistration, frame []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.turns == nil {
		c.turns = make(map[uint16]uint)
	}
	turn := c.turns[registration.pathID]
	c.turns[registration.pathID] = turn + 1
	member, ok := pickReflectMember(registration.healthyMembers, registration.members, turn)
	if !ok {
		return fmt.Errorf("ingress reflect path %d has no member", registration.pathID)
	}
	if err := c.bindRawLocked(registration); err != nil {
		return err
	}
	packet, destination := reflectedControlPacket(registration, member, frame, 0)
	return unix.Sendto(c.raw, packet, 0, &unix.SockaddrInet4{Addr: destination.As4()})
}

// bindRawLocked opens the raw socket on first use and binds it to the
// interface of the path. The socket serves every path, so each send sets its
// interface. An empty name removes the binding.
func (c *linuxClientControls) bindRawLocked(registration pathRegistration) error {
	if !c.rawOpen {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
		if err != nil {
			return fmt.Errorf("open the raw control socket: %w", err)
		}
		c.raw, c.rawOpen = fd, true
	}
	if err := unix.BindToDevice(c.raw, registration.path.Interface); err != nil {
		return fmt.Errorf("bind the raw control socket to %q: %w", registration.path.Interface, err)
	}
	return nil
}

// dropAllInput attaches a socket filter that drops every packet, for a raw
// socket that only sends.
func dropAllInput(connection syscallConnection) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	filter := []unix.SockFilter{{Code: unix.BPF_RET | unix.BPF_K, K: 0}}
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		socketErr = unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &program)
	}); err != nil {
		return err
	}
	return socketErr
}

type udpControlSocketConn struct {
	connection *net.UDPConn
	advertised netip.Addr
	oob        []byte
}

func listenUDPControl(local netip.AddrPort) (udpControlConn, error) {
	connection, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(local))
	if err != nil {
		return nil, err
	}
	if err := enablePacketInfo(connection); err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("enable UDP packet info: %w", err)
	}
	return &udpControlSocketConn{
		connection: connection,
		advertised: local.Addr(),
		oob:        make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo)),
	}, nil
}

func (s *udpControlSocketConn) readControl(buffer []byte) (int, netip.AddrPort, int, error) {
	count, oobCount, _, source, err := s.connection.ReadMsgUDPAddrPort(buffer, s.oob)
	if err != nil {
		return 0, netip.AddrPort{}, 0, err
	}
	ifindex := 0
	if info, err := packetInfo(s.oob[:oobCount]); err == nil {
		ifindex = int(info.Ifindex)
	}
	return count, source, ifindex, nil
}

func (s *udpControlSocketConn) writeControl(frame []byte, destination netip.AddrPort, ifindex int) error {
	if ifindex <= 0 {
		_, err := s.connection.WriteToUDPAddrPort(frame, destination)
		return err
	}
	oob := unix.PktInfo4(&unix.Inet4Pktinfo{Ifindex: int32(ifindex), Spec_dst: s.advertised.As4()})
	_, _, err := s.connection.WriteMsgUDPAddrPort(frame, oob, destination)
	return err
}

func (s *udpControlSocketConn) Close() error {
	return s.connection.Close()
}

type icmpPathConn struct {
	connection   *net.IPConn
	destination  *net.IPAddr
	buffer       []byte
	registration pathRegistration
	// An ingress path of a group with separate egress paths reads its ACK from
	// the shared ICMP socket through routed.
	router *ackRouter
	routed *ackWaiter
}

func openICMPPathConn(registration pathRegistration) (*icmpPathConn, error) {
	connection, err := net.ListenIP("ip4:icmp", &net.IPAddr{IP: net.IP(registration.advertisedIP.AsSlice())})
	if err != nil {
		return nil, fmt.Errorf("open ICMP control path %d: %w", registration.pathID, err)
	}
	if err := bindToDevice(connection, registration.path.Interface); err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("bind ICMP control path %d: %w", registration.pathID, err)
	}
	return &icmpPathConn{
		connection:   connection,
		destination:  &net.IPAddr{IP: net.IP(registration.path.Server.AsSlice())},
		buffer:       make([]byte, icmpControlBufferLength),
		registration: registration,
	}, nil
}

func (s *icmpPathConn) Close() error {
	if s.routed != nil {
		s.router.unsubscribe(s.routed)
	}
	return s.connection.Close()
}

func (s *icmpPathConn) Run(ctx context.Context, report probeReporter) error {
	defer s.Close()
	var sequence uint32
	for {
		sequence++
		sentAt := time.Now()
		frame, err := registrationFrame(s.registration, sequence)
		if err != nil {
			return err
		}
		result := s.register(frame, sentAt, sequence)
		if err := report(ctx, sequence, sentAt, time.Time{}, result); err != nil {
			return err
		}
		if err := sleepContext(ctx, registrationDelay(result == registerAcked)); err != nil {
			return err
		}
	}
}

// register sends one REGISTER in an Echo Request and waits for the matching
// ACK in an Echo Reply.
func (s *icmpPathConn) register(frame []byte, sentAt time.Time, sequence uint32) registerResult {
	path := s.registration.path
	for _, egress := range s.registration.egressFrames(sequence) {
		_, _ = s.connection.WriteToIP(marshalICMPEcho(icmpEchoRequest, path.ServerPort, uint16(sequence), egress), s.destination)
	}
	if s.routed != nil {
		drainRouted(s.routed)
	}
	echo := marshalICMPEcho(icmpEchoRequest, path.ServerPort, uint16(sequence), frame)
	// Only the read has a deadline. A deadline on the writes would still be in
	// the past at the next round, and the EGRESS_REGISTER frames above would
	// then fail without a word, so the server would lose the egress paths.
	_ = s.connection.SetReadDeadline(sentAt.Add(controlReplyTimeout))
	if _, err := s.connection.WriteToIP(echo, s.destination); err != nil {
		return registerMissed
	}
	if s.routed != nil {
		return s.awaitRouted(sentAt, sequence)
	}
	for {
		// ReadMsgIP keeps the IPv4 header, unlike ReadFromIP.
		count, _, _, source, err := s.connection.ReadMsgIP(s.buffer, nil)
		if err != nil {
			return registerMissed
		}
		if ipAddress(source.IP) != path.Server {
			continue
		}
		parsed, parseErr := parseICMPEcho(stripIPv4Header(s.buffer[:count]))
		if parseErr != nil || parsed.echoType != icmpEchoReply || parsed.identifier != path.ServerPort {
			continue
		}
		if result, ok := registrationACKResult(parsed.payload, s.registration.nonce, s.registration.pathID, sequence); ok {
			return result
		}
	}
}

// awaitRouted waits for the ACK of an ingress path of a group with separate egress
// paths, which the shared ICMP socket or a UDP socket passes on.
func (s *icmpPathConn) awaitRouted(sentAt time.Time, sequence uint32) registerResult {
	timer := time.NewTimer(time.Until(sentAt.Add(controlReplyTimeout)))
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			return registerMissed
		case reply := <-s.routed.replies:
			if result, ok := registrationACKResult(reply, s.registration.nonce, s.registration.pathID, sequence); ok {
				return result
			}
		}
	}
}

func serveServerControls(
	ctx context.Context,
	server config.Server,
	registry *control.Registry,
	sink registrationSink,
	targets *reflectorTargets,
	egresses *egressService,
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 3)
	go func() {
		results <- serveServerUDPControl(ctx, server, registry, sink, targets, egresses)
	}()
	go func() {
		results <- serveServerICMPControl(ctx, server, registry, sink, targets, egresses)
	}()
	go func() {
		results <- expireRegistry(ctx, registry)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-results:
		if err == nil {
			return errors.New("server control listener stopped unexpectedly")
		}
		return err
	}
}

// expireRegistry forgets expired registrations. The dataplane sweeper expires
// the matching BPF entries by their own deadlines.
func expireRegistry(ctx context.Context, registry *control.Registry) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now := <-ticker.C:
			registry.Expire(now)
		}
	}
}

func serveServerUDPControl(
	ctx context.Context,
	server config.Server,
	registry *control.Registry,
	sink registrationSink,
	targets *reflectorTargets,
	egresses *egressService,
) error {
	connections := make([]*net.UDPConn, 0, server.Port.Len())
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	for port := int(server.Port.First); port <= int(server.Port.Last); port++ {
		connection, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
		if err != nil {
			return fmt.Errorf("listen UDP/%d: %w", port, err)
		}
		connections = append(connections, connection)
		if err := enablePacketInfo(connection); err != nil {
			return fmt.Errorf("enable UDP packet info on port %d: %w", port, err)
		}
	}
	results := make(chan error, len(connections))
	for _, connection := range connections {
		go func() {
			results <- serveServerUDPConnection(ctx, connection, registry, sink, targets, egresses)
		}()
	}
	return <-results
}

func serveServerUDPConnection(
	ctx context.Context,
	connection *net.UDPConn,
	registry *control.Registry,
	sink registrationSink,
	targets *reflectorTargets,
	egresses *egressService,
) error {
	serverPort := uint16(connection.LocalAddr().(*net.UDPAddr).Port)
	buffer := make([]byte, udpControlBufferLength)
	oob := make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
	for {
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		count, oobCount, _, source, err := connection.ReadMsgUDP(buffer, oob)
		if isTimeoutOrCanceled(ctx, err) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		if err != nil {
			return err
		}
		if count != protocol.ControlFrameLength {
			continue
		}
		frame, err := protocol.DecodeControlFrame(buffer[:count])
		if err != nil {
			continue
		}
		// The egress frames of a reflect path arrive from a via host, so the
		// server finds the path of the packet before it handles them.
		local, localErr := packetInfoDestination(oob[:oobCount])
		arrival := control.PathKey{Local: local, Source: ipAddress(source.IP), Transport: protocol.TransportUDP, ServerPort: serverPort}
		if egresses.handle(frame, arrival.Source, arrivedOnReflectPath(registry, frame, arrival, time.Now())) {
			continue
		}
		// A probe reply confirms a UDP reflector reached the client. It carries
		// the reflector in its return IP, because the reply itself comes from
		// the client, not from the spoofed source.
		if frame.Type == protocol.ControlProbeReply {
			if targets != nil && targets.confirms(frame, time.Now()) {
				_ = sink.ConfirmReflector(frame.ReturnIP)
			}
			continue
		}
		if localErr != nil {
			continue
		}
		ack, err := acceptRegistration(
			buffer[:count],
			protocol.TransportUDP,
			serverPort,
			ipAddress(source.IP),
			local,
			registry,
			sink,
			targets,
			egresses,
		)
		if err == nil {
			_, _, _ = connection.WriteMsgUDP(ack, replySource(local), source)
			egresses.ack(frame, ack)
		}
	}
}

func serveServerICMPControl(
	ctx context.Context,
	server config.Server,
	registry *control.Registry,
	sink registrationSink,
	targets *reflectorTargets,
	egresses *egressService,
) error {
	connection, err := net.ListenIP("ip4:icmp", &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		return fmt.Errorf("listen ICMP: %w", err)
	}
	defer connection.Close()
	if err := enablePacketInfo(connection); err != nil {
		return fmt.Errorf("enable ICMP packet info: %w", err)
	}
	buffer := make([]byte, icmpControlBufferLength)
	oob := make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
	for {
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		count, oobCount, _, source, err := connection.ReadMsgIP(buffer, oob)
		if isTimeoutOrCanceled(ctx, err) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		if err != nil {
			return err
		}
		echo, err := parseICMPEcho(stripIPv4Header(buffer[:count]))
		// A reflected ingress REGISTER arrives as an Echo Reply from the via host, so
		// the server reads both Echo Requests and Echo Replies as control.
		if err != nil || (echo.echoType != icmpEchoRequest && echo.echoType != icmpEchoReply) ||
			!server.Port.Contains(echo.identifier) {
			continue
		}
		frame, err := protocol.DecodeControlFrame(echo.payload)
		if err != nil {
			continue
		}
		// A reflected egress frame arrives as an Echo Reply from the via host,
		// so the server finds the path of the packet before it handles it.
		local, localErr := packetInfoDestination(oob[:oobCount])
		arrival := control.PathKey{Local: local, Source: ipAddress(source.IP), Transport: protocol.TransportICMP, ServerPort: echo.identifier}
		if egresses.handle(frame, arrival.Source, arrivedOnReflectPath(registry, frame, arrival, time.Now())) {
			continue
		}
		if localErr != nil {
			continue
		}
		ack, err := acceptRegistration(
			echo.payload,
			protocol.TransportICMP,
			echo.identifier,
			ipAddress(source.IP),
			local,
			registry,
			sink,
			targets,
			egresses,
		)
		if err == nil {
			reply := marshalICMPEcho(icmpEchoReply, echo.identifier, echo.sequence, ack)
			_, _, _ = connection.WriteMsgIP(reply, replySource(local), source)
			egresses.ack(frame, ack)
		}
	}
}

func acceptRegistration(
	packet []byte,
	transport protocol.TransportID,
	serverPort uint16,
	source, local netip.Addr,
	registry *control.Registry,
	sink registrationSink,
	targets *reflectorTargets,
	egresses *egressService,
) ([]byte, error) {
	frame, err := protocol.DecodeControlFrame(packet)
	if err != nil {
		return nil, err
	}
	request := control.RegistrationRequest{
		Frame: frame,
		Path: control.PathKey{
			Local:      local,
			Source:     source,
			Transport:  transport,
			ServerPort: serverPort,
		},
	}
	result, err := registry.Register(time.Now(), request)
	if err != nil {
		return nil, err
	}
	if result.Replaced != nil {
		replaced := dataplane.ClientKey{
			AdvertisedIP:  result.Replaced.AdvertisedIP,
			InstanceNonce: result.Replaced.InstanceNonce,
		}
		if err := sink.RevokeRegistration(replaced); err != nil {
			return nil, err
		}
		egresses.revoke(replaced)
	}
	now, err := monotonicNowNS()
	if err != nil {
		return nil, err
	}
	balance := config.BalancePerPeer
	if frame.Flags&protocol.ControlFlagBalancePerPacket != 0 {
		balance = config.BalancePerPacket
	}
	// An ingress reflect REGISTER arrives from the via host, so its source is the
	// via. The path accepts the reflected ingress from that source, and it
	// reflects no replies, so the server skips the reflector setup below.
	ingressReflect := frame.Flags&protocol.ControlFlagIngressReflect != 0
	settings := dataplane.RegistrationSettings{
		AdvertisedIP:   frame.AdvertisedIP,
		InstanceNonce:  frame.InstanceNonce,
		ReturnIP:       frame.ReturnIP,
		ReturnPrefix:   frame.ReturnPrefix,
		Balance:        balance,
		ListenPort:     frame.ListenPort,
		PathCount:      1,
		ExpiresAtNS:    now + uint64(registrationLeaseSeconds)*uint64(time.Second),
		IngressReflect: ingressReflect,
		Path: dataplane.RegisteredPathSettings{
			SourceIP:   source,
			LocalIP:    local,
			ServerPort: serverPort,
			Transport:  transport,
			PathID:     frame.PathID,
		},
	}
	if err := sink.RegisterPath(settings); err != nil {
		return nil, err
	}
	status := protocol.ControlStatusOK
	if !ingressReflect && frame.Flags&protocol.ControlFlagReturnPool != 0 {
		if err := sink.ObservePool(frame.ReturnIP, frame.ReturnPrefix, transport); err != nil {
			return nil, err
		}
		// Without a healthy reflector, the server drops every reply of the
		// path, so it tells the client, and the client counts the path as
		// missed. The registration stays, so the path comes back when a
		// reflector does.
		ready, err := sink.PoolReady(frame.ReturnIP, transport)
		if err != nil {
			return nil, err
		}
		if !ready {
			status = protocol.ControlStatusNoReflector
		}
		// A UDP reflector is a spoofed source, so the server probes it toward
		// the client and the client confirms it. Record the client as a target.
		if transport == protocol.TransportUDP && targets != nil {
			targets.add(reflectorTarget{
				advertisedIP: frame.AdvertisedIP,
				listenPort:   frame.ListenPort,
				nonce:        frame.InstanceNonce,
				pathID:       frame.PathID,
				serverPort:   serverPort,
				base:         frame.ReturnIP,
				prefix:       frame.ReturnPrefix,
			}, time.Now().Add(registrationLeaseSeconds*time.Second))
		}
	}
	ackFrame := frame
	ackFrame.Type = protocol.ControlRegisterACK
	ackFrame.Status = status
	ackFrame.LeaseSeconds = registrationLeaseSeconds
	ack := make([]byte, protocol.ControlFrameLength)
	if err := protocol.EncodeControlFrame(ack, ackFrame); err != nil {
		return nil, err
	}
	return ack, nil
}

func enablePacketInfo(connection syscallConnection) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		socketErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
	}); err != nil {
		return err
	}
	return socketErr
}

func bindToDevice(connection syscallConnection, interfaceName string) error {
	if interfaceName == "" {
		return nil
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		socketErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, interfaceName)
	}); err != nil {
		return err
	}
	return socketErr
}

// replySource makes a reply leave from the local address that received the
// request. Otherwise a server with several addresses can answer from another
// address, and the client rejects the reply.
func replySource(local netip.Addr) []byte {
	return unix.PktInfo4(&unix.Inet4Pktinfo{Spec_dst: local.As4()})
}

func packetInfoDestination(oob []byte) (netip.Addr, error) {
	info, err := packetInfo(oob)
	if err != nil {
		return netip.Addr{}, err
	}
	address := netip.AddrFrom4(info.Addr)
	if address.IsUnspecified() {
		address = netip.AddrFrom4(info.Spec_dst)
	}
	if !address.IsUnspecified() {
		return address, nil
	}
	return netip.Addr{}, errors.New("IPv4 packet info is missing")
}

func packetInfo(oob []byte) (unix.Inet4Pktinfo, error) {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return unix.Inet4Pktinfo{}, err
	}
	for _, message := range messages {
		if message.Header.Level != unix.IPPROTO_IP || message.Header.Type != unix.IP_PKTINFO ||
			len(message.Data) < unix.SizeofInet4Pktinfo {
			continue
		}
		return *(*unix.Inet4Pktinfo)(unsafe.Pointer(&message.Data[0])), nil
	}
	return unix.Inet4Pktinfo{}, errors.New("IPv4 packet info is missing")
}

func monotonicNowNS() (uint64, error) {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return 0, err
	}
	return uint64(now.Nano()), nil
}

func stripIPv4Header(packet []byte) []byte {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return nil
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || headerLength > len(packet) {
		return nil
	}
	return packet[headerLength:]
}

func ipAddress(ip net.IP) netip.Addr {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	return address.Unmap()
}

func isTimeoutOrCanceled(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	var networkError net.Error
	return ctx.Err() != nil || (errors.As(err, &networkError) && networkError.Timeout())
}
