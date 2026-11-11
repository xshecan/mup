//go:build linux

package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
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
	registrationRefresh = 10 * time.Second
	registrationRetry   = time.Second

	// One byte more than a control frame lets a read detect truncation.
	udpControlBufferLength = protocol.ControlFrameLength + 1
	// Raw ICMP reads include an IPv4 header of up to 60 bytes.
	icmpControlBufferLength = 60 + 8 + protocol.ControlFrameLength + 1
)

type syscallConnection interface {
	SyscallConn() (syscall.RawConn, error)
}

func openClientPath(registration pathRegistration) (pathConn, error) {
	if registration.path.Transport == protocol.TransportUDP {
		return openUDPPathConn(registration)
	}
	return openICMPPathConn(registration)
}

type udpPathConn struct {
	connection   *net.UDPConn
	destination  *net.UDPAddr
	registration pathRegistration
}

func openUDPPathConn(registration pathRegistration) (*udpPathConn, error) {
	local := &net.UDPAddr{IP: net.IP(registration.advertisedIP.AsSlice())}
	connection, err := net.ListenUDP("udp4", local)
	if err != nil {
		return nil, fmt.Errorf("open UDP control path %d: %w", registration.pathID, err)
	}
	if err := bindToDevice(connection, registration.path.Interface); err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("bind UDP control path %d: %w", registration.pathID, err)
	}
	return &udpPathConn{
		connection:   connection,
		destination:  net.UDPAddrFromAddrPort(registration.path.Endpoint()),
		registration: registration,
	}, nil
}

func (s *udpPathConn) Close() error {
	return s.connection.Close()
}

func (s *udpPathConn) Run(ctx context.Context, report probeReporter) error {
	defer s.connection.Close()
	var sequence uint32
	for {
		sequence++
		sentAt := time.Now()
		frame, err := registrationFrame(s.registration, sequence)
		if err != nil {
			return err
		}
		success := s.register(frame, sentAt, sequence)
		if err := report(ctx, sequence, sentAt, success); err != nil {
			return err
		}
		if err := sleepContext(ctx, registrationDelay(success)); err != nil {
			return err
		}
	}
}

// register sends one REGISTER and waits for the matching ACK.
func (s *udpPathConn) register(frame []byte, sentAt time.Time, sequence uint32) bool {
	_ = s.connection.SetDeadline(sentAt.Add(controlReplyTimeout))
	if _, err := s.connection.WriteToUDP(frame, s.destination); err != nil {
		return false
	}
	for {
		var reply [udpControlBufferLength]byte
		count, source, err := s.connection.ReadFromUDP(reply[:])
		if err != nil {
			return false
		}
		if count != protocol.ControlFrameLength || source.AddrPort() != s.destination.AddrPort() {
			continue
		}
		if validateRegistrationACK(reply[:count], s.registration.nonce, s.registration.pathID, sequence) == nil {
			return true
		}
	}
}

type icmpPathConn struct {
	connection   *net.IPConn
	destination  *net.IPAddr
	buffer       []byte
	registration pathRegistration
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
	return s.connection.Close()
}

func (s *icmpPathConn) Run(ctx context.Context, report probeReporter) error {
	defer s.connection.Close()
	var sequence uint32
	for {
		sequence++
		sentAt := time.Now()
		frame, err := registrationFrame(s.registration, sequence)
		if err != nil {
			return err
		}
		success := s.register(frame, sentAt, sequence)
		if err := report(ctx, sequence, sentAt, success); err != nil {
			return err
		}
		if err := sleepContext(ctx, registrationDelay(success)); err != nil {
			return err
		}
	}
}

// register sends one REGISTER in an Echo Request and waits for the matching
// ACK in an Echo Reply.
func (s *icmpPathConn) register(frame []byte, sentAt time.Time, sequence uint32) bool {
	path := s.registration.path
	echo := marshalICMPEcho(icmpEchoRequest, path.ServerPort, uint16(sequence), frame)
	_ = s.connection.SetDeadline(sentAt.Add(controlReplyTimeout))
	if _, err := s.connection.WriteToIP(echo, s.destination); err != nil {
		return false
	}
	for {
		// ReadMsgIP keeps the IPv4 header, unlike ReadFromIP.
		count, _, _, source, err := s.connection.ReadMsgIP(s.buffer, nil)
		if err != nil {
			return false
		}
		if ipAddress(source.IP) != path.Server {
			continue
		}
		parsed, parseErr := parseICMPEcho(stripIPv4Header(s.buffer[:count]))
		if parseErr != nil || parsed.echoType != icmpEchoReply || parsed.identifier != path.ServerPort {
			continue
		}
		if validateRegistrationACK(parsed.payload, s.registration.nonce, s.registration.pathID, sequence) == nil {
			return true
		}
	}
}

func registrationDelay(success bool) time.Duration {
	if success {
		return registrationRefresh
	}
	return registrationRetry
}

func serveServerControls(
	ctx context.Context,
	server config.Server,
	registry *control.Registry,
	sink registrationSink,
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 3)
	go func() {
		results <- serveServerUDPControl(ctx, server, registry, sink)
	}()
	go func() {
		results <- serveServerICMPControl(ctx, server, registry, sink)
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
			results <- serveServerUDPConnection(ctx, connection, registry, sink)
		}()
	}
	return <-results
}

func serveServerUDPConnection(
	ctx context.Context,
	connection *net.UDPConn,
	registry *control.Registry,
	sink registrationSink,
) error {
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
		local, err := packetInfoDestination(oob[:oobCount])
		if err != nil {
			continue
		}
		ack, err := acceptRegistration(
			buffer[:count],
			protocol.TransportUDP,
			ipAddress(source.IP),
			local,
			registry,
			sink,
		)
		if err == nil {
			_, _, _ = connection.WriteMsgUDP(ack, replySource(local), source)
		}
	}
}

func serveServerICMPControl(
	ctx context.Context,
	server config.Server,
	registry *control.Registry,
	sink registrationSink,
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
		if err != nil || echo.echoType != icmpEchoRequest || !server.Port.Contains(echo.identifier) {
			continue
		}
		local, err := packetInfoDestination(oob[:oobCount])
		if err != nil {
			continue
		}
		ack, err := acceptRegistration(
			echo.payload,
			protocol.TransportICMP,
			ipAddress(source.IP),
			local,
			registry,
			sink,
		)
		if err == nil {
			reply := marshalICMPEcho(icmpEchoReply, echo.identifier, echo.sequence, ack)
			_, _, _ = connection.WriteMsgIP(reply, replySource(local), source)
		}
	}
}

func acceptRegistration(
	packet []byte,
	transport protocol.TransportID,
	source, local netip.Addr,
	registry *control.Registry,
	sink registrationSink,
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
			ServerPort: frame.ServerPort,
		},
	}
	result, err := registry.Register(time.Now(), request)
	if err != nil {
		return nil, err
	}
	if result.Replaced != nil {
		if err := sink.RevokeRegistration(dataplane.ClientKey{
			AdvertisedIP:  result.Replaced.AdvertisedIP,
			InstanceNonce: result.Replaced.InstanceNonce,
		}); err != nil {
			return nil, err
		}
	}
	now, err := monotonicNowNS()
	if err != nil {
		return nil, err
	}
	settings := dataplane.RegistrationSettings{
		AdvertisedIP:  frame.AdvertisedIP,
		InstanceNonce: frame.InstanceNonce,
		ReturnIP:      frame.ReturnIP,
		ListenPort:    frame.ListenPort,
		PathCount:     1,
		ExpiresAtNS:   now + uint64(registrationLeaseSeconds)*uint64(time.Second),
		Path: dataplane.RegisteredPathSettings{
			SourceIP:   source,
			LocalIP:    local,
			ServerPort: frame.ServerPort,
			Transport:  transport,
			PathID:     frame.PathID,
		},
	}
	if err := sink.RegisterPath(settings); err != nil {
		return nil, err
	}
	ackFrame := frame
	ackFrame.Type = protocol.ControlRegisterACK
	ackFrame.Status = protocol.ControlStatusOK
	ackFrame.LeaseSeconds = registrationLeaseSeconds
	ack := make([]byte, protocol.ControlFrameLength)
	if err := protocol.EncodeControlFrame(ack, ackFrame); err != nil {
		return nil, err
	}
	return ack, nil
}

func registrationFrame(registration pathRegistration, sequence uint32) ([]byte, error) {
	frame := protocol.ControlFrame{
		Type:          protocol.ControlRegister,
		Transport:     registration.path.Transport,
		PathID:        registration.pathID,
		Sequence:      sequence,
		ListenPort:    registration.listenPort,
		ServerPort:    registration.path.ServerPort,
		LeaseSeconds:  registrationLeaseSeconds,
		InstanceNonce: registration.nonce,
		AdvertisedIP:  registration.advertisedIP,
		ReturnIP:      registration.returnIP,
	}
	if registration.returnIP.IsValid() {
		frame.Flags = protocol.ControlFlagReturnIP
	}
	packet := make([]byte, protocol.ControlFrameLength)
	if err := protocol.EncodeControlFrame(packet, frame); err != nil {
		return nil, err
	}
	return packet, nil
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
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, message := range messages {
		if message.Header.Level != unix.IPPROTO_IP || message.Header.Type != unix.IP_PKTINFO ||
			len(message.Data) < unix.SizeofInet4Pktinfo {
			continue
		}
		info := *(*unix.Inet4Pktinfo)(unsafe.Pointer(&message.Data[0]))
		address := netip.AddrFrom4(info.Addr)
		if address.IsUnspecified() {
			address = netip.AddrFrom4(info.Spec_dst)
		}
		if address.Is4() && !address.IsUnspecified() {
			return address, nil
		}
	}
	return netip.Addr{}, errors.New("IPv4 packet info is missing")
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

func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isTimeoutOrCanceled(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	var networkError net.Error
	return ctx.Err() != nil || (errors.As(err, &networkError) && networkError.Timeout())
}
