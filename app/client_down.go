package app

import (
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/protocol"
)

// clientControls owns the control sockets of a client. It opens the socket of
// each ingress path, receives the frames that arrive on egress paths, and sends a
// frame on an ingress path.
type clientControls interface {
	open(pathRegistration) (pathConn, error)
	// listenEgress starts to receive the frames on the egress paths of the
	// groups with these listen ports. It passes each egress path probe to
	// handle, and each REGISTER_ACK to the ingress path that waits for it and
	// to handle. The returned function stops it.
	listenEgress(listen egressListen, handle func(egressProbe)) (func(), error)
	// sendIngress sends one control frame on an ingress path.
	sendIngress(registration pathRegistration, frame []byte) error
}

// egressListen names what a client receives on its egress paths.
type egressListen struct {
	advertisedIP netip.Addr
	nonce        uint64
	listenPorts  []uint16
}

// egressProbe is a PROBE or a REGISTER_ACK that arrived on an egress socket. Source
// is the packet source, and Port is the UDP source port or the ICMP identifier.
type egressProbe struct {
	frame     protocol.ControlFrame
	source    netip.Addr
	transport protocol.TransportID
	port      uint16
	received  time.Time
}

// open lets a pathOpener act as the controls of a client without egress paths.
func (o pathOpener) open(registration pathRegistration) (pathConn, error) {
	return o(registration)
}

func (pathOpener) listenEgress(egressListen, func(egressProbe)) (func(), error) {
	return func() {}, nil
}

func (pathOpener) sendIngress(pathRegistration, []byte) error {
	return nil
}

// ackRouter passes each REGISTER_ACK of a group with egress paths to the ingress path
// that waits for it. The ACK can arrive on any egress path, so on any socket.
type ackRouter struct {
	mu      sync.Mutex
	waiters []*ackWaiter
}

type ackWaiter struct {
	pathID  uint16
	replies chan []byte
}

func (r *ackRouter) subscribe(pathID uint16) *ackWaiter {
	waiter := &ackWaiter{pathID: pathID, replies: make(chan []byte, udpReplyQueueLength)}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.waiters = append(r.waiters, waiter)
	return waiter
}

func (r *ackRouter) unsubscribe(waiter *ackWaiter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.waiters = slices.DeleteFunc(r.waiters, func(current *ackWaiter) bool { return current == waiter })
}

// post passes a copy of a frame to the waiters of its path. A full waiter
// drops it, because a later REGISTER asks again.
func (r *ackRouter) post(pathID uint16, frame []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, waiter := range r.waiters {
		if waiter.pathID != pathID {
			continue
		}
		select {
		case waiter.replies <- slices.Clone(frame):
		default:
		}
	}
}

// egressSet holds the egress paths of a group with separate egress paths. Each ingress
// path of the group sends a EGRESS_REGISTER for each of them with every
// REGISTER, so each server that an ingress path reaches learns them all. A removed
// egress path stays in the frames with a lease of zero for one lease, so the
// servers forget it at once.
type egressSet struct {
	mu        sync.Mutex
	mode      config.Mode
	paths     map[uint16]config.Path
	withdrawn map[uint16]egressWithdrawal
}

type egressWithdrawal struct {
	path  config.Path
	until time.Time
}

func newEgressSet(mode config.Mode) *egressSet {
	return &egressSet{mode: mode, paths: make(map[uint16]config.Path), withdrawn: make(map[uint16]egressWithdrawal)}
}

func (d *egressSet) set(slot uint16, path config.Path) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.paths[slot] = path
	delete(d.withdrawn, slot)
}

func (d *egressSet) remove(slot uint16, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if path, ok := d.paths[slot]; ok {
		d.withdrawn[slot] = egressWithdrawal{path: path, until: now.Add(registrationLeaseSeconds * time.Second)}
	}
	delete(d.paths, slot)
}

func (d *egressSet) setMode(mode config.Mode) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.mode = mode
}

// frames builds the EGRESS_REGISTER frames that an ingress path sends before its
// REGISTER with this sequence.
func (d *egressSet) frames(registration pathRegistration, sequence uint32, now time.Time) [][]byte {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	frames := make([][]byte, 0, len(d.paths)+len(d.withdrawn))
	for slot, path := range d.paths {
		if frame, err := egressRegisterFrame(registration, slot, path, d.mode, sequence, registrationLeaseSeconds); err == nil {
			frames = append(frames, frame)
		}
	}
	for slot, withdrawal := range d.withdrawn {
		if now.After(withdrawal.until) {
			delete(d.withdrawn, slot)
			continue
		}
		if frame, err := egressRegisterFrame(registration, slot, withdrawal.path, d.mode, sequence, 0); err == nil {
			frames = append(frames, frame)
		}
	}
	return frames
}

func egressRegisterFrame(registration pathRegistration, slot uint16, path config.Path, mode config.Mode, sequence, lease uint32) ([]byte, error) {
	frame := protocol.ControlFrame{
		Type:          protocol.ControlEgressRegister,
		Transport:     path.Transport,
		PathID:        slot,
		Sequence:      sequence,
		ListenPort:    registration.listenPort,
		ServerPort:    path.ServerPort,
		LeaseSeconds:  lease,
		InstanceNonce: registration.nonce,
		AdvertisedIP:  registration.advertisedIP,
		EgressMode:    uint8(mode),
		EgressServer:  path.Server,
	}
	switch {
	case path.IsPool():
		frame.ReturnIP = path.ReturnIP
		frame.ReturnPrefix = path.ReturnPrefix
		frame.Flags = protocol.ControlFlagReturnPool
		if path.Balance == config.BalancePerPacket {
			frame.Flags |= protocol.ControlFlagBalancePerPacket
		}
	case path.ReturnIP.IsValid():
		frame.ReturnIP = path.ReturnIP
		frame.Flags = protocol.ControlFlagReturnIP
	}
	if path.Bridge {
		frame.Flags |= protocol.ControlFlagBridge
	}
	if path.BridgeVia {
		frame.Flags |= protocol.ControlFlagBridgeVia
	}
	// The source range takes the bytes of the sequence, and the server does
	// not read the sequence of a EGRESS_REGISTER.
	setSourceRange(&frame, path)
	if frame.Flags&protocol.ControlFlagSourceRange != 0 {
		frame.Sequence = 0
	}
	packet := make([]byte, protocol.ControlFrameLength)
	if err := protocol.EncodeControlFrame(packet, frame); err != nil {
		return nil, err
	}
	return packet, nil
}

// egressProbeReplyFrame answers a probe of an egress path. It names the return IP
// of the probe when the probe has one. The server puts the member there for a
// bridge via path, because the client sees only the bridge address. Otherwise
// it names the source that the probe came from, which is the reflector of a
// reflected path.
func egressProbeReplyFrame(registration pathRegistration, probe egressProbe, path config.Path) ([]byte, error) {
	named := probe.source
	if probe.frame.Flags&protocol.ControlFlagReturnIP != 0 && probe.frame.ReturnIP.IsValid() {
		named = probe.frame.ReturnIP
	}
	frame := protocol.ControlFrame{
		Type:          protocol.ControlProbeReply,
		Transport:     path.Transport,
		Flags:         protocol.ControlFlagEgressPath | protocol.ControlFlagReturnIP,
		PathID:        probe.frame.PathID,
		Sequence:      probe.frame.Sequence,
		ListenPort:    registration.listenPort,
		ServerPort:    path.ServerPort,
		InstanceNonce: registration.nonce,
		AdvertisedIP:  registration.advertisedIP,
		ReturnIP:      named,
	}
	packet := make([]byte, protocol.ControlFrameLength)
	if err := protocol.EncodeControlFrame(packet, frame); err != nil {
		return nil, err
	}
	return packet, nil
}

// egressSourceMatches reports whether a packet source and port fit an egress path:
// the server of a direct path, its return IP, or an address in its pool. The via
// of a bridge via path is on the leg to the bridge, so its source is the bridge.
func egressSourceMatches(path config.Path, source netip.Addr, transport protocol.TransportID, port uint16) bool {
	if path.Transport != transport || path.ServerPort != port {
		return false
	}
	switch {
	case path.BridgeVia:
		return path.Server == source
	case path.IsPool():
		return netip.PrefixFrom(path.ReturnIP, int(path.ReturnPrefix)).Contains(source)
	case path.ReturnIP.IsValid():
		return path.ReturnIP == source
	default:
		return path.Server == source
	}
}
