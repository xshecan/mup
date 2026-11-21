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
// each up path, receives the frames that arrive on down paths, and sends a
// frame on an up path.
type clientControls interface {
	open(pathRegistration) (pathConn, error)
	// listenDown starts to receive the frames on the down paths of the
	// groups with these listen ports. It passes each down path probe to
	// handle, and each REGISTER_ACK to the up path that waits for it. The
	// returned function stops it.
	listenDown(listen downListen, handle func(downProbe)) (func(), error)
	// sendUp sends one control frame on an up path.
	sendUp(registration pathRegistration, frame []byte) error
}

// downListen names what a client receives on its down paths.
type downListen struct {
	advertisedIP netip.Addr
	nonce        uint64
	listenPorts  []uint16
}

// downProbe is a PROBE that arrived on a down path. Source is the packet
// source, and Port is the UDP source port or the ICMP identifier.
type downProbe struct {
	frame     protocol.ControlFrame
	source    netip.Addr
	transport protocol.TransportID
	port      uint16
	received  time.Time
}

// open lets a pathOpener act as the controls of a client without down paths.
func (o pathOpener) open(registration pathRegistration) (pathConn, error) {
	return o(registration)
}

func (pathOpener) listenDown(downListen, func(downProbe)) (func(), error) {
	return func() {}, nil
}

func (pathOpener) sendUp(pathRegistration, []byte) error {
	return nil
}

// ackRouter passes each REGISTER_ACK of a group with down paths to the up path
// that waits for it. The ACK can arrive on any down path, so on any socket.
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

// downSet holds the down paths of a group with separate down paths. Each up
// path of the group sends a DOWN_REGISTER for each of them with every
// REGISTER, so each server that an up path reaches learns them all. A removed
// down path stays in the frames with a lease of zero for one lease, so the
// servers forget it at once.
type downSet struct {
	mu        sync.Mutex
	mode      config.Mode
	paths     map[uint16]config.Path
	withdrawn map[uint16]downWithdrawal
}

type downWithdrawal struct {
	path  config.Path
	until time.Time
}

func newDownSet(mode config.Mode) *downSet {
	return &downSet{mode: mode, paths: make(map[uint16]config.Path), withdrawn: make(map[uint16]downWithdrawal)}
}

func (d *downSet) set(slot uint16, path config.Path) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.paths[slot] = path
	delete(d.withdrawn, slot)
}

func (d *downSet) remove(slot uint16, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if path, ok := d.paths[slot]; ok {
		d.withdrawn[slot] = downWithdrawal{path: path, until: now.Add(registrationLeaseSeconds * time.Second)}
	}
	delete(d.paths, slot)
}

func (d *downSet) setMode(mode config.Mode) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.mode = mode
}

// frames builds the DOWN_REGISTER frames that an up path sends before its
// REGISTER with this sequence.
func (d *downSet) frames(registration pathRegistration, sequence uint32, now time.Time) [][]byte {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	frames := make([][]byte, 0, len(d.paths)+len(d.withdrawn))
	for slot, path := range d.paths {
		if frame, err := downRegisterFrame(registration, slot, path, d.mode, sequence, registrationLeaseSeconds); err == nil {
			frames = append(frames, frame)
		}
	}
	for slot, withdrawal := range d.withdrawn {
		if now.After(withdrawal.until) {
			delete(d.withdrawn, slot)
			continue
		}
		if frame, err := downRegisterFrame(registration, slot, withdrawal.path, d.mode, sequence, 0); err == nil {
			frames = append(frames, frame)
		}
	}
	return frames
}

func downRegisterFrame(registration pathRegistration, slot uint16, path config.Path, mode config.Mode, sequence, lease uint32) ([]byte, error) {
	frame := protocol.ControlFrame{
		Type:          protocol.ControlDownRegister,
		Transport:     path.Transport,
		PathID:        slot,
		Sequence:      sequence,
		ListenPort:    registration.listenPort,
		ServerPort:    path.ServerPort,
		LeaseSeconds:  lease,
		InstanceNonce: registration.nonce,
		AdvertisedIP:  registration.advertisedIP,
		DownMode:      uint8(mode),
		DownServer:    path.Server,
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
	packet := make([]byte, protocol.ControlFrameLength)
	if err := protocol.EncodeControlFrame(packet, frame); err != nil {
		return nil, err
	}
	return packet, nil
}

// downProbeReplyFrame answers a probe of a down path. It names the source that
// the probe came from, which is the reflector of a reflected path.
func downProbeReplyFrame(registration pathRegistration, probe downProbe, path config.Path) ([]byte, error) {
	frame := protocol.ControlFrame{
		Type:          protocol.ControlProbeReply,
		Transport:     path.Transport,
		Flags:         protocol.ControlFlagDownPath | protocol.ControlFlagReturnIP,
		PathID:        probe.frame.PathID,
		Sequence:      probe.frame.Sequence,
		ListenPort:    registration.listenPort,
		ServerPort:    path.ServerPort,
		InstanceNonce: registration.nonce,
		AdvertisedIP:  registration.advertisedIP,
		ReturnIP:      probe.source,
	}
	packet := make([]byte, protocol.ControlFrameLength)
	if err := protocol.EncodeControlFrame(packet, frame); err != nil {
		return nil, err
	}
	return packet, nil
}

// downSourceMatches reports whether a packet source and port fit a down path:
// the server of a direct path, its return IP, or an address in its pool.
func downSourceMatches(path config.Path, source netip.Addr, transport protocol.TransportID, port uint16) bool {
	if path.Transport != transport || path.ServerPort != port {
		return false
	}
	switch {
	case path.IsPool():
		return netip.PrefixFrom(path.ReturnIP, int(path.ReturnPrefix)).Contains(source)
	case path.ReturnIP.IsValid():
		return path.ReturnIP == source
	default:
		return path.Server == source
	}
}
