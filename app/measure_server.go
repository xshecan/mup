package app

import (
	"net/netip"
	"sync"
	"time"

	"github.com/xshecan/mup/api"
	"github.com/xshecan/mup/control"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/measure"
	"github.com/xshecan/mup/protocol"
)

// pathCounterStore is the part of the server dataplane that counts the data
// packets of each path of each client.
type pathCounterStore interface {
	EnsureServerPathCounter(client dataplane.ClientKey, pathID uint16, direction uint8) error
	DeleteServerPathCounter(client dataplane.ClientKey, pathID uint16, direction uint8) error
	ServerPathCounter(client dataplane.ClientKey, pathID uint16, direction uint8) (dataplane.PathCounter, bool, error)
}

// egressRoundKeep is how long the server keeps the count of a probe round. A
// reply that comes later gives no loss marker.
const egressRoundKeep = 10 * time.Second

// egressRound is one probe round of an egress path. All probes of the round
// carry the same count, and the first reply of the round gives the marker.
type egressRound struct {
	tx     uint32
	sent   time.Time
	marked bool
}

// egressMeasure measures one egress path of a client on the server.
type egressMeasure struct {
	loss    measure.Loss
	rate    measure.Rate
	probes  measure.Probes
	members map[netip.Addr]*measure.Probes
	rounds  map[uint32]*egressRound
}

func newEgressMeasure() *egressMeasure {
	return &egressMeasure{members: make(map[netip.Addr]*measure.Probes), rounds: make(map[uint32]*egressRound)}
}

// startRound begins a probe round with the egress counter of the path, read
// just before the probes leave. It forgets the old rounds and the members
// that are no longer candidates.
func (m *egressMeasure) startRound(counter dataplane.PathCounter, counted bool, candidates []netip.Addr, now time.Time) *egressRound {
	round := &egressRound{sent: now}
	if counted {
		round.tx = measure.EncodeCount(counter.Packets)
		m.rate.Sample(counter.Packets, counter.Bytes, now)
	}
	for sequence, old := range m.rounds {
		if now.Sub(old.sent) > egressRoundKeep {
			delete(m.rounds, sequence)
		}
	}
	for member := range m.members {
		if !containsAddr(candidates, member) {
			delete(m.members, member)
		}
	}
	return round
}

// sent records one probe of a round through member.
func (m *egressMeasure) sent(round *egressRound, sequence uint32, member netip.Addr, now time.Time) {
	m.rounds[sequence] = round
	m.probes.Sent(sequence, now)
	tracker := m.members[member]
	if tracker == nil {
		tracker = &measure.Probes{}
		m.members[member] = tracker
	}
	tracker.Sent(sequence, now)
}

// answered records a PROBE_REPLY that names member. The first reply of a
// round that carries a count gives a loss marker: the count in the probe and
// the count of the client when the probe arrived belong to the same frame.
func (m *egressMeasure) answered(sequence uint32, member netip.Addr, rxCode uint32, now time.Time) {
	if tracker := m.members[member]; tracker != nil {
		tracker.Answered(sequence, now)
	}
	m.probes.Answered(sequence, now)
	round := m.rounds[sequence]
	if round == nil || round.marked {
		return
	}
	tx, txOK := measure.DecodeCount(round.tx)
	rx, rxOK := measure.DecodeCount(rxCode)
	if !txOK || !rxOK {
		return
	}
	round.marked = true
	m.loss.Mark(tx, rx, now)
}

// view is the measurement of the path: the loss of its data, its probes over
// all members, and its rate.
func (m *egressMeasure) view(now time.Time) api.Measurement {
	view := probesMeasurement(&m.probes, now)
	view.LossPercent, view.LossLongPercent = lossMeasurement(&m.loss, now)
	view.RatePacketsPerSecond, view.RateBitsPerSecond = m.rate.Rate(now)
	return view
}

// memberView is the measurement of the probes through one member.
func (m *egressMeasure) memberView(member netip.Addr, now time.Time) api.Measurement {
	if tracker := m.members[member]; tracker != nil {
		return probesMeasurement(tracker, now)
	}
	return api.Measurement{}
}

// probesMeasurement fills the probe loss and the RTT of a probe tracker.
func probesMeasurement(probes *measure.Probes, now time.Time) api.Measurement {
	var view api.Measurement
	if loss, ok := probes.LossPercent(now); ok {
		view.ProbeLossPercent = &loss
	}
	if rtt, ok := probes.RTTAvg(now); ok {
		view.RTTAvgSeconds = rtt.Seconds()
	}
	if jitter, ok := probes.RTTJitter(now); ok {
		view.RTTJitterSeconds = jitter.Seconds()
	}
	return view
}

// lossMeasurement returns the data loss of the short and the long window, or
// nil where it is unknown.
func lossMeasurement(loss *measure.Loss, now time.Time) (short, long *float64) {
	if value, ok := loss.Percent(measure.ShortWindow, now); ok {
		short = &value
	}
	if value, ok := loss.Percent(measure.LongWindow, now); ok {
		long = &value
	}
	return short, long
}

func containsAddr(addresses []netip.Addr, address netip.Addr) bool {
	for _, current := range addresses {
		if current == address {
			return true
		}
	}
	return false
}

// acceptMeasure answers a MEASURE on a registered ingress path. It checks the
// frame like a REGISTER, and it registers and refreshes nothing. The reply is
// a copy of the frame with the count of the data packets that the server
// received on the path, or zero when the path has no counter.
func acceptMeasure(
	frame protocol.ControlFrame,
	transport protocol.TransportID,
	serverPort uint16,
	source, local netip.Addr,
	registry *control.Registry,
	counters pathCounterStore,
	now time.Time,
) ([]byte, error) {
	key, err := registry.Measure(now, control.RegistrationRequest{
		Frame: frame,
		Path:  control.PathKey{Local: local, Source: source, Transport: transport, ServerPort: serverPort},
	})
	if err != nil {
		return nil, err
	}
	reply := frame
	reply.Type = protocol.ControlMeasureReply
	reply.PeerCount = 0
	client := dataplane.ClientKey{AdvertisedIP: key.AdvertisedIP, InstanceNonce: key.InstanceNonce}
	if counter, ok, err := counters.ServerPathCounter(client, frame.PathID, dataplane.PathCounterIngress); err == nil && ok {
		reply.PeerCount = measure.EncodeCount(counter.Packets)
	}
	packet := make([]byte, protocol.ControlFrameLength)
	if err := protocol.EncodeControlFrame(packet, reply); err != nil {
		return nil, err
	}
	return packet, nil
}

type ingressCounterKey struct {
	client dataplane.ClientKey
	pathID uint16
}

// ingressCounters keeps one ingress counter for each live path ID of each
// client. All the paths of a client with one path ID, such as the members of
// an ingress reflect pool, share the counter.
type ingressCounters struct {
	mu       sync.Mutex
	counters pathCounterStore
	live     map[ingressCounterKey]bool
}

func newIngressCounters(counters pathCounterStore) *ingressCounters {
	return &ingressCounters{counters: counters, live: make(map[ingressCounterKey]bool)}
}

// ensure creates the counter of a registered path. The dataplane keeps a
// counter that exists, so a refresh does not reset it.
func (c *ingressCounters) ensure(client dataplane.ClientKey, pathID uint16) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.counters.EnsureServerPathCounter(client, pathID, dataplane.PathCounterIngress); err == nil {
		c.live[ingressCounterKey{client: client, pathID: pathID}] = true
	}
}

// prune deletes the counters of the path IDs that have no live path left in
// the registry. It reads the registry under its lock, so a path that ensure
// adds at the same time is either in the registry or not yet in the set.
func (c *ingressCounters) prune(registry *control.Registry, now time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	live := registry.PathIDs(now)
	for key := range c.live {
		mask := live[control.ClientKey{AdvertisedIP: key.client.AdvertisedIP, InstanceNonce: key.client.InstanceNonce}]
		if key.pathID <= protocol.MaxPathID && mask&(1<<key.pathID) != 0 {
			continue
		}
		if err := c.counters.DeleteServerPathCounter(key.client, key.pathID, dataplane.PathCounterIngress); err == nil {
			delete(c.live, key)
		}
	}
}
