package app

import (
	"net/netip"
	"sync"
	"time"

	"github.com/xshecan/mup/protocol"
)

// reflectorTarget is one client that the server probes for one UDP return pool.
// The server sends a spoofed-source probe from each pool member to the client's
// control socket, and the client confirms the members it received.
type reflectorTarget struct {
	advertisedIP netip.Addr
	listenPort   uint16
	nonce        uint64
	pathID       uint16
	serverPort   uint16
	base         netip.Addr
	prefix       uint8
}

type reflectorTargetKey struct {
	advertisedIP netip.Addr
	nonce        uint64
	pathID       uint16
	base         netip.Addr
}

type reflectorTargetEntry struct {
	target  reflectorTarget
	expires time.Time
}

// reflectorTargets holds the live UDP pool clients to probe. A registration
// adds or refreshes a target, and the emitter reads the active targets. A
// target leaves when its lease ends.
type reflectorTargets struct {
	mu      sync.Mutex
	entries map[reflectorTargetKey]reflectorTargetEntry
}

func newReflectorTargets() *reflectorTargets {
	return &reflectorTargets{entries: make(map[reflectorTargetKey]reflectorTargetEntry)}
}

func (t *reflectorTargets) add(target reflectorTarget, expires time.Time) {
	key := reflectorTargetKey{
		advertisedIP: target.advertisedIP,
		nonce:        target.nonce,
		pathID:       target.pathID,
		base:         target.base,
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[key] = reflectorTargetEntry{target: target, expires: expires}
}

// active returns the targets whose lease has not ended, and forgets the rest.
func (t *reflectorTargets) active(now time.Time) []reflectorTarget {
	t.mu.Lock()
	defer t.mu.Unlock()
	targets := make([]reflectorTarget, 0, len(t.entries))
	for key, entry := range t.entries {
		if now.After(entry.expires) {
			delete(t.entries, key)
			continue
		}
		targets = append(targets, entry.target)
	}
	return targets
}

// confirms reports whether a probe reply answers a probe of an active target:
// the reply must name the client identity and path of the target, and the
// reflector must be in the pool of that path. The server ignores every other
// reply, so a stray frame cannot mark a reflector healthy.
func (t *reflectorTargets) confirms(frame protocol.ControlFrame, now time.Time) bool {
	if frame.Type != protocol.ControlProbeReply || frame.Transport != protocol.TransportUDP ||
		!frame.ReturnIP.Is4() {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, entry := range t.entries {
		target := entry.target
		if now.After(entry.expires) || target.advertisedIP != frame.AdvertisedIP ||
			target.nonce != frame.InstanceNonce || target.pathID != frame.PathID {
			continue
		}
		if netip.PrefixFrom(target.base, int(target.prefix)).Contains(frame.ReturnIP) {
			return true
		}
	}
	return false
}
