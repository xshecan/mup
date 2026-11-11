package control

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrHealthPath    = errors.New("health path index out of range")
	ErrProbeSequence = errors.New("probe reply does not match pending sequence")
)

type HealthTransition struct {
	Path       int
	Healthy    bool
	Changed    bool
	Generation uint32
}

// PathHealth describes one path for status output.
type PathHealth struct {
	Healthy   bool
	Misses    int
	LastReply time.Time
	RTT       time.Duration
}

type probeState struct {
	healthy   bool
	misses    int
	pending   bool
	sequence  uint32
	sentAt    time.Time
	lastReply time.Time
	rtt       time.Duration
}

type HealthEngine struct {
	mu         sync.Mutex
	paths      []probeState
	deadline   time.Duration
	missLimit  int
	generation uint32
}

func NewHealthEngine(pathCount int, deadline time.Duration, missLimit int) *HealthEngine {
	return &HealthEngine{
		paths:     make([]probeState, pathCount),
		deadline:  deadline,
		missLimit: missLimit,
	}
}

// StartHealthy starts to track a path from the command line as healthy.
func (e *HealthEngine) StartHealthy(path int) (HealthTransition, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	state, err := e.stateOf(path)
	if err != nil {
		return HealthTransition{}, err
	}
	changed := !state.healthy
	state.healthy = true
	state.misses = 0
	if changed {
		e.generation++
	}
	return HealthTransition{Path: path, Healthy: true, Changed: changed, Generation: e.generation}, nil
}

// StartUnhealthy starts to track a path that joined at run time. The path stays
// unhealthy until its first reply.
func (e *HealthEngine) StartUnhealthy(path int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	state, err := e.stateOf(path)
	if err != nil {
		return err
	}
	*state = probeState{}
	return nil
}

// Forget stops tracking a path and forgets its state.
func (e *HealthEngine) Forget(path int) (HealthTransition, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	state, err := e.stateOf(path)
	if err != nil {
		return HealthTransition{}, err
	}
	changed := state.healthy
	*state = probeState{}
	if changed {
		e.generation++
	}
	return HealthTransition{Path: path, Healthy: false, Changed: changed, Generation: e.generation}, nil
}

// Path returns the current health of one path.
func (e *HealthEngine) Path(path int) (PathHealth, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	state, err := e.stateOf(path)
	if err != nil {
		return PathHealth{}, err
	}
	return PathHealth{Healthy: state.healthy, Misses: state.misses, LastReply: state.lastReply, RTT: state.rtt}, nil
}

func (e *HealthEngine) Sent(path int, sequence uint32, now time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	state, err := e.stateOf(path)
	if err != nil {
		return err
	}
	state.pending = true
	state.sequence = sequence
	state.sentAt = now
	return nil
}

func (e *HealthEngine) Reply(path int, sequence uint32, now time.Time) (HealthTransition, time.Duration, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	state, err := e.stateOf(path)
	if err != nil {
		return HealthTransition{}, 0, err
	}
	if !state.pending || state.sequence != sequence {
		return HealthTransition{}, 0, ErrProbeSequence
	}
	rtt := now.Sub(state.sentAt)
	if rtt < 0 {
		return HealthTransition{}, 0, fmt.Errorf("probe reply precedes send time")
	}
	state.pending = false
	state.misses = 0
	state.lastReply = now
	state.rtt = rtt
	changed := !state.healthy
	state.healthy = true
	if changed {
		e.generation++
	}
	return HealthTransition{Path: path, Healthy: true, Changed: changed, Generation: e.generation}, rtt, nil
}

// ExpireProbes counts a miss for each pending probe past its deadline, and
// returns the paths that became unhealthy.
func (e *HealthEngine) ExpireProbes(now time.Time) []HealthTransition {
	e.mu.Lock()
	defer e.mu.Unlock()
	var transitions []HealthTransition
	for path := range e.paths {
		state := &e.paths[path]
		if !state.pending || now.Before(state.sentAt.Add(e.deadline)) {
			continue
		}
		state.pending = false
		state.misses++
		if state.healthy && state.misses >= e.missLimit {
			state.healthy = false
			e.generation++
			transitions = append(transitions, HealthTransition{
				Path:       path,
				Healthy:    false,
				Changed:    true,
				Generation: e.generation,
			})
		}
	}
	return transitions
}

func (e *HealthEngine) Snapshot() (uint8, uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var mask uint8
	for path := range e.paths {
		if e.paths[path].healthy {
			mask |= 1 << path
		}
	}
	return mask, e.generation
}

func (e *HealthEngine) stateOf(path int) (*probeState, error) {
	if path < 0 || path >= len(e.paths) {
		return nil, fmt.Errorf("%w: %d", ErrHealthPath, path)
	}
	return &e.paths[path], nil
}
