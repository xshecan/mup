package app

import (
	"sync"

	"github.com/xshecan/mup/dataplane"
)

type serverCounterKey struct {
	client    dataplane.ClientKey
	pathID    uint16
	direction uint8
}

// fakeServerCounters holds the path counters of a fake server dataplane. Its
// zero value is ready to use.
type fakeServerCounters struct {
	countersMu sync.Mutex
	counters   map[serverCounterKey]dataplane.PathCounter
	// counterLog records each create and delete as "ensure" or "delete".
	counterLog []string
}

func (f *fakeServerCounters) EnsureServerPathCounter(client dataplane.ClientKey, pathID uint16, direction uint8) error {
	f.countersMu.Lock()
	defer f.countersMu.Unlock()
	if f.counters == nil {
		f.counters = map[serverCounterKey]dataplane.PathCounter{}
	}
	key := serverCounterKey{client: client, pathID: pathID, direction: direction}
	if _, ok := f.counters[key]; !ok {
		f.counters[key] = dataplane.PathCounter{}
		f.counterLog = append(f.counterLog, "ensure")
	}
	return nil
}

func (f *fakeServerCounters) DeleteServerPathCounter(client dataplane.ClientKey, pathID uint16, direction uint8) error {
	f.countersMu.Lock()
	defer f.countersMu.Unlock()
	key := serverCounterKey{client: client, pathID: pathID, direction: direction}
	if _, ok := f.counters[key]; ok {
		delete(f.counters, key)
		f.counterLog = append(f.counterLog, "delete")
	}
	return nil
}

func (f *fakeServerCounters) ServerPathCounter(client dataplane.ClientKey, pathID uint16, direction uint8) (dataplane.PathCounter, bool, error) {
	f.countersMu.Lock()
	defer f.countersMu.Unlock()
	counter, ok := f.counters[serverCounterKey{client: client, pathID: pathID, direction: direction}]
	return counter, ok, nil
}

// setCounter sets the packets of an existing counter, as the BPF program
// counts them.
func (f *fakeServerCounters) setCounter(client dataplane.ClientKey, pathID uint16, direction uint8, packets uint64) bool {
	f.countersMu.Lock()
	defer f.countersMu.Unlock()
	key := serverCounterKey{client: client, pathID: pathID, direction: direction}
	if _, ok := f.counters[key]; !ok {
		return false
	}
	f.counters[key] = dataplane.PathCounter{Packets: packets, Bytes: packets * 100}
	return true
}

func (f *fakeServerCounters) hasCounter(client dataplane.ClientKey, pathID uint16, direction uint8) bool {
	f.countersMu.Lock()
	defer f.countersMu.Unlock()
	_, ok := f.counters[serverCounterKey{client: client, pathID: pathID, direction: direction}]
	return ok
}
