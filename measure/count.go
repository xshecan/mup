// Package measure turns counts and probe answers into loss, latency and
// rate numbers. It holds no locks and starts no goroutines, so a caller
// guards each value with its own lock.
package measure

import "time"

// Windows and timeouts used by the trackers.
const (
	ShortWindow  = 10 * time.Second
	LongWindow   = 60 * time.Second
	ProbeTimeout = 2 * time.Second
	ProbeWindow  = 60 * time.Second
	RateWindow   = 10 * time.Second
)

// countModulus is the modulus of all count arithmetic.
const countModulus = 0xFFFFFFFF

// EncodeCount turns a packet total into a wire code. Code 0 is never produced.
func EncodeCount(packets uint64) uint32 {
	return uint32(packets%countModulus) + 1
}

// DecodeCount turns a wire code into a count. Code 0 means no count.
func DecodeCount(code uint32) (count uint32, ok bool) {
	if code == 0 {
		return 0, false
	}
	return code - 1, true
}

// CountDelta returns (newer - older) modulo 0xFFFFFFFF for decoded counts.
func CountDelta(newer, older uint32) uint32 {
	d := uint64(newer) + countModulus - uint64(older)
	return uint32(d % countModulus)
}
