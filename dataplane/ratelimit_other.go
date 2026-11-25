//go:build !linux

package dataplane

// Only the Linux build has a BPF program, so the fields of the limits stay
// zero elsewhere.

func setPathLimitFields(*mupPathConfigV1, PathSettings) {}

func setEgressPathLimitFields(*mupDownPathV1, RateLimit) {}

func setEgressGroupShares(*mupDownGroupV1, EgressGroupEntry) {}
