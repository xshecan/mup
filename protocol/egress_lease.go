package protocol

// The lease field of a EGRESS_REGISTER, at offset 40, also carries the
// settings of the egress group. Bits 0 to 7 hold the lease in seconds, bit 8
// asks for the egress path with the lowest round trip time, and bits 16 to 31
// hold the loss limit in tenths of a percent. A field of zero withdraws the
// path. A server before v0.5.4 tests the field only against zero, so it keeps
// the path and ignores the settings.
const (
	egressLeaseSecondsMask = 0xff
	egressLeasePrefer      = 1 << 8
	egressLeaseLossShift   = 16
	// MaxEgressLossTenths is the largest loss limit of a EGRESS_REGISTER, 100
	// percent in tenths.
	MaxEgressLossTenths = 1000
)

// EgressSettings are the settings of an egress group that a EGRESS_REGISTER
// carries. The zero value means no loss limit and the order of the paths.
type EgressSettings struct {
	// MaxLossTenths is the loss limit in tenths of a percent, or zero for
	// none.
	MaxLossTenths uint16
	// PreferLatency picks the egress path with the lowest round trip time in
	// the failover mode.
	PreferLatency bool
}

// PackEgressLease builds the lease field of a EGRESS_REGISTER. A lease of zero
// gives a field of zero, which withdraws the path, so it carries no settings.
// A loss limit above MaxEgressLossTenths counts as none.
func PackEgressLease(seconds uint8, settings EgressSettings) uint32 {
	if seconds == 0 {
		return 0
	}
	field := uint32(seconds)
	if settings.PreferLatency {
		field |= egressLeasePrefer
	}
	if settings.MaxLossTenths <= MaxEgressLossTenths {
		field |= uint32(settings.MaxLossTenths) << egressLeaseLossShift
	}
	return field
}

// UnpackEgressLease reads the lease field of a EGRESS_REGISTER. A loss limit
// above MaxEgressLossTenths counts as none.
func UnpackEgressLease(field uint32) (seconds uint8, settings EgressSettings) {
	seconds = uint8(field & egressLeaseSecondsMask)
	settings.PreferLatency = field&egressLeasePrefer != 0
	if tenths := uint16(field >> egressLeaseLossShift); tenths <= MaxEgressLossTenths {
		settings.MaxLossTenths = tenths
	}
	return seconds, settings
}
