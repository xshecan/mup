package dataplane

// PathCounter counts the data packets of one path in one direction. Bytes is
// the sum of their IPv4 total lengths at the count point.
type PathCounter struct {
	Packets uint64
	Bytes   uint64
}

// The directions of a server path counter. An ingress counter holds the
// packets that the server received from a client on an ingress path. An
// egress counter holds the packets that the server sent to a client on an
// egress path.
const (
	PathCounterIngress uint8 = 0
	PathCounterEgress  uint8 = 1
)
