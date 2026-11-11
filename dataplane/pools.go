package dataplane

import "github.com/xshecan/mup/protocol"

const (
	peerTokenPoolSize  = int(protocol.MaxPeerToken)
	firstTargetPort    = 20000
	lastTargetPort     = 60999
	targetPortPoolSize = lastTargetPort - firstTargetPort + 1
)

func peerTokenPool() []uint32 {
	pool := make([]uint32, peerTokenPoolSize)
	for index := range pool {
		pool[index] = uint32(index + 1)
	}
	return pool
}

func targetPortPool() []uint16 {
	pool := make([]uint16, targetPortPoolSize)
	for index := range pool {
		pool[index] = uint16(firstTargetPort + index)
	}
	return pool
}
