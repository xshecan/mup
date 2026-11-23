//go:build !linux

package app

import (
	"context"
	"net/netip"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/control"
	"github.com/xshecan/mup/dataplane"
)

// These functions keep the Fx graph the same on every platform. Run stops
// before it builds the graph on other platforms, so nothing calls them.

func newClientPathOpener() clientControls {
	return pathOpener(func(pathRegistration) (pathConn, error) {
		return nil, dataplane.ErrUnsupportedPlatform
	})
}

func serveServerControls(context.Context, config.Server, *control.Registry, registrationSink, *reflectorTargets, *egressService) error {
	return dataplane.ErrUnsupportedPlatform
}

func openEgressSender() (*rawEgressSender, error) {
	return nil, dataplane.ErrUnsupportedPlatform
}

type rawEgressSender struct{}

func (*rawEgressSender) send(egressTarget, []byte, uint16) error {
	return dataplane.ErrUnsupportedPlatform
}

func (*rawEgressSender) Close() error {
	return nil
}

func locateEgressInterface(netip.Addr, netip.Addr) (int, error) {
	return 0, dataplane.ErrUnsupportedPlatform
}

func monotonicNowNS() (uint64, error) {
	return 0, dataplane.ErrUnsupportedPlatform
}
