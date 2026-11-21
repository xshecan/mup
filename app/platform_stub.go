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

func serveServerControls(context.Context, config.Server, *control.Registry, registrationSink, *reflectorTargets, *downService) error {
	return dataplane.ErrUnsupportedPlatform
}

func openDownSender() (*rawDownSender, error) {
	return nil, dataplane.ErrUnsupportedPlatform
}

type rawDownSender struct{}

func (*rawDownSender) send(downTarget, []byte, uint16) error {
	return dataplane.ErrUnsupportedPlatform
}

func (*rawDownSender) Close() error {
	return nil
}

func locateDownInterface(netip.Addr, netip.Addr) (int, error) {
	return 0, dataplane.ErrUnsupportedPlatform
}

func monotonicNowNS() (uint64, error) {
	return 0, dataplane.ErrUnsupportedPlatform
}
