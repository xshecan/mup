//go:build !linux

package app

import (
	"context"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/control"
	"github.com/xshecan/mup/dataplane"
)

// These functions keep the Fx graph the same on every platform. Run stops
// before it builds the graph on other platforms, so nothing calls them.

func newClientPathOpener() pathOpener {
	return func(pathRegistration) (pathConn, error) {
		return nil, dataplane.ErrUnsupportedPlatform
	}
}

func serveServerControls(context.Context, config.Server, *control.Registry, registrationSink) error {
	return dataplane.ErrUnsupportedPlatform
}

func monotonicNowNS() (uint64, error) {
	return 0, dataplane.ErrUnsupportedPlatform
}
