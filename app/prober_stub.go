//go:build !linux

package app

import (
	"context"
	"log"

	"github.com/xshecan/mup/dataplane"
)

// newReflectorProbeLoop returns a loop that does nothing off Linux, where the
// server does not run.
func newReflectorProbeLoop(_ *dataplane.Runtime, _ *log.Logger) loop {
	return func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
}

// newReflectorEmitLoop returns a loop that does nothing off Linux.
func newReflectorEmitLoop(_ *dataplane.Runtime, _ *reflectorTargets, _ *log.Logger) loop {
	return func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
}
