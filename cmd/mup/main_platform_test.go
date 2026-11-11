//go:build !linux

package main

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
)

func TestRunApplicationUsesPlatformRuntime(t *testing.T) {
	t.Parallel()

	err := runApplication(context.Background(), config.App{Server: &config.Server{
		Port:   5000,
		Target: netip.MustParseAddrPort("192.0.2.1:51820"),
	}})
	if !errors.Is(err, dataplane.ErrUnsupportedPlatform) {
		t.Fatalf("runApplication error = %v, want %v", err, dataplane.ErrUnsupportedPlatform)
	}
}
