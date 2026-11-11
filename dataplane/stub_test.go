//go:build !linux

package dataplane

import (
	"errors"
	"testing"
)

func TestLoadRejectsUnsupportedPlatform(t *testing.T) {
	t.Parallel()

	runtime, err := Load(Config{})
	if runtime != nil {
		t.Fatalf("Load returned runtime %#v on unsupported platform", runtime)
	}
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("Load error = %v, want %v", err, ErrUnsupportedPlatform)
	}
}

func TestValidatePinRoot(t *testing.T) {
	t.Parallel()

	if err := validatePinRoot("/sys/fs/bpf/mup/client"); err != nil {
		t.Fatalf("validatePinRoot: %v", err)
	}
	for _, path := range []string{"", "relative/path"} {
		if err := validatePinRoot(path); err == nil {
			t.Fatalf("validatePinRoot(%q) unexpectedly succeeded", path)
		}
	}
}
