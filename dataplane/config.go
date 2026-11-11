package dataplane

import (
	"errors"
	"fmt"
	"path/filepath"
)

var ErrUnsupportedPlatform = errors.New("MUP TCX dataplane requires Linux 6.6 or newer")

type Config struct {
	PinRoot string
}

func validatePinRoot(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("BPF pin root must be absolute")
	}
	return nil
}
