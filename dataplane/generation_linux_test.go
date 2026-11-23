//go:build linux

package dataplane

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPinGenerationStartsOverForANewBuild checks that a pin root marked by an
// old build, or not marked at all, loses its pins and gains this build's marker.
func TestPinGenerationStartsOverForANewBuild(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "generation-0123456789abcdef"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "stats"), []byte("state"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := reconcilePinGeneration(root); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "stats")); !os.IsNotExist(err) {
		t.Fatalf("a pin of the old build survived: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "generation-0123456789abcdef")); !os.IsNotExist(err) {
		t.Fatalf("the marker of the old build survived: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "generation-"+pinGeneration())); err != nil {
		t.Fatalf("the marker of this build is missing: %v", err)
	}
}

// TestPinGenerationKeepsThePinsOfTheSameBuild checks that a second start of the
// same build keeps the pins, so a restart does not disturb running tunnels.
func TestPinGenerationKeepsThePinsOfTheSameBuild(t *testing.T) {
	root := t.TempDir()
	if err := reconcilePinGeneration(root); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "stats"), []byte("state"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := reconcilePinGeneration(root); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "stats")); err != nil {
		t.Fatalf("a pin of the same build was removed: %v", err)
	}
}
