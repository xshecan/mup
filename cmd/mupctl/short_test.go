package main

import (
	"strings"
	"testing"
)

func TestListCommandsWithoutGet(t *testing.T) {
	t.Parallel()

	daemon := fakeDaemon(t, clientStatus())
	for _, resource := range []string{"groups", "paths", "peers", "drops"} {
		_, short, shortErr := runCommand(t, daemon, resource)
		_, long, longErr := runCommand(t, daemon, "get", resource)
		if short != long || shortErr != longErr {
			t.Fatalf("mupctl %s printed %q and %q, but get %s printed %q and %q", resource, short, shortErr, resource, long, longErr)
		}
	}
	if code, stdout, stderr := runCommand(t, daemon, "path"); code != 0 || !strings.Contains(stdout, "SERVER") {
		t.Fatalf("mupctl path = %d, %q, %q", code, stdout, stderr)
	}
	for _, args := range [][]string{{"paths", "extra"}, {"reset"}, {"reset", "paths"}, {"reset", "drops", "-w"}} {
		if code, _, stderr := runCommand(t, daemon, args...); code != 2 || stderr == "" {
			t.Fatalf("mupctl %q = %d, %q, want a usage error", args, code, stderr)
		}
	}
	if _, err := parseCommand(options{args: []string{"paths"}, watch: true}); err != nil {
		t.Fatalf("paths with --watch: %v", err)
	}
}

func TestResetDrops(t *testing.T) {
	t.Parallel()

	code, stdout, stderr := runCommand(t, fakeDaemon(t, clientStatus()), "reset", "drops")
	if code != 0 || stdout != "drop counters reset\n" {
		t.Fatalf("reset drops = %d, %q, %q", code, stdout, stderr)
	}
}
