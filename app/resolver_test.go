package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHasEthernetHeader(t *testing.T) {
	root := t.TempDir()
	links := map[string]string{
		"eth0":   "1\n",
		"lo":     "772\n",
		"tun0":   "65534\n",
		"wwan0":  "519\n",
		"broken": "not a number\n",
	}
	for name, linkType := range links {
		if err := os.Mkdir(filepath.Join(root, name), 0o755); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(root, name, "type"), []byte(linkType), 0o644); err != nil {
			t.Fatalf("write %s type: %v", name, err)
		}
	}
	previous := sysfsNetRoot
	sysfsNetRoot = root
	t.Cleanup(func() { sysfsNetRoot = previous })

	for _, test := range []struct {
		name string
		want bool
	}{
		{name: "eth0", want: true},
		{name: "lo", want: true},
		{name: "tun0", want: false},
		{name: "wwan0", want: false},
		{name: "missing", want: true},
		{name: "broken", want: true},
	} {
		if got := hasEthernetHeader(test.name); got != test.want {
			t.Errorf("hasEthernetHeader(%q) = %v, want %v", test.name, got, test.want)
		}
	}
	if err := checkEthernetHeader("wwan0"); err == nil ||
		err.Error() != "interface wwan0 has no Ethernet header, and MUP does not support it" {
		t.Errorf("checkEthernetHeader(wwan0) error = %v", err)
	}
	if err := checkEthernetHeader("eth0"); err != nil {
		t.Errorf("checkEthernetHeader(eth0) error = %v", err)
	}
}
