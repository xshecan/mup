package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/xshecan/mup/api"
)

// TestPrivilegedSplitPaths runs a group with one UDP up path and two down
// paths: an ICMP path that reflects through 10.210.1.3, and a direct UDP path.
// The downstream moves to the second down path when the reflector fails,
// while the up path stays healthy, and a downstream burst reaches each peer
// once.
func TestPrivilegedSplitPaths(t *testing.T) {
	requirePrivilegedLinux(t)
	binaryPath := buildDaemon(t)

	suffix := strconv.FormatInt(time.Now().UnixNano()%1_000_000, 10)
	clientNS, serverNS, targetNS := "mup-client-"+suffix, "mup-server-"+suffix, "mup-target-"+suffix
	reflectorNS, switchNS, peerNS := "mup-reflector-"+suffix, "mup-switch-"+suffix, "mup-peer-"+suffix
	for _, namespace := range []string{clientNS, serverNS, targetNS, reflectorNS, switchNS, peerNS} {
		addNamespace(t, namespace)
	}
	runIP(t, "-n", switchNS, "link", "add", "br0", "type", "bridge")
	runIP(t, "-n", switchNS, "link", "set", "br0", "up")
	for _, member := range []struct{ link, namespace string }{
		{"mc" + suffix, clientNS}, {"ms" + suffix, serverNS}, {"mr" + suffix, reflectorNS},
	} {
		port := "b" + member.link
		linkPair(t, member.link, member.namespace, port, switchNS)
		runIP(t, "-n", switchNS, "link", "set", port, "master", "br0", "up")
	}
	addressLink(t, clientNS, "mc"+suffix, "10.210.1.1/24")
	addressLink(t, serverNS, "ms"+suffix, "10.210.1.2/24")
	addressLink(t, reflectorNS, "mr"+suffix, "10.210.1.3/24")
	linkPair(t, "st"+suffix, serverNS, "ts"+suffix, targetNS)
	addressLink(t, serverNS, "st"+suffix, "10.210.2.1/24")
	addressLink(t, targetNS, "ts"+suffix, "10.210.2.2/24")
	linkPair(t, "cp"+suffix, clientNS, "pc"+suffix, peerNS)
	addressLink(t, clientNS, "cp"+suffix, "10.210.3.1/24")
	addressLink(t, peerNS, "pc"+suffix, "10.210.3.2/24")

	target := startEchoTarget(t, targetNS, "10.210.2.2:51820")
	defer target.stop(t)

	directory := t.TempDir()
	serverSocket := filepath.Join(directory, "server.sock")
	clientSocket := filepath.Join(directory, "client.sock")
	server := startNamespaced(t, serverNS, binaryPath, "server", "-p", "5000-5099", "-r", "10.210.2.2:51820", "--control-socket", serverSocket)
	defer server.stop(t)

	configuration := filepath.Join(directory, "client.yaml")
	content := fmt.Sprintf(`client:
  advertise: 10.210.1.1
  control_socket: %s
  servers:
    - port: 51820
      upstream:
        routes: [10.210.1.2:5000/udp]
      downstream:
        mode: fallback
        routes:
          - "10.210.1.2:5010/icmp via 10.210.1.3"
          - 10.210.1.2:5020/udp
`, clientSocket)
	if err := os.WriteFile(configuration, []byte(content), 0o600); err != nil {
		t.Fatalf("write client configuration: %v", err)
	}
	client := startNamespaced(t, clientNS, binaryPath, "--config", configuration)
	defer client.stop(t)

	clientAPI := api.NewDaemonClient(clientSocket)
	serverAPI := api.NewDaemonClient(serverSocket)
	logs := func() string {
		return fmt.Sprintf("client log:\n%s\nserver log:\n%s\ntarget log:\n%s", client.log(t), server.log(t), target.log(t))
	}
	state := func() string {
		return fmt.Sprintf("%s\nclient %s\nserver %s\n%s", pathText(t, clientAPI), dropText(t, clientAPI), dropText(t, serverAPI), logs())
	}
	// downHealth reads the health of each down path on the server and on the
	// client, and whether the client uses it.
	type downView struct{ server, client, inUse [2]bool }
	view := func() (downView, error) {
		var current downView
		clients, err := serverAPI.Clients(context.Background())
		if err != nil {
			return current, err
		}
		for _, registered := range clients {
			if registered.Down == nil {
				continue
			}
			for _, path := range registered.Down.Paths {
				if path.ID < 2 {
					current.server[path.ID] = path.Healthy
				}
			}
		}
		paths, err := clientAPI.Paths(context.Background())
		if err != nil {
			return current, err
		}
		for _, path := range paths {
			if path.Direction == "down" && path.ID < 2 {
				current.client[path.ID] = path.Healthy
				current.inUse[path.ID] = path.InUse
			}
		}
		return current, nil
	}
	waitForDown := func(description string, want [2]bool) {
		t.Helper()
		waitFor(t, 30*time.Second, description, state, func() (bool, error) {
			current, err := view()
			return err == nil && current.server == want && current.client == want, err
		})
	}

	waitForRegisteredPaths(t, serverAPI, 1, logs)
	waitForDown("both down paths to become healthy", [2]bool{true, true})
	exchange(t, peerNS, "10.210.3.1:51820", 3, state)
	if current, _ := view(); current.inUse != [2]bool{true, false} {
		t.Fatalf("fallback uses down paths %v, want only the reflected path\n%s", current.inUse, state())
	}

	// Without the reflector, the downstream moves to the direct path, and the
	// up path stays healthy, because the server sends each ACK on the direct
	// down path too.
	runIP(t, "-n", reflectorNS, "link", "set", "mr"+suffix, "down")
	waitForDown("the reflected down path to become unhealthy", [2]bool{false, true})
	exchange(t, peerNS, "10.210.3.1:51820", 3, state)
	paths, err := clientAPI.Paths(context.Background())
	if err != nil {
		t.Fatalf("client paths: %v", err)
	}
	for _, path := range paths {
		if path.Direction == "up" && !path.Healthy {
			t.Fatalf("up path %d became unhealthy with a down path\n%s", path.ID, state())
		}
		if path.Direction == "down" && path.ID == 1 && !path.InUse {
			t.Fatalf("the direct down path carries no replies\n%s", state())
		}
	}

	// A downstream burst sends each reply on both down paths, and the client
	// passes one copy to the peer.
	runIP(t, "-n", reflectorNS, "link", "set", "mr"+suffix, "up")
	waitForDown("the reflected down path to come back", [2]bool{true, true})
	if err := clientAPI.SetDownMode(context.Background(), "burst", 0); err != nil {
		t.Fatalf("set down mode: %v", err)
	}
	waitFor(t, 20*time.Second, "the server to take the burst mode", state, func() (bool, error) {
		clients, err := serverAPI.Clients(context.Background())
		if err != nil {
			return false, err
		}
		for _, registered := range clients {
			if registered.Down != nil && registered.Down.Mode == "burst" {
				return true, nil
			}
		}
		return false, nil
	})
	exchange(t, peerNS, "10.210.3.1:51820", 3, state)
	waitFor(t, 5*time.Second, "the client to drop the second copies", state, func() (bool, error) {
		status, err := clientAPI.Status(context.Background())
		return err == nil && dropCount(status.Drops, "DUPLICATE") >= 3, err
	})
	status, err := clientAPI.Status(context.Background())
	if err != nil {
		t.Fatalf("client status: %v", err)
	}
	if refused := dropCount(status.Drops, "DOWNSTREAM_SOURCE"); refused != 0 {
		t.Fatalf("client refused %d downstream packets\n%s", refused, state())
	}
}
