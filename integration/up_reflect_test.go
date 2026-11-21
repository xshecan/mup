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

// TestPrivilegedUpReflect runs a group whose up path reflects the upstream
// through a reflector at 10.210.1.3. The client sends each REGISTER and each
// upstream packet to the reflector with the server as the source, so the
// reflector answers the server. The up path is healthy while the reflector
// reflects, and the upstream stops when the reflector fails.
func TestPrivilegedUpReflect(t *testing.T) {
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
        routes:
          - "10.210.1.2:5000/icmp via 10.210.1.3"
      downstream:
        routes:
          - 10.210.1.2:5010/udp
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
	upHealthy := func() (bool, error) {
		paths, err := clientAPI.Paths(context.Background())
		if err != nil {
			return false, err
		}
		for _, path := range paths {
			if path.Direction == "up" {
				return path.Healthy, nil
			}
		}
		return false, nil
	}

	// The reflector registers the up path, so the server sees one registered
	// path from the reflector source, and the up path becomes healthy.
	waitForRegisteredPaths(t, serverAPI, 1, logs)
	waitFor(t, 30*time.Second, "the up reflect path to become healthy", state, upHealthy)
	exchange(t, peerNS, "10.210.3.1:51820", 3, state)

	// Without the reflector, no member answers, so the up path becomes
	// unhealthy and the upstream stops.
	runIP(t, "-n", reflectorNS, "link", "set", "mr"+suffix, "down")
	waitFor(t, 30*time.Second, "the up reflect path to become unhealthy", state, func() (bool, error) {
		healthy, err := upHealthy()
		return err == nil && !healthy, err
	})

	// With the reflector back, the up path recovers and the upstream flows.
	runIP(t, "-n", reflectorNS, "link", "set", "mr"+suffix, "up")
	waitFor(t, 30*time.Second, "the up reflect path to recover", state, upHealthy)
	exchange(t, peerNS, "10.210.3.1:51820", 3, state)
}
