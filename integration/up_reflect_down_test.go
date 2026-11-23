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

// TestPrivilegedUpReflectDownReflect mirrors the production split group that
// failed: the up routes reflect through a bridge over a UDP pool, and the down
// path reflects the replies through the same pool as ICMP. The up path is
// healthy only when its member ACKs come back on the down path, so a down path
// that the server never probes keeps the up path unhealthy. One reflector owns
// the whole pool 10.210.1.8/29, so it answers both the UDP up members and the
// ICMP down probes.
func TestPrivilegedUpReflectDownReflect(t *testing.T) {
	requirePrivilegedLinux(t)
	binaryPath := buildDaemon(t)

	suffix := strconv.FormatInt(time.Now().UnixNano()%1_000_000, 10)
	clientNS, serverNS, targetNS := "mup-client-"+suffix, "mup-server-"+suffix, "mup-target-"+suffix
	reflectorNS, bridgeNS := "mup-reflector-"+suffix, "mup-bridge-"+suffix
	switchNS, peerNS := "mup-switch-"+suffix, "mup-peer-"+suffix
	for _, namespace := range []string{clientNS, serverNS, targetNS, reflectorNS, bridgeNS, switchNS, peerNS} {
		addNamespace(t, namespace)
	}
	runIP(t, "-n", switchNS, "link", "add", "br0", "type", "bridge")
	runIP(t, "-n", switchNS, "link", "set", "br0", "up")
	for _, member := range []struct{ link, namespace string }{
		{"mc" + suffix, clientNS}, {"ms" + suffix, serverNS},
		{"mr" + suffix, reflectorNS}, {"mb" + suffix, bridgeNS},
	} {
		port := "b" + member.link
		linkPair(t, member.link, member.namespace, port, switchNS)
		runIP(t, "-n", switchNS, "link", "set", port, "master", "br0", "up")
	}
	addressLink(t, clientNS, "mc"+suffix, "10.210.1.1/24")
	addressLink(t, serverNS, "ms"+suffix, "10.210.1.2/24")
	// The down path names a second server address (10.210.1.20), different from
	// the up server (10.210.1.2), as production does (.99 down vs .33 up).
	runIP(t, "-n", serverNS, "addr", "add", "10.210.1.20/24", "dev", "ms"+suffix)
	addressLink(t, reflectorNS, "mr"+suffix, "10.210.1.3/24")
	addressLink(t, bridgeNS, "mb"+suffix, "10.210.1.4/24")
	// The reflector owns the whole pool 10.210.1.8/29, members 10.210.1.9-.14,
	// so it answers both the UDP up registrations and the ICMP down probes.
	for member := 9; member <= 14; member++ {
		runIP(t, "-n", reflectorNS, "addr", "add", fmt.Sprintf("10.210.1.%d/24", member), "dev", "mr"+suffix)
	}
	linkPair(t, "st"+suffix, serverNS, "ts"+suffix, targetNS)
	addressLink(t, serverNS, "st"+suffix, "10.210.2.1/24")
	addressLink(t, targetNS, "ts"+suffix, "10.210.2.2/24")
	linkPair(t, "cp"+suffix, clientNS, "pc"+suffix, peerNS)
	addressLink(t, clientNS, "cp"+suffix, "10.210.3.1/24")
	addressLink(t, peerNS, "pc"+suffix, "10.210.3.2/24")
	runInNamespace(t, bridgeNS, "sysctl", "-qw", "net.ipv4.ip_forward=1")

	// The target is a local server address, as in production, so the echo
	// target runs in the server namespace and takes the ingress delivery.
	target := startEchoTarget(t, serverNS, "10.210.1.2:51820")
	defer target.stop(t)

	directory := t.TempDir()
	serverSocket := filepath.Join(directory, "server.sock")
	bridgeSocket := filepath.Join(directory, "bridge.sock")
	clientSocket := filepath.Join(directory, "client.sock")
	// The production server runs in target-ingress (fast path) mode, so the test
	// does too: the target is a local server address delivered into its ingress.
	server := startNamespaced(t, serverNS, binaryPath, "server", "-p", "5000-5099", "-r", "10.210.1.2:51820", "--target-ingress", "--control-socket", serverSocket)
	defer server.stop(t)
	bridge := startNamespaced(t, bridgeNS, binaryPath, "bridge", "-s", "10.210.1.2", "-p", "5000-5099", "-a", "10.210.1.1/32", "--control-socket", bridgeSocket)
	defer bridge.stop(t)

	configuration := filepath.Join(directory, "client.yaml")
	content := fmt.Sprintf(`client:
  advertise: 10.210.1.1
  control_socket: %s
  servers:
    - port: 51821
      mode: fallback
      routes:
        - "10.210.1.2:5020/icmp via 10.210.1.8/29 balance per-packet"
    - port: 51820
      upstream:
        routes:
          - "10.210.1.2:5000/udp via 10.210.1.8/29 balance per-packet bridge 10.210.1.4"
      downstream:
        routes:
          - "10.210.1.20:5010/icmp via 10.210.1.8/29 balance per-packet"
`, clientSocket)
	if err := os.WriteFile(configuration, []byte(content), 0o600); err != nil {
		t.Fatalf("write client configuration: %v", err)
	}
	// Production reaches the server only through the reflection, never directly,
	// which is the reason the up path uses a bridge. The switch drops every
	// IPv4 packet from the port of the client to the up server, so a control
	// frame that the client sends straight to the server is lost in transit,
	// whatever socket sends it. The down registration and the probe replies
	// must travel through the bridge to arrive.
	runInNamespace(t, switchNS, "nft", "add", "table", "bridge", "mup")
	runInNamespace(t, switchNS, "nft", "add", "chain", "bridge", "mup", "forward", "{ type filter hook forward priority 0 ; }")
	runInNamespace(t, switchNS, "nft", "add", "rule", "bridge", "mup", "forward", "iifname", "bmc"+suffix, "ip", "daddr", "10.210.1.2", "drop")
	client := startNamespaced(t, clientNS, binaryPath, "--config", configuration)
	defer client.stop(t)

	clientAPI := api.NewDaemonClient(clientSocket)
	serverAPI := api.NewDaemonClient(serverSocket)
	bridgeAPI := api.NewDaemonClient(bridgeSocket)
	logs := func() string {
		return fmt.Sprintf("client log:\n%s\nserver log:\n%s\nbridge log:\n%s\ntarget log:\n%s",
			client.log(t), server.log(t), bridge.log(t), target.log(t))
	}
	state := func() string {
		return fmt.Sprintf("%s\nclient %s\nserver %s\nbridge %s\n%s",
			pathText(t, clientAPI), dropText(t, clientAPI), dropText(t, serverAPI), dropText(t, bridgeAPI), logs())
	}
	directionHealthy := func(direction string) func() (bool, error) {
		return func() (bool, error) {
			paths, err := clientAPI.Paths(context.Background())
			if err != nil {
				return false, err
			}
			for _, path := range paths {
				if path.Direction == direction {
					return path.Healthy, nil
				}
			}
			return false, nil
		}
	}

	// The down path reflects, so it becomes healthy once the server reflects a
	// probe through the pool to the client.
	waitFor(t, 30*time.Second, "the reflected down path to become healthy", state, directionHealthy("down"))
	// The up path becomes healthy once its member ACK returns on the down path.
	waitFor(t, 30*time.Second, "the up bridge reflect path to become healthy", state, directionHealthy("up"))

	// The server takes a new down path as healthy for its first 6 seconds.
	// After that it sends a reply only through a member that a probe reply of
	// the client confirmed, and that reply reaches the server only through the
	// bridge. The wait passes the first window, so the exchange needs it.
	time.Sleep(8 * time.Second)
	exchange(t, peerNS, "10.210.3.1:51820", 3, state)
	waitFor(t, 5*time.Second, "the paths to stay healthy after the exchange", state, func() (bool, error) {
		up, err := directionHealthy("up")()
		if err != nil || !up {
			return false, err
		}
		return directionHealthy("down")()
	})
}
