package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/xshecan/mup/api"
)

// TestPrivilegedBridge runs a group whose ingress path and egress path both go
// through a bridge at 10.210.1.4. The egress path reflects through 10.210.1.3,
// so its replies need a spoofed source. The switch drops every packet of the
// server with another source, so only the bridge can send them. When the
// bridge stops, both paths become unhealthy, and they come back with it.
func TestPrivilegedBridge(t *testing.T) {
	requirePrivilegedLinux(t)
	binaryPath := buildDaemon(t)

	suffix := strconv.FormatInt(time.Now().UnixNano()%1_000_000, 10)
	clientNS, serverNS, targetNS := "mup-client-"+suffix, "mup-server-"+suffix, "mup-target-"+suffix
	reflectorNS, bridgeNS, switchNS, peerNS := "mup-reflector-"+suffix, "mup-bridge-"+suffix, "mup-switch-"+suffix, "mup-peer-"+suffix
	for _, namespace := range []string{clientNS, serverNS, targetNS, reflectorNS, bridgeNS, switchNS, peerNS} {
		addNamespace(t, namespace)
	}
	runIP(t, "-n", switchNS, "link", "add", "br0", "type", "bridge")
	runIP(t, "-n", switchNS, "link", "set", "br0", "up")
	for _, member := range []struct{ link, namespace string }{
		{"mc" + suffix, clientNS}, {"ms" + suffix, serverNS}, {"mr" + suffix, reflectorNS}, {"mb" + suffix, bridgeNS},
	} {
		port := "b" + member.link
		linkPair(t, member.link, member.namespace, port, switchNS)
		runIP(t, "-n", switchNS, "link", "set", port, "master", "br0", "up")
	}
	addressLink(t, clientNS, "mc"+suffix, "10.210.1.1/24")
	addressLink(t, serverNS, "ms"+suffix, "10.210.1.2/24")
	addressLink(t, reflectorNS, "mr"+suffix, "10.210.1.3/24")
	addressLink(t, bridgeNS, "mb"+suffix, "10.210.1.4/24")
	linkPair(t, "st"+suffix, serverNS, "ts"+suffix, targetNS)
	addressLink(t, serverNS, "st"+suffix, "10.210.2.1/24")
	addressLink(t, targetNS, "ts"+suffix, "10.210.2.2/24")
	linkPair(t, "cp"+suffix, clientNS, "pc"+suffix, peerNS)
	addressLink(t, clientNS, "cp"+suffix, "10.210.3.1/24")
	addressLink(t, peerNS, "pc"+suffix, "10.210.3.2/24")
	runInNamespace(t, bridgeNS, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	// The server network drops spoofed packets, as source filtering does.
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("the bridge test needs nft for the source filter of the server")
	}
	for _, rule := range [][]string{
		{"add", "table", "bridge", "mup"},
		{"add", "chain", "bridge", "mup", "forward", "{ type filter hook forward priority 0; }"},
		{"add", "rule", "bridge", "mup", "forward", "iifname", "bms" + suffix, "ip", "saddr", "!=", "10.210.1.2", "drop"},
	} {
		runInNamespace(t, switchNS, append([]string{"nft"}, rule...)...)
	}

	target := startEchoTarget(t, targetNS, "10.210.2.2:51820")
	defer target.stop(t)

	directory := t.TempDir()
	serverSocket := filepath.Join(directory, "server.sock")
	bridgeSocket := filepath.Join(directory, "bridge.sock")
	clientSocket := filepath.Join(directory, "client.sock")
	server := startNamespaced(t, serverNS, binaryPath, "server", "-p", "5000-5099", "-r", "10.210.2.2:51820", "--control-socket", serverSocket)
	defer server.stop(t)
	bridge := startNamespaced(t, bridgeNS, binaryPath, "bridge", "-s", "10.210.1.2", "-p", "5000-5099", "--control-socket", bridgeSocket)
	defer bridge.stop(t)

	configuration := filepath.Join(directory, "client.yaml")
	content := fmt.Sprintf(`client:
  advertise: 10.210.1.1
  control_socket: %s
  servers:
    - port: 51820
      ingress:
        bridges: [10.210.1.4:5000/udp]
      egress:
        bridges:
          - "10.210.1.4:5010/icmp via 10.210.1.3"
`, clientSocket)
	if err := os.WriteFile(configuration, []byte(content), 0o600); err != nil {
		t.Fatalf("write client configuration: %v", err)
	}
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
	// health reads the health of the ingress bridge on the client, and of the egress
	// bridge on the server and on the client.
	health := func() ([3]bool, error) {
		var current [3]bool
		paths, err := clientAPI.Paths(context.Background())
		if err != nil {
			return current, err
		}
		for _, path := range paths {
			if !path.Bridge {
				return current, fmt.Errorf("path %d is not a bridge", path.ID)
			}
			if path.Direction == "ingress" {
				current[0] = path.Healthy
			} else {
				current[2] = path.Healthy
			}
		}
		clients, err := serverAPI.Clients(context.Background())
		if err != nil {
			return current, err
		}
		for _, registered := range clients {
			if registered.Egress != nil && len(registered.Egress.Paths) == 1 && registered.Egress.Paths[0].Bridge {
				current[1] = registered.Egress.Paths[0].Healthy
			}
		}
		return current, nil
	}
	waitForHealth := func(description string, want bool) {
		t.Helper()
		waitFor(t, 40*time.Second, description, state, func() (bool, error) {
			current, err := health()
			return err == nil && current == [3]bool{want, want, want}, err
		})
	}

	waitForHealth("the bridge paths to become healthy", true)
	exchange(t, peerNS, "10.210.3.1:51820", 3, state)
	status, err := bridgeAPI.Status(context.Background())
	if err != nil || status.Bridge == nil {
		t.Fatalf("bridge status = %#v, %v", status, err)
	}
	if status.Bridge.IngressPackets == 0 || status.Bridge.EgressPackets == 0 {
		t.Fatalf("bridge sent %d packets ingress and %d egress, want both\n%s", status.Bridge.IngressPackets, status.Bridge.EgressPackets, state())
	}

	runIP(t, "-n", bridgeNS, "link", "set", "mb"+suffix, "down")
	waitForHealth("the bridge paths to become unhealthy", false)
	runIP(t, "-n", bridgeNS, "link", "set", "mb"+suffix, "up")
	waitForHealth("the bridge paths to come back", true)
	exchange(t, peerNS, "10.210.3.1:51820", 3, state)

	// A drop reset clears the counters of the daemon.
	for name, daemon := range map[string]*api.DaemonClient{"client": clientAPI, "server": serverAPI, "bridge": bridgeAPI} {
		if err := daemon.ResetDrops(context.Background()); err != nil {
			t.Fatalf("reset the drops of the %s: %v", name, err)
		}
	}
	status, err = clientAPI.Status(context.Background())
	if err != nil {
		t.Fatalf("client status: %v", err)
	}
	for _, drop := range status.Drops {
		if drop.Count > 2 {
			t.Fatalf("client drop %s = %d after the reset\n%s", drop.Name, drop.Count, state())
		}
	}
}
