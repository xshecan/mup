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

// TestPrivilegedIngressBridgeReflect runs a group whose ingress route reflects the
// ingress through a member at 10.210.1.3, by way of a bridge at 10.210.1.4.
// The client cannot spoof, so it wraps each reflected REGISTER and each ingress
// packet for the bridge, and the bridge removes the wrapper and emits the
// spoofed packet to the member. The member answers the server, so the ingress route
// is healthy while the bridge relays, and the ingress stops when the bridge
// fails.
func TestPrivilegedIngressBridgeReflect(t *testing.T) {
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
	addressLink(t, reflectorNS, "mr"+suffix, "10.210.1.3/24")
	addressLink(t, bridgeNS, "mb"+suffix, "10.210.1.4/24")
	linkPair(t, "st"+suffix, serverNS, "ts"+suffix, targetNS)
	addressLink(t, serverNS, "st"+suffix, "10.210.2.1/24")
	addressLink(t, targetNS, "ts"+suffix, "10.210.2.2/24")
	linkPair(t, "cp"+suffix, clientNS, "pc"+suffix, peerNS)
	addressLink(t, clientNS, "cp"+suffix, "10.210.3.1/24")
	addressLink(t, peerNS, "pc"+suffix, "10.210.3.2/24")
	runInNamespace(t, bridgeNS, "sysctl", "-qw", "net.ipv4.ip_forward=1")

	target := startEchoTarget(t, targetNS, "10.210.2.2:51820")
	defer target.stop(t)

	directory := t.TempDir()
	serverSocket := filepath.Join(directory, "server.sock")
	bridgeSocket := filepath.Join(directory, "bridge.sock")
	clientSocket := filepath.Join(directory, "client.sock")
	server := startNamespaced(t, serverNS, binaryPath, "server", "-p", "5000-5099", "-r", "10.210.2.2:51820", "--control-socket", serverSocket)
	defer server.stop(t)
	// The bridge allows the advertised client source, because the client sends
	// the wrapper from that address, not from the server.
	bridge := startNamespaced(t, bridgeNS, binaryPath, "bridge", "-s", "10.210.1.2", "-p", "5000-5099", "-a", "10.210.1.1/32", "--control-socket", bridgeSocket)
	defer bridge.stop(t)

	configuration := filepath.Join(directory, "client.yaml")
	content := fmt.Sprintf(`client:
  advertise: 10.210.1.1
  control_socket: %s
  servers:
    - port: 51820
      ingress:
        routes:
          - "10.210.1.2:5000/icmp via 10.210.1.3 bridge 10.210.1.4"
      egress:
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
	bridgeAPI := api.NewDaemonClient(bridgeSocket)
	logs := func() string {
		return fmt.Sprintf("client log:\n%s\nserver log:\n%s\nbridge log:\n%s\ntarget log:\n%s",
			client.log(t), server.log(t), bridge.log(t), target.log(t))
	}
	state := func() string {
		return fmt.Sprintf("%s\nclient %s\nserver %s\nbridge %s\n%s",
			pathText(t, clientAPI), dropText(t, clientAPI), dropText(t, serverAPI), dropText(t, bridgeAPI), logs())
	}
	ingressHealthy := func() (bool, error) {
		paths, err := clientAPI.Paths(context.Background())
		if err != nil {
			return false, err
		}
		for _, path := range paths {
			if path.Direction == "ingress" {
				return path.Healthy, nil
			}
		}
		return false, nil
	}

	// The member reflects the REGISTER that the bridge emits, so the server sees
	// one registered path, and the ingress route becomes healthy.
	waitForRegisteredPaths(t, serverAPI, 1, logs)
	waitFor(t, 30*time.Second, "the ingress bridge reflect path to become healthy", state, ingressHealthy)
	exchange(t, peerNS, "10.210.3.1:51820", 3, state)

	// The bridge removed the wrapper and relayed the ingress, so it counted the
	// wrapped packets that it unwrapped.
	status, err := bridgeAPI.Status(context.Background())
	if err != nil || status.Bridge == nil {
		t.Fatalf("bridge status = %#v, %v", status, err)
	}
	if status.Bridge.EgressPackets == 0 {
		t.Fatalf("bridge relayed %d wrapped packets, want more than zero\n%s", status.Bridge.EgressPackets, state())
	}

	// Without the bridge, the client cannot emit the spoofed packet, so the ingress
	// route becomes unhealthy and the ingress stops.
	runIP(t, "-n", bridgeNS, "link", "set", "mb"+suffix, "down")
	waitFor(t, 30*time.Second, "the ingress bridge reflect path to become unhealthy", state, func() (bool, error) {
		healthy, err := ingressHealthy()
		return err == nil && !healthy, err
	})

	// With the bridge back, the ingress route recovers and the ingress flows.
	runIP(t, "-n", bridgeNS, "link", "set", "mb"+suffix, "up")
	waitFor(t, 30*time.Second, "the ingress bridge reflect path to recover", state, ingressHealthy)
	exchange(t, peerNS, "10.210.3.1:51820", 3, state)
}
