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

// TestPrivilegedEgressBridgeVia runs a group whose egress is a UDP bridge entry
// with a via. The server sends the wrapped replies to the bridge with the via
// address as the source, and the bridge sends them to the client from its own
// address. The switch drops every packet of the bridge with another source, so
// the bridge cannot spoof. It also drops every packet from the server to the
// client, so no reply goes straight. The bridge lists the via address in its
// allow list. An ICMP entry reflects the wrapper off a real via host, and
// TestPrivilegedEgressBridgeReflect covers it.
func TestPrivilegedEgressBridgeVia(t *testing.T) {
	runEgressBridgeVia(t, "10.215", "udp", true)
}

// TestPrivilegedEgressBridgeViaNeedsAllow starts the same group with a bridge that
// does not list the via address. The bridge unwraps only packets from allowed
// sources, so it drops every wrapper of the server and the egress path never
// becomes healthy.
func TestPrivilegedEgressBridgeViaNeedsAllow(t *testing.T) {
	runEgressBridgeVia(t, "10.217", "udp", false)
}

// runEgressBridgeVia builds the topology in the range prefix.1.0/24 (client .1,
// server .2, bridge .4), with the peer behind the client on prefix.3.0/24 and the
// echo target behind the server on prefix.2.0/24. The via address .9 belongs to
// no host. It only appears as a forged source. The transport is the transport of
// the egress bridge entry. When allowed is false, the bridge does not list the via
// address.
func runEgressBridgeVia(t *testing.T, prefix, transport string, allowed bool) {
	t.Helper()
	requirePrivilegedLinux(t)
	binaryPath := buildDaemon(t)

	suffix := strconv.FormatInt(time.Now().UnixNano()%1_000_000, 10)
	clientNS, serverNS, targetNS := "mup-client-"+suffix, "mup-server-"+suffix, "mup-target-"+suffix
	bridgeNS, switchNS, peerNS := "mup-bridge-"+suffix, "mup-switch-"+suffix, "mup-peer-"+suffix
	for _, namespace := range []string{clientNS, serverNS, targetNS, bridgeNS, switchNS, peerNS} {
		addNamespace(t, namespace)
	}
	runIP(t, "-n", switchNS, "link", "add", "br0", "type", "bridge")
	runIP(t, "-n", switchNS, "link", "set", "br0", "up")
	for _, member := range []struct{ link, namespace string }{
		{"mc" + suffix, clientNS}, {"ms" + suffix, serverNS}, {"mb" + suffix, bridgeNS},
	} {
		port := "b" + member.link
		linkPair(t, member.link, member.namespace, port, switchNS)
		runIP(t, "-n", switchNS, "link", "set", port, "master", "br0", "up")
	}
	clientAddress, serverAddress := prefix+".1.1", prefix+".1.2"
	bridgeAddress, viaAddress := prefix+".1.4", prefix+".1.9"
	addressLink(t, clientNS, "mc"+suffix, clientAddress+"/24")
	addressLink(t, serverNS, "ms"+suffix, serverAddress+"/24")
	addressLink(t, bridgeNS, "mb"+suffix, bridgeAddress+"/24")
	linkPair(t, "st"+suffix, serverNS, "ts"+suffix, targetNS)
	addressLink(t, serverNS, "st"+suffix, prefix+".2.1/24")
	addressLink(t, targetNS, "ts"+suffix, prefix+".2.2/24")
	linkPair(t, "cp"+suffix, clientNS, "pc"+suffix, peerNS)
	addressLink(t, clientNS, "cp"+suffix, prefix+".3.1/24")
	addressLink(t, peerNS, "pc"+suffix, prefix+".3.2/24")
	runInNamespace(t, bridgeNS, "sysctl", "-qw", "net.ipv4.ip_forward=1")

	// The switch rules exist before the daemons start. The first rule drops every
	// IPv4 packet from the port of the bridge with another source than the bridge,
	// so a spoofed reply never arrives. The second rule drops every IPv4 packet
	// from the port of the server to the client, so no reply goes straight. The
	// server still reaches the bridge, and the ACKs and probes of the group
	// travel through it.
	runInNamespace(t, switchNS, "nft", "add", "table", "bridge", "mup")
	runInNamespace(t, switchNS, "nft", "add", "chain", "bridge", "mup", "forward", "{ type filter hook forward priority 0 ; }")
	runInNamespace(t, switchNS, "nft", "add", "rule", "bridge", "mup", "forward", "iifname", "bmb"+suffix,
		"ip", "saddr", "!=", bridgeAddress, "drop")
	runInNamespace(t, switchNS, "nft", "add", "rule", "bridge", "mup", "forward", "iifname", "bms"+suffix,
		"ip", "daddr", clientAddress, "drop")

	target := startEchoTarget(t, targetNS, prefix+".2.2:51820")
	defer target.stop(t)

	directory := t.TempDir()
	serverSocket := filepath.Join(directory, "server.sock")
	bridgeSocket := filepath.Join(directory, "bridge.sock")
	clientSocket := filepath.Join(directory, "client.sock")
	server := startNamespaced(t, serverNS, binaryPath, "server", "-p", "5000-5009", "-r", prefix+".2.2:51820", "--control-socket", serverSocket)
	defer server.stop(t)
	// The bridge accepts the server and, when allowed, the via address. Without
	// the via address in its allow list, it drops the wrappers of the server.
	bridgeArguments := []string{"bridge", "-s", serverAddress, "-p", "5010-5019", "--control-socket", bridgeSocket}
	if allowed {
		bridgeArguments = append(bridgeArguments, "-a", viaAddress+"/32")
	}
	bridge := startNamespaced(t, bridgeNS, binaryPath, bridgeArguments...)
	defer bridge.stop(t)

	configuration := filepath.Join(directory, "client.yaml")
	content := fmt.Sprintf(`client:
  advertise: %s
  control_socket: %s
  servers:
    - port: 51820
      ingress:
        routes:
          - "%s:5000/udp"
      egress:
        bridges:
          - "%s:5010/%s via %s"
`, clientAddress, clientSocket, serverAddress, bridgeAddress, transport, viaAddress)
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

	if !allowed {
		// The bridge drops every wrapper, so no probe reaches the client and the
		// egress path stays unhealthy. The bridge counts each wrapper as a drop
		// of its source.
		// The client needs a moment to open its control socket.
		waitFor(t, 10*time.Second, "the client to answer on its control socket", logs, func() (bool, error) {
			_, err := clientAPI.Paths(context.Background())
			return err == nil, nil
		})
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			healthy, err := directionHealthy("egress")()
			if err != nil {
				t.Fatalf("read the paths: %v", err)
			}
			if healthy {
				t.Fatalf("the egress path became healthy although the bridge does not allow the via address\n%s", state())
			}
			time.Sleep(500 * time.Millisecond)
		}
		status, err := bridgeAPI.Status(context.Background())
		if err != nil {
			t.Fatalf("bridge status: %v", err)
		}
		if dropCount(status.Drops, "BRIDGE_SOURCE") == 0 {
			t.Fatalf("the bridge counted no BRIDGE_SOURCE drop\n%s", state())
		}
		return
	}

	// The egress path becomes healthy once the server probes it through the bridge
	// and the probe reply reaches the server. The ingress path becomes healthy once
	// its ACK returns on the egress path, because the direct ACK is dropped.
	waitFor(t, 30*time.Second, "the egress bridge path to become healthy", state, directionHealthy("egress"))
	waitFor(t, 30*time.Second, "the ingress path to become healthy", state, directionHealthy("ingress"))

	// The server takes a new egress path as healthy for its first 6 seconds.
	// After that it sends a reply only through a member that a probe reply of
	// the client confirmed. The wait passes the first window, so the exchange
	// needs the confirmed via member.
	time.Sleep(8 * time.Second)
	exchangeFrom(t, peerNS, prefix+".3.2:0", prefix+".3.1:51820", 3, state)

	waitFor(t, 5*time.Second, "the server to keep the egress path healthy", state, func() (bool, error) {
		clients, err := serverAPI.Clients(context.Background())
		if err != nil {
			return false, err
		}
		seen := false
		for _, registered := range clients {
			if registered.Egress == nil {
				continue
			}
			for _, path := range registered.Egress.Paths {
				if !path.Healthy {
					return false, nil
				}
				seen = true
			}
		}
		return seen, nil
	})
	waitFor(t, 5*time.Second, "the paths to stay healthy after the exchange", state, func() (bool, error) {
		ingress, err := directionHealthy("ingress")()
		if err != nil || !ingress {
			return false, err
		}
		return directionHealthy("egress")()
	})

	clientStatus, err := clientAPI.Status(context.Background())
	if err != nil {
		t.Fatalf("client status: %v", err)
	}
	if refused := dropCount(clientStatus.Drops, "EGRESS_SOURCE"); refused != 0 {
		t.Fatalf("client refused %d egress packets\n%s", refused, state())
	}
	serverStatus, err := serverAPI.Status(context.Background())
	if err != nil {
		t.Fatalf("server status: %v", err)
	}
	if dropped := dropCount(serverStatus.Drops, "NO_PATH"); dropped != 0 {
		t.Fatalf("server dropped %d replies without a path\n%s", dropped, state())
	}
	bridgeStatus, err := bridgeAPI.Status(context.Background())
	if err != nil || bridgeStatus.Bridge == nil {
		t.Fatalf("bridge status = %#v, %v", bridgeStatus, err)
	}
	for _, drop := range bridgeStatus.Drops {
		if drop.Count != 0 {
			t.Fatalf("bridge drop %s = %d, want 0\n%s", drop.Name, drop.Count, state())
		}
	}
	if bridgeStatus.Bridge.EgressPackets == 0 {
		t.Fatalf("the bridge sent no egress packets\n%s", state())
	}
}
