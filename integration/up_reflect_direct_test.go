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

// TestPrivilegedIngressReflectWithoutADirectPath runs a split group whose ingress
// route reflects without a bridge, on a network that drops every packet from the
// client address to the server. The egress registration and the probe replies of
// the group are control frames of the client itself, so they must travel reflected
// like the data. If they leave straight to the server, the switch drops them, the
// server never confirms the egress paths, and the ingress path never gets its ACK.
func TestPrivilegedIngressReflectWithoutADirectPath(t *testing.T) {
	t.Run("udp", func(t *testing.T) {
		// The ingress route forges a member of a small pool as the source. The
		// server answers on the egress paths, never to a pool member, so the
		// reflector needs no pool address.
		runIngressReflectWithoutADirectPath(t, "10.213",
			"10.213.1.2:5000/udp via 10.213.1.8/29",
			"10.213.1.2:5010/icmp via 10.213.1.3")
	})
	t.Run("icmp", func(t *testing.T) {
		// The same reflector host reflects both directions. The two routes have
		// different server ports, so the loader accepts them.
		runIngressReflectWithoutADirectPath(t, "10.214",
			"10.214.1.2:5000/icmp via 10.214.1.3",
			"10.214.1.2:5010/icmp via 10.214.1.3")
	})
}

// runIngressReflectWithoutADirectPath builds the topology in the range prefix.1.0/24
// (client .1, server .2, reflector .3), with the peer behind the client on
// prefix.3.0/24 and the echo target behind the server on prefix.2.0/24. The
// ingress and egress arguments are the routes of the group.
func runIngressReflectWithoutADirectPath(t *testing.T, prefix, ingress, egress string) {
	t.Helper()
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
	addressLink(t, clientNS, "mc"+suffix, prefix+".1.1/24")
	addressLink(t, serverNS, "ms"+suffix, prefix+".1.2/24")
	addressLink(t, reflectorNS, "mr"+suffix, prefix+".1.3/24")
	linkPair(t, "st"+suffix, serverNS, "ts"+suffix, targetNS)
	addressLink(t, serverNS, "st"+suffix, prefix+".2.1/24")
	addressLink(t, targetNS, "ts"+suffix, prefix+".2.2/24")
	linkPair(t, "cp"+suffix, clientNS, "pc"+suffix, peerNS)
	addressLink(t, clientNS, "cp"+suffix, prefix+".3.1/24")
	addressLink(t, peerNS, "pc"+suffix, prefix+".3.2/24")

	target := startEchoTarget(t, targetNS, prefix+".2.2:51820")
	defer target.stop(t)

	directory := t.TempDir()
	serverSocket := filepath.Join(directory, "server.sock")
	clientSocket := filepath.Join(directory, "client.sock")
	server := startNamespaced(t, serverNS, binaryPath, "server", "-p", "5000-5099", "-r", prefix+".2.2:51820", "--control-socket", serverSocket)
	defer server.stop(t)

	configuration := filepath.Join(directory, "client.yaml")
	content := fmt.Sprintf(`client:
  advertise: %s.1.1
  control_socket: %s
  servers:
    - port: 51820
      ingress:
        routes:
          - "%s"
      egress:
        routes:
          - "%s"
`, prefix, clientSocket, ingress, egress)
	if err := os.WriteFile(configuration, []byte(content), 0o600); err != nil {
		t.Fatalf("write client configuration: %v", err)
	}

	// The network has no direct flow from the client to the server. The switch drops
	// every IPv4 packet from the port of the client with the client address as the
	// source and the server as the destination. The rule matches on the source too,
	// because the forged and the reflected packets of the client leave the same port
	// and must pass: a forged UDP packet has a pool member as its source, and a
	// reflected ICMP packet goes to the reflector. Only a control frame that the
	// client sends straight to the server matches, whatever socket sends it. The
	// rule exists before the client starts, so no direct frame ever arrives.
	runInNamespace(t, switchNS, "nft", "add", "table", "bridge", "mup")
	runInNamespace(t, switchNS, "nft", "add", "chain", "bridge", "mup", "forward", "{ type filter hook forward priority 0 ; }")
	runInNamespace(t, switchNS, "nft", "add", "rule", "bridge", "mup", "forward", "iifname", "bmc"+suffix,
		"ip", "saddr", prefix+".1.1", "ip", "daddr", prefix+".1.2", "drop")
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
	// serverEgressHealthy reports whether the server sees an egress path and takes
	// every egress path it knows as healthy.
	serverEgressHealthy := func() (bool, error) {
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
	}

	// The egress path becomes healthy once the server probes it and the probe reply
	// of the client reaches the server. The ingress path becomes healthy once its
	// ACK returns on the egress path.
	waitFor(t, 30*time.Second, "the egress path to become healthy", state, directionHealthy("egress"))
	waitFor(t, 30*time.Second, "the ingress reflect path to become healthy", state, directionHealthy("ingress"))

	// The server takes a new egress path as healthy for its first 6 seconds.
	// After that it sends a reply only through a member that a probe reply of
	// the client confirmed, and that probe reply reaches the server only
	// reflected, because the direct flow is dropped. The wait passes the first
	// window, so the exchange needs the reflected probe replies.
	time.Sleep(8 * time.Second)
	exchangeFrom(t, peerNS, prefix+".3.2:0", prefix+".3.1:51820", 3, state)

	waitFor(t, 5*time.Second, "the server to keep the egress path healthy", state, serverEgressHealthy)
	waitFor(t, 5*time.Second, "the paths to stay healthy after the exchange", state, func() (bool, error) {
		ingressOK, err := directionHealthy("ingress")()
		if err != nil || !ingressOK {
			return false, err
		}
		return directionHealthy("egress")()
	})
	serverStatus, err := serverAPI.Status(context.Background())
	if err != nil {
		t.Fatalf("server status: %v", err)
	}
	if dropped := dropCount(serverStatus.Drops, "NO_PATH"); dropped != 0 {
		t.Fatalf("server dropped %d replies without a path\n%s", dropped, state())
	}
	clientStatus, err := clientAPI.Status(context.Background())
	if err != nil {
		t.Fatalf("client status: %v", err)
	}
	if refused := dropCount(clientStatus.Drops, "EGRESS_SOURCE"); refused != 0 {
		t.Fatalf("client refused %d egress packets\n%s", refused, state())
	}
}
