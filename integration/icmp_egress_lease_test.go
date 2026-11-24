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

// TestPrivilegedICMPIngressKeepsItsEgressPaths runs a group with a plain ICMP
// ingress route and a direct UDP egress route. The ingress paths of a group send
// EGRESS_REGISTER frames before each REGISTER, and the server keeps an egress path
// for 30 seconds after its latest frame. The control connection of a plain ICMP
// ingress path once set a deadline that also covered its writes. From the second
// round on, that deadline was in the past, so the frames never left again. The
// server then lost the egress path 30 seconds after the start, and the group had
// no way back to the client. The test waits 40 seconds after the client starts,
// which is longer than the lease plus one refresh. It needs about 45 seconds.
func TestPrivilegedICMPIngressKeepsItsEgressPaths(t *testing.T) {
	requirePrivilegedLinux(t)
	binaryPath := buildDaemon(t)

	suffix := strconv.FormatInt(time.Now().UnixNano()%1_000_000, 10)
	clientNS, serverNS, targetNS := "mup-client-"+suffix, "mup-server-"+suffix, "mup-target-"+suffix
	switchNS, peerNS := "mup-switch-"+suffix, "mup-peer-"+suffix
	for _, namespace := range []string{clientNS, serverNS, targetNS, switchNS, peerNS} {
		addNamespace(t, namespace)
	}
	runIP(t, "-n", switchNS, "link", "add", "br0", "type", "bridge")
	runIP(t, "-n", switchNS, "link", "set", "br0", "up")
	for _, member := range []struct{ link, namespace string }{
		{"mc" + suffix, clientNS}, {"ms" + suffix, serverNS},
	} {
		port := "b" + member.link
		linkPair(t, member.link, member.namespace, port, switchNS)
		runIP(t, "-n", switchNS, "link", "set", port, "master", "br0", "up")
	}
	// The range 10.224.1.0/24 holds the client (.1) and the server (.2). The echo
	// target sits behind the server on 10.224.2.0/24, and the peer sits behind the
	// client on 10.224.3.0/24.
	const prefix = "10.224"
	clientAddress, serverAddress := prefix+".1.1", prefix+".1.2"
	addressLink(t, clientNS, "mc"+suffix, clientAddress+"/24")
	addressLink(t, serverNS, "ms"+suffix, serverAddress+"/24")
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
  advertise: %s
  control_socket: %s
  servers:
    - port: 51820
      ingress:
        routes: ["%s:5000/icmp"]
      egress:
        routes: ["%s:5010/udp"]
`, clientAddress, clientSocket, serverAddress, serverAddress)
	if err := os.WriteFile(configuration, []byte(content), 0o600); err != nil {
		t.Fatalf("write client configuration: %v", err)
	}
	client := startNamespaced(t, clientNS, binaryPath, "--config", configuration)
	started := time.Now()
	defer client.stop(t)

	clientAPI := api.NewDaemonClient(clientSocket)
	serverAPI := api.NewDaemonClient(serverSocket)
	logs := func() string {
		return fmt.Sprintf("client log:\n%s\nserver log:\n%s\ntarget log:\n%s", client.log(t), server.log(t), target.log(t))
	}
	// serverEgress lists the egress paths that the server holds for the client.
	serverEgress := func() ([]api.EgressPath, error) {
		clients, err := serverAPI.Clients(context.Background())
		if err != nil {
			return nil, err
		}
		var paths []api.EgressPath
		for _, registered := range clients {
			if registered.Egress != nil {
				paths = append(paths, registered.Egress.Paths...)
			}
		}
		return paths, nil
	}
	serverView := func() string {
		paths, err := serverEgress()
		if err != nil {
			return fmt.Sprintf("server egress paths: <%v>", err)
		}
		text := fmt.Sprintf("server egress paths: %d", len(paths))
		for _, path := range paths {
			text += fmt.Sprintf(" [%d %s:%d healthy=%v %d/%d]", path.ID, path.Transport, path.Port, path.Healthy, path.HealthyMembers, path.Members)
		}
		return text
	}
	state := func() string {
		return fmt.Sprintf("%s\n%s\nclient %s\nserver %s\n%s",
			pathText(t, clientAPI), serverView(), dropText(t, clientAPI), dropText(t, serverAPI), logs())
	}
	// clientHealthy says whether the client reports both of its paths healthy.
	clientHealthy := func() (bool, error) {
		paths, err := clientAPI.Paths(context.Background())
		if err != nil || len(paths) < 2 {
			return false, err
		}
		for _, path := range paths {
			if !path.Healthy {
				return false, nil
			}
		}
		return true, nil
	}
	// serverHealthy says whether the server reports its egress path healthy.
	serverHealthy := func() (bool, error) {
		paths, err := serverEgress()
		if err != nil || len(paths) == 0 {
			return false, err
		}
		for _, path := range paths {
			if !path.Healthy {
				return false, nil
			}
		}
		return true, nil
	}

	waitForRegisteredPaths(t, serverAPI, 1, logs)
	waitFor(t, 30*time.Second, "both client paths to become healthy", state, clientHealthy)
	waitFor(t, 30*time.Second, "the server to see the egress path healthy", state, serverHealthy)
	// The server takes a new egress path as healthy for its first 6 seconds.
	// After that it sends a reply only through a path that a probe reply of the
	// client confirmed. The wait passes the first window, so the exchange needs the
	// confirmed path.
	time.Sleep(8 * time.Second)
	exchangeFrom(t, peerNS, prefix+".3.2:0", prefix+".3.1:51820", 3, state)

	// The lease of an egress path on the server lasts 30 seconds from its latest
	// EGRESS_REGISTER frame. The loop runs until 40 seconds after the start, which
	// is the lease plus one refresh. With the bug, the frames stop after the first
	// round, and the egress path leaves the server about 30 seconds after the start.
	for deadline := started.Add(40 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Second) {
		elapsed := time.Since(started).Round(time.Second)
		serverOK, err := serverHealthy()
		if err != nil || !serverOK {
			t.Fatalf("the server lost its healthy egress path %s after the start (error: %v)\n%s", elapsed, err, state())
		}
		clientOK, err := clientHealthy()
		if err != nil || !clientOK {
			t.Fatalf("the client has an unhealthy path %s after the start (error: %v)\n%s", elapsed, err, state())
		}
	}

	exchangeFrom(t, peerNS, prefix+".3.2:0", prefix+".3.1:51820", 3, state)

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
