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

// TestPrivilegedTwoGroupsOneClient runs one client with two groups: a normal
// group on port 51820 and a group with separate egress paths on port 51821.
// Both groups register with the same client key, and the server must keep the
// listen port of each group, so that every reply follows the paths of its own
// group. A server with one listen port per client sends the replies of both
// groups by the group that registered last, and the client drops them as
// EGRESS_SOURCE.
func TestPrivilegedTwoGroupsOneClient(t *testing.T) {
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
	addressLink(t, clientNS, "mc"+suffix, "10.212.1.1/24")
	addressLink(t, serverNS, "ms"+suffix, "10.212.1.2/24")
	addressLink(t, reflectorNS, "mr"+suffix, "10.212.1.3/24")
	linkPair(t, "st"+suffix, serverNS, "ts"+suffix, targetNS)
	addressLink(t, serverNS, "st"+suffix, "10.212.2.1/24")
	addressLink(t, targetNS, "ts"+suffix, "10.212.2.2/24")
	linkPair(t, "cp"+suffix, clientNS, "pc"+suffix, peerNS)
	addressLink(t, clientNS, "cp"+suffix, "10.212.3.1/24")
	addressLink(t, peerNS, "pc"+suffix, "10.212.3.2/24")

	// One target serves both groups, because it answers every message.
	target := startEchoTarget(t, targetNS, "10.212.2.2:51820")
	defer target.stop(t)

	directory := t.TempDir()
	serverSocket := filepath.Join(directory, "server.sock")
	clientSocket := filepath.Join(directory, "client.sock")
	server := startNamespaced(t, serverNS, binaryPath, "server", "-p", "5000-5099", "-r", "10.212.2.2:51820", "--control-socket", serverSocket)
	defer server.stop(t)

	configuration := filepath.Join(directory, "client.yaml")
	content := fmt.Sprintf(`client:
  advertise: 10.212.1.1
  control_socket: %s
  servers:
    - port: 51820
      mode: failover
      routes: [10.212.1.2:5000/udp]
    - port: 51821
      ingress:
        routes: [10.212.1.2:5001/udp]
      egress:
        mode: failover
        routes:
          - "10.212.1.2:5010/icmp via 10.212.1.3"
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
	// egressHealthy tells whether the egress path of the second group is healthy
	// on the server and on the client.
	egressHealthy := func() (bool, error) {
		clients, err := serverAPI.Clients(context.Background())
		if err != nil {
			return false, err
		}
		onServer := false
		for _, registered := range clients {
			if registered.Egress == nil {
				continue
			}
			for _, path := range registered.Egress.Paths {
				onServer = onServer || path.Healthy
			}
		}
		paths, err := clientAPI.Paths(context.Background())
		if err != nil {
			return false, err
		}
		onClient := false
		for _, path := range paths {
			onClient = onClient || (path.Direction == "egress" && path.Healthy)
		}
		return onServer && onClient, nil
	}

	// The helper exchange has the peer address of the other tests built in, so the
	// loop below uses exchangeFrom. The two ingress paths are one path of each group.
	waitForRegisteredPaths(t, serverAPI, 2, logs)
	waitFor(t, 30*time.Second, "the egress path of the second group to become healthy", state, egressHealthy)

	// Each path registers again 10 seconds after its own ACK, and a server with
	// one listen port per client follows the group that registered last. A
	// second ingress path of the split group, added 4 seconds after the start,
	// registers between the other paths. The split group is then the last one
	// for a part of each cycle, whatever the order of the first paths is.
	time.Sleep(4 * time.Second)
	if _, err := clientAPI.AddPath(context.Background(), "10.212.1.2:5002/udp", 51821); err != nil {
		t.Fatalf("add an ingress path to the split group: %v\n%s", err, state())
	}
	waitForRegisteredPaths(t, serverAPI, 3, logs)

	// Each group registers again every 10 seconds, so 25 seconds cover two
	// refresh cycles of each group. The client drops a reply that follows the
	// wrong group. The exchange then fails, or a later copy passes and the drop
	// counter below shows it.
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		exchangeFrom(t, peerNS, "10.212.3.2:0", "10.212.3.1:51820", 3, state)
		exchangeFrom(t, peerNS, "10.212.3.2:0", "10.212.3.1:51821", 3, state)
		time.Sleep(500 * time.Millisecond)
	}

	status, err := clientAPI.Status(context.Background())
	if err != nil {
		t.Fatalf("client status: %v", err)
	}
	if refused := dropCount(status.Drops, "EGRESS_SOURCE"); refused != 0 {
		t.Fatalf("client refused %d egress packets\n%s", refused, state())
	}
	serverStatus, err := serverAPI.Status(context.Background())
	if err != nil {
		t.Fatalf("server status: %v", err)
	}
	if lost := dropCount(serverStatus.Drops, "NO_PATH"); lost != 0 {
		t.Fatalf("server found no path for %d packets\n%s", lost, state())
	}
}
