package integration

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/xshecan/mup/api"
)

func TestPrivilegedModesAndFailover(t *testing.T) {
	requirePrivilegedLinux(t)
	binaryPath := buildDaemon(t)

	suffix := strconv.FormatInt(time.Now().UnixNano()%1_000_000, 10)
	clientNS, peerNS, targetNS := "mup-client-"+suffix, "mup-peer-"+suffix, "mup-target-"+suffix
	firstNS, secondNS := "mup-s1-"+suffix, "mup-s2-"+suffix
	for _, namespace := range []string{clientNS, peerNS, targetNS, firstNS, secondNS} {
		addNamespace(t, namespace)
	}

	linkPair(t, "cp"+suffix, clientNS, "pc"+suffix, peerNS)
	addressLink(t, clientNS, "cp"+suffix, "10.210.3.1/24")
	addressLink(t, peerNS, "pc"+suffix, "10.210.3.2/24")

	linkPair(t, "c1"+suffix, clientNS, "s1"+suffix, firstNS)
	addressLink(t, clientNS, "c1"+suffix, "10.210.1.1/24")
	addressLink(t, firstNS, "s1"+suffix, "10.210.1.2/24")
	linkPair(t, "c2"+suffix, clientNS, "s2"+suffix, secondNS)
	addressLink(t, clientNS, "c2"+suffix, "10.210.5.1/24")
	addressLink(t, secondNS, "s2"+suffix, "10.210.5.2/24")
	runIP(t, "-n", secondNS, "route", "add", "10.210.1.1/32", "via", "10.210.5.1")

	linkPair(t, "a1"+suffix, firstNS, "t1"+suffix, targetNS)
	addressLink(t, firstNS, "a1"+suffix, "10.210.2.1/24")
	addressLink(t, targetNS, "t1"+suffix, "10.210.2.2/24")
	linkPair(t, "a2"+suffix, secondNS, "t2"+suffix, targetNS)
	addressLink(t, secondNS, "a2"+suffix, "10.210.6.1/24")
	addressLink(t, targetNS, "t2"+suffix, "10.210.6.2/24")
	runIP(t, "-n", secondNS, "route", "add", "10.210.2.2/32", "via", "10.210.6.2")

	target := startEchoTarget(t, targetNS, "10.210.2.2:51820")
	defer target.stop(t)

	directory := t.TempDir()
	firstSocket := filepath.Join(directory, "s1.sock")
	secondSocket := filepath.Join(directory, "s2.sock")
	clientSocket := filepath.Join(directory, "client.sock")
	first := startNamespaced(t, firstNS, binaryPath, "server", "-p", "5000", "-r", "10.210.2.2:51820", "--control-socket", firstSocket)
	defer first.stop(t)
	second := startNamespaced(t, secondNS, binaryPath, "server", "-p", "5000", "-r", "10.210.2.2:51820", "--control-socket", secondSocket)
	defer second.stop(t)

	configuration := filepath.Join(directory, "client.yaml")
	content := fmt.Sprintf(`client:
  advertise: 10.210.1.1
  control_socket: %s
  servers:
    - port: 51820
      mode: burst
      routes: [10.210.1.2:5000/udp, 10.210.5.2:5000/icmp]
`, clientSocket)
	if err := os.WriteFile(configuration, []byte(content), 0o600); err != nil {
		t.Fatalf("write client configuration: %v", err)
	}
	client := startNamespaced(t, clientNS, binaryPath, "--config", configuration)
	defer client.stop(t)

	clientAPI := api.NewDaemonClient(clientSocket)
	firstAPI := api.NewDaemonClient(firstSocket)
	secondAPI := api.NewDaemonClient(secondSocket)
	logs := func() string {
		return fmt.Sprintf("client log:\n%s\nfirst server log:\n%s\nsecond server log:\n%s", client.log(t), first.log(t), second.log(t))
	}
	waitForRegisteredPaths(t, firstAPI, 1, logs)
	waitForRegisteredPaths(t, secondAPI, 1, logs)

	routeCounts := func() (int, int) {
		return len(serverRoutes(t, firstAPI)), len(serverRoutes(t, secondAPI))
	}
	state := func() string {
		return fmt.Sprintf("%s\nclient %s\nfirst server %s\nsecond server %s\n%s",
			pathText(t, clientAPI), dropText(t, clientAPI), dropText(t, firstAPI), dropText(t, secondAPI), logs())
	}

	exchange(t, peerNS, "10.210.3.1:51820", 1, logs)
	if first, second := routeCounts(); first != 1 || second != 1 {
		t.Fatalf("burst left %d and %d routes on the servers, want 1 and 1\n%s", first, second, state())
	}

	setMode(t, clientAPI, "fallback")
	exchange(t, peerNS, "10.210.3.1:51820", 1, logs)
	if first, second := routeCounts(); first != 2 || second != 1 {
		t.Fatalf("fallback left %d and %d routes on the servers, want 2 and 1\n%s", first, second, state())
	}

	setMode(t, clientAPI, "balancer")
	exchange(t, peerNS, "10.210.3.1:51820", 3, logs)
	if first, second := routeCounts(); first+second != 4 {
		t.Fatalf("balancer left %d and %d routes on the servers, want 4 in all\n%s", first, second, state())
	}

	setMode(t, clientAPI, "fallback")
	_, before := routeCounts()
	first.stop(t)
	waitFor(t, 40*time.Second, "the first path to become unhealthy", logs, func() (bool, error) {
		paths, err := clientAPI.Paths(context.Background())
		if err != nil || len(paths) != 2 {
			return false, err
		}
		return !paths[0].Healthy && paths[1].Healthy, nil
	})
	exchange(t, peerNS, "10.210.3.1:51820", 2, logs)
	if after := len(serverRoutes(t, secondAPI)); after != before+1 {
		t.Fatalf("failover left %d routes on the second server, want %d\n%s\nclient %s", after, before+1, pathText(t, clientAPI), dropText(t, clientAPI))
	}
}

func TestPrivilegedLocalTarget(t *testing.T) {
	requirePrivilegedLinux(t)
	if _, err := exec.LookPath("ethtool"); err != nil {
		t.Skip("the local target test needs ethtool")
	}
	binaryPath := buildDaemon(t)

	tests := []struct {
		name      string
		target    string
		transport string
	}{
		{name: "loopback-udp", target: "127.0.0.1:51820", transport: "udp"},
		{name: "loopback-icmp", target: "127.0.0.1:51820", transport: "icmp"},
		{name: "own-address-udp", target: "10.210.1.2:51820", transport: "udp"},
		{name: "own-address-icmp", target: "10.210.1.2:51820", transport: "icmp"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			suffix := strconv.FormatInt(time.Now().UnixNano()%1_000_000, 10)
			clientNS, peerNS, serverNS := "mup-client-"+suffix, "mup-peer-"+suffix, "mup-server-"+suffix
			for _, namespace := range []string{clientNS, peerNS, serverNS} {
				addNamespace(t, namespace)
			}
			linkPair(t, "cp"+suffix, clientNS, "pc"+suffix, peerNS)
			addressLink(t, clientNS, "cp"+suffix, "10.210.3.1/24")
			addressLink(t, peerNS, "pc"+suffix, "10.210.3.2/24")
			linkPair(t, "mc"+suffix, clientNS, "ms"+suffix, serverNS)
			addressLink(t, clientNS, "mc"+suffix, "10.210.1.1/24")
			addressLink(t, serverNS, "ms"+suffix, "10.210.1.2/24")
			runInNamespace(t, serverNS, "ethtool", "-K", "ms"+suffix, "tx", "off")

			target := startEchoTarget(t, serverNS, test.target)
			defer target.stop(t)

			directory := t.TempDir()
			serverSocket := filepath.Join(directory, "server.sock")
			server := startNamespaced(t, serverNS, binaryPath, "server", "-p", "5000", "-r", test.target, "--control-socket", serverSocket)
			defer server.stop(t)
			client := startDaemon(t, clientNS, binaryPath, "client", "-p", "51820", "-u", "10.210.1.2:5000/"+test.transport, "-s", "10.210.1.1")
			defer client.stop(t)
			logs := func() string {
				return fmt.Sprintf("client log:\n%s\nserver log:\n%s\ntarget log:\n%s", client.log(t), server.log(t), target.log(t))
			}
			serverAPI := api.NewDaemonClient(serverSocket)
			waitForRegisteredPaths(t, serverAPI, 1, logs)
			exchange(t, peerNS, "10.210.3.1:51820", 3, func() string {
				return dropText(t, serverAPI) + "\n" + logs()
			})
		})
	}
}

func TestPrivilegedSourceLimit(t *testing.T) {
	requirePrivilegedLinux(t)
	binaryPath := buildDaemon(t)

	suffix := strconv.FormatInt(time.Now().UnixNano()%1_000_000, 10)
	clientNS, peerNS, serverNS, targetNS := "mup-client-"+suffix, "mup-peer-"+suffix, "mup-server-"+suffix, "mup-target-"+suffix
	for _, namespace := range []string{clientNS, peerNS, serverNS, targetNS} {
		addNamespace(t, namespace)
	}
	linkPair(t, "cp"+suffix, clientNS, "pc"+suffix, peerNS)
	addressLink(t, clientNS, "cp"+suffix, "10.210.3.1/24")
	addressLink(t, peerNS, "pc"+suffix, "10.210.3.2/24")
	runIP(t, "-n", peerNS, "addr", "add", "10.210.3.3/24", "dev", "pc"+suffix)
	linkPair(t, "mc"+suffix, clientNS, "ms"+suffix, serverNS)
	addressLink(t, clientNS, "mc"+suffix, "10.210.1.1/24")
	addressLink(t, serverNS, "ms"+suffix, "10.210.1.2/24")
	linkPair(t, "st"+suffix, serverNS, "ts"+suffix, targetNS)
	addressLink(t, serverNS, "st"+suffix, "10.210.2.1/24")
	addressLink(t, targetNS, "ts"+suffix, "10.210.2.2/24")

	target := startEchoTarget(t, targetNS, "10.210.2.2:51820")
	defer target.stop(t)
	directory := t.TempDir()
	serverSocket := filepath.Join(directory, "server.sock")
	clientSocket := filepath.Join(directory, "client.sock")
	server := startNamespaced(t, serverNS, binaryPath, "server", "-p", "5000", "-r", "10.210.2.2:51820", "--control-socket", serverSocket)
	defer server.stop(t)
	client := startNamespaced(t, clientNS, binaryPath, "client", "-p", "51820", "-u", "10.210.1.2:5000/udp", "-s", "10.210.1.1", "--control-socket", clientSocket)
	defer client.stop(t)
	logs := func() string {
		return fmt.Sprintf("client log:\n%s\nserver log:\n%s", client.log(t), server.log(t))
	}
	waitForRegisteredPaths(t, api.NewDaemonClient(serverSocket), 1, logs)

	const sources = 1100
	flood := exec.Command("ip", "netns", "exec", peerNS, testExecutable(t), "-test.run=^TestHelperProcess$", "-test.v")
	flood.Env = append(os.Environ(),
		"MUP_INTEGRATION_HELPER=flood",
		"MUP_PEER_DESTINATION=10.210.3.1:51820",
		"MUP_FLOOD_COUNT="+strconv.Itoa(sources),
	)
	if output, err := flood.CombinedOutput(); err != nil {
		t.Fatalf("flood: %v\n%s", err, output)
	}

	clientAPI := api.NewDaemonClient(clientSocket)
	status, err := clientAPI.Status(context.Background())
	if err != nil {
		t.Fatalf("client status: %v\n%s", err, logs())
	}
	refused := dropCount(status.Drops, "SOURCE_LIMIT")
	if status.Client.Peers > 1024 || status.Client.Peers < 1000 {
		t.Fatalf("the client has %d routes after %d sources, want about 1024\n%s", status.Client.Peers, sources, dropText(t, clientAPI))
	}
	if refused < sources-1024 {
		t.Fatalf("SOURCE_LIMIT counted %d packets, want at least %d\n%s", refused, sources-1024, dropText(t, clientAPI))
	}

	exchangeFrom(t, peerNS, "10.210.3.3:0", "10.210.3.1:51820", 1, logs)
}

func TestPrivilegedPingPassesThePrograms(t *testing.T) {
	requirePrivilegedLinux(t)
	binaryPath := buildDaemon(t)

	suffix := strconv.FormatInt(time.Now().UnixNano()%1_000_000, 10)
	clientNS, serverNS := "mup-client-"+suffix, "mup-server-"+suffix
	for _, namespace := range []string{clientNS, serverNS} {
		addNamespace(t, namespace)
	}
	linkPair(t, "mc"+suffix, clientNS, "ms"+suffix, serverNS)
	addressLink(t, clientNS, "mc"+suffix, "10.210.1.1/24")
	addressLink(t, serverNS, "ms"+suffix, "10.210.1.2/24")

	directory := t.TempDir()
	serverSocket := filepath.Join(directory, "server.sock")
	server := startNamespaced(t, serverNS, binaryPath, "server", "-p", "5000", "-r", "10.210.1.9:51820", "--control-socket", serverSocket)
	defer server.stop(t)
	client := startDaemon(t, clientNS, binaryPath, "client", "-p", "51820", "-u", "10.210.1.2:5000/icmp", "-s", "10.210.1.1")
	defer client.stop(t)
	logs := func() string {
		return fmt.Sprintf("client log:\n%s\nserver log:\n%s", client.log(t), server.log(t))
	}
	waitForRegisteredPaths(t, api.NewDaemonClient(serverSocket), 1, logs)

	ping := exec.Command("ip", "netns", "exec", clientNS, testExecutable(t), "-test.run=^TestHelperProcess$", "-test.v")
	ping.Env = append(os.Environ(),
		"MUP_INTEGRATION_HELPER=ping",
		"MUP_PING_SOURCE=10.210.1.1",
		"MUP_PING_DESTINATION=10.210.1.2",
		"MUP_PING_IDENTIFIER=5000",
	)
	if output, err := ping.CombinedOutput(); err != nil {
		t.Fatalf("ping with the server port as identifier: %v\n%s\n%s", err, output, logs())
	}
}

func startEchoTarget(t *testing.T, namespace, address string) *process {
	t.Helper()
	readyFile := filepath.Join(t.TempDir(), "target-ready")
	target := startHelper(t, namespace, "echo", readyFile, "MUP_TARGET_ADDRESS="+address)
	waitForFile(t, readyFile, 5*time.Second)
	return target
}

func exchange(t *testing.T, peerNS, destination string, count int, logs func() string) {
	t.Helper()
	exchangeFrom(t, peerNS, "10.210.3.2:0", destination, count, logs)
}

func exchangeFrom(t *testing.T, peerNS, local, destination string, count int, logs func() string) {
	t.Helper()
	peer := exec.Command("ip", "netns", "exec", peerNS, testExecutable(t), "-test.run=^TestHelperProcess$", "-test.v")
	peer.Env = append(os.Environ(),
		"MUP_INTEGRATION_HELPER=exchange",
		"MUP_PEER_LOCAL="+local,
		"MUP_PEER_DESTINATION="+destination,
		"MUP_PEER_COUNT="+strconv.Itoa(count),
	)
	if output, err := peer.CombinedOutput(); err != nil {
		t.Fatalf("exchange with %s: %v\n%s\n%s", destination, err, output, logs())
	}
}

func runInNamespace(t *testing.T, namespace string, arguments ...string) {
	t.Helper()
	command := exec.Command("ip", append([]string{"netns", "exec", namespace}, arguments...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%v in %s: %v\n%s", arguments, namespace, err, output)
	}
}

func waitFor(t *testing.T, timeout time.Duration, description string, logs func() string, condition func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		done, err := condition()
		if done {
			return
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s (last error: %v)\n%s", description, lastErr, logs())
}

func waitForRegisteredPaths(t *testing.T, server *api.DaemonClient, paths uint64, logs func() string) {
	t.Helper()
	waitFor(t, 15*time.Second, "the registration of the client paths", logs, func() (bool, error) {
		status, err := server.Status(context.Background())
		if err != nil || status.Server == nil {
			return false, err
		}
		return status.Server.Paths >= paths, nil
	})
}

func serverRoutes(t *testing.T, server *api.DaemonClient) []api.Route {
	t.Helper()
	peers, err := server.Peers(context.Background())
	if err != nil {
		t.Fatalf("list server routes: %v", err)
	}
	return peers.Routes
}

func setMode(t *testing.T, client *api.DaemonClient, mode string) {
	t.Helper()
	if err := client.SetMode(context.Background(), mode, 0); err != nil {
		t.Fatalf("set mode %s: %v", mode, err)
	}
}

func dropCount(drops []api.Drop, name string) uint64 {
	for _, drop := range drops {
		if drop.Name == name {
			return drop.Count
		}
	}
	return 0
}

func pathText(t *testing.T, client *api.DaemonClient) string {
	t.Helper()
	status, err := client.Status(context.Background())
	if err != nil || status.Client == nil {
		return fmt.Sprintf("paths: <%v>", err)
	}
	text := "paths:"
	for _, group := range status.Client.Groups {
		text += fmt.Sprintf(" [group %d mode %s]", group.ListenPort, group.Mode)
	}
	for _, path := range status.Client.Paths {
		text += fmt.Sprintf(" [%d %s:%d/%s healthy=%v in_use=%v misses=%d priority=%d]",
			path.ID, path.Server, path.Port, path.Transport, path.Healthy, path.InUse, path.Misses, path.Priority)
	}
	return text
}

func dropText(t *testing.T, daemon *api.DaemonClient) string {
	t.Helper()
	status, err := daemon.Status(context.Background())
	if err != nil {
		return fmt.Sprintf("drops: <%v>", err)
	}
	text := "drops:"
	for _, drop := range status.Drops {
		if drop.Count > 0 {
			text += fmt.Sprintf(" %s=%d", drop.Name, drop.Count)
		}
	}
	return text
}

func runEchoTargetHelper(t *testing.T) {
	connection, err := net.ListenUDP("udp4", mustUDPAddress(t, os.Getenv("MUP_TARGET_ADDRESS")))
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer connection.Close()
	if err := os.WriteFile(os.Getenv("MUP_TARGET_READY"), []byte("ready"), 0o600); err != nil {
		t.Fatalf("write target readiness: %v", err)
	}
	deadline := time.Now().Add(3 * time.Minute)
	buffer := make([]byte, 2048)
	for time.Now().Before(deadline) {
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		count, source, err := connection.ReadFromUDP(buffer)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			t.Fatalf("read target packet: %v", err)
		}
		payload := buffer[:count]
		assertWireGuardFixture(t, payload)
		if !bytes.Equal(payload[1:4], []byte{0, 0, 0}) {
			t.Fatalf("target received nonzero WireGuard reserved bytes: %x", payload[1:4])
		}
		if _, err := connection.WriteToUDP(payload, source); err != nil {
			t.Fatalf("reply from target: %v", err)
		}
	}
}

func runExchangeHelper(t *testing.T) {
	destination := mustUDPAddress(t, os.Getenv("MUP_PEER_DESTINATION"))
	connection, err := net.ListenUDP("udp4", mustUDPAddress(t, os.Getenv("MUP_PEER_LOCAL")))
	if err != nil {
		t.Fatalf("listen peer: %v", err)
	}
	defer connection.Close()
	count, err := strconv.Atoi(os.Getenv("MUP_PEER_COUNT"))
	if err != nil || count <= 0 {
		t.Fatalf("invalid MUP_PEER_COUNT %q", os.Getenv("MUP_PEER_COUNT"))
	}
	seed := uint64(time.Now().UnixNano())
	buffer := make([]byte, 2048)
	for message := 0; message < count; message++ {
		payload := wireGuardFixture()
		binary.LittleEndian.PutUint64(payload[8:16], seed+uint64(message))
		deadline := time.Now().Add(10 * time.Second)
		answered := false
		for attempt := uint32(0); !answered && time.Now().Before(deadline); attempt++ {
			binary.LittleEndian.PutUint32(payload[16:20], attempt)
			if _, err := connection.WriteToUDP(payload, destination); err != nil {
				t.Fatalf("send peer packet: %v", err)
			}
			retry := time.Now().Add(500 * time.Millisecond)
			for !answered {
				_ = connection.SetReadDeadline(retry)
				size, source, err := connection.ReadFromUDP(buffer)
				if err != nil {
					if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
						break
					}
					t.Fatalf("read peer reply: %v", err)
				}
				answered = source.IP.Equal(destination.IP) && source.Port == destination.Port &&
					bytes.Equal(buffer[:size], payload)
			}
		}
		if !answered {
			t.Fatalf("message %d of %d got no reply", message+1, count)
		}
	}
}

func runFloodHelper(t *testing.T) {
	destination := mustUDPAddress(t, os.Getenv("MUP_PEER_DESTINATION"))
	count, err := strconv.Atoi(os.Getenv("MUP_FLOOD_COUNT"))
	if err != nil || count <= 0 {
		t.Fatalf("invalid MUP_FLOOD_COUNT %q", os.Getenv("MUP_FLOOD_COUNT"))
	}
	for index := 0; index < count; index++ {
		connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(10, 210, 3, 2), Port: 20000 + index})
		if err != nil {
			t.Fatalf("listen flood source %d: %v", index, err)
		}
		payload := wireGuardFixture()
		binary.LittleEndian.PutUint64(payload[8:16], uint64(index))
		_, err = connection.WriteToUDP(payload, destination)
		_ = connection.Close()
		if err != nil {
			t.Fatalf("send flood packet %d: %v", index, err)
		}
		if index%50 == 49 {
			time.Sleep(5 * time.Millisecond)
		}
	}
	time.Sleep(300 * time.Millisecond)
}

func runPingHelper(t *testing.T) {
	identifier, err := strconv.ParseUint(os.Getenv("MUP_PING_IDENTIFIER"), 10, 16)
	if err != nil {
		t.Fatalf("invalid MUP_PING_IDENTIFIER: %v", err)
	}
	source := net.ParseIP(os.Getenv("MUP_PING_SOURCE"))
	destination := net.ParseIP(os.Getenv("MUP_PING_DESTINATION"))
	connection, err := net.ListenIP("ip4:icmp", &net.IPAddr{IP: source})
	if err != nil {
		t.Fatalf("open ICMP socket: %v", err)
	}
	defer connection.Close()

	request := make([]byte, 8+32)
	request[0] = 8
	binary.BigEndian.PutUint16(request[4:6], uint16(identifier))
	binary.BigEndian.PutUint16(request[6:8], 1)
	for index := 8; index < len(request); index++ {
		request[index] = 0x55
	}
	binary.BigEndian.PutUint16(request[2:4], icmpChecksum(request))

	deadline := time.Now().Add(5 * time.Second)
	buffer := make([]byte, 2048)
	for time.Now().Before(deadline) {
		if _, err := connection.WriteToIP(request, &net.IPAddr{IP: destination}); err != nil {
			t.Fatalf("send Echo Request: %v", err)
		}
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		for {
			size, from, err := connection.ReadFromIP(buffer)
			if err != nil {
				break
			}
			if size >= 8 && from.IP.Equal(destination) && buffer[0] == 0 &&
				binary.BigEndian.Uint16(buffer[4:6]) == uint16(identifier) &&
				bytes.Equal(buffer[8:size], request[8:]) {
				return
			}
		}
	}
	t.Fatal("no Echo Reply arrived")
}

func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(data); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[index : index+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
