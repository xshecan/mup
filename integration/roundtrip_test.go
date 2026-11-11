package integration

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/xshecan/mup/protocol"
)

const privilegedTestsEnvironment = "MUP_PRIVILEGED_TESTS"

func requirePrivilegedLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("network-namespace qualification requires Linux")
	}
	if os.Getenv(privilegedTestsEnvironment) != "1" {
		t.Skip("set MUP_PRIVILEGED_TESTS=1 to run privileged namespace qualification")
	}
	if os.Geteuid() != 0 {
		t.Skip("privileged namespace qualification requires root")
	}
	for _, command := range []string{"ip", "mount", "sysctl", "unshare"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("required command %q is unavailable", command)
		}
	}
}

func buildDaemon(t *testing.T) string {
	t.Helper()
	binaryPath := filepath.Join(t.TempDir(), "mup")
	build := exec.Command("go", "build", "-o", binaryPath, "../cmd/mup")
	build.Dir = filepath.Join("..", "integration")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build MUP: %v\n%s", err, output)
	}
	return binaryPath
}

func addNamespace(t *testing.T, namespace string) {
	t.Helper()
	runIP(t, "netns", "add", namespace)
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "del", namespace).Run()
	})
	runIP(t, "-n", namespace, "link", "set", "lo", "up")
}

func TestPrivilegedRoundTrip(t *testing.T) {
	requirePrivilegedLinux(t)
	binaryPath := buildDaemon(t)

	tests := []struct {
		name      string
		transport string
		reflected bool
	}{
		{name: "udp-direct", transport: "udp"},
		{name: "udp-reflected", transport: "udp", reflected: true},
		{name: "icmp-direct", transport: "icmp"},
		{name: "icmp-reflected", transport: "icmp", reflected: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runRoundTrip(t, binaryPath, test.transport, test.reflected)
		})
	}
}

func TestPrivilegedTwoTargets(t *testing.T) {
	requirePrivilegedLinux(t)
	binaryPath := buildDaemon(t)

	suffix := strconv.FormatInt(time.Now().UnixNano()%1_000_000, 10)
	clientNS, peerNS := "mup-client-"+suffix, "mup-peer-"+suffix
	firstServerNS, firstTargetNS := "mup-s1-"+suffix, "mup-t1-"+suffix
	secondServerNS, secondTargetNS := "mup-s2-"+suffix, "mup-t2-"+suffix
	for _, namespace := range []string{clientNS, peerNS, firstServerNS, firstTargetNS, secondServerNS, secondTargetNS} {
		addNamespace(t, namespace)
	}

	linkPair(t, "cp"+suffix, clientNS, "pc"+suffix, peerNS)
	addressLink(t, clientNS, "cp"+suffix, "10.210.3.1/24")
	addressLink(t, peerNS, "pc"+suffix, "10.210.3.2/24")

	// The advertised IP is on the first link, so the second server needs a route
	// to it.
	linkPair(t, "c1"+suffix, clientNS, "s1"+suffix, firstServerNS)
	addressLink(t, clientNS, "c1"+suffix, "10.210.1.1/24")
	addressLink(t, firstServerNS, "s1"+suffix, "10.210.1.2/24")
	linkPair(t, "c2"+suffix, clientNS, "s2"+suffix, secondServerNS)
	addressLink(t, clientNS, "c2"+suffix, "10.210.5.1/24")
	addressLink(t, secondServerNS, "s2"+suffix, "10.210.5.2/24")
	runIP(t, "-n", secondServerNS, "route", "add", "10.210.1.1/32", "via", "10.210.5.1")

	linkPair(t, "a1"+suffix, firstServerNS, "t1"+suffix, firstTargetNS)
	addressLink(t, firstServerNS, "a1"+suffix, "10.210.2.1/24")
	addressLink(t, firstTargetNS, "t1"+suffix, "10.210.2.2/24")
	linkPair(t, "a2"+suffix, secondServerNS, "t2"+suffix, secondTargetNS)
	addressLink(t, secondServerNS, "a2"+suffix, "10.210.6.1/24")
	addressLink(t, secondTargetNS, "t2"+suffix, "10.210.6.2/24")

	firstReady := filepath.Join(t.TempDir(), "first-target-ready")
	firstTarget := startHelper(t, firstTargetNS, "target", firstReady, "MUP_TARGET_ADDRESS=10.210.2.2:51820")
	defer firstTarget.stop(t)
	secondReady := filepath.Join(t.TempDir(), "second-target-ready")
	secondTarget := startHelper(t, secondTargetNS, "target", secondReady, "MUP_TARGET_ADDRESS=10.210.6.2:51820")
	defer secondTarget.stop(t)
	waitForFile(t, firstReady, 5*time.Second)
	waitForFile(t, secondReady, 5*time.Second)

	firstServer := startDaemon(t, firstServerNS, binaryPath, "server", "-p", "5000", "-r", "10.210.2.2:51820")
	defer firstServer.stop(t)
	secondServer := startDaemon(t, secondServerNS, binaryPath, "server", "-p", "6000", "-r", "10.210.6.2:51820")
	defer secondServer.stop(t)

	directory := t.TempDir()
	configuration := filepath.Join(directory, "client.yaml")
	content := fmt.Sprintf(`client:
  advertise: 10.210.1.1
  control_socket: %s
  groups:
    - port: 51820
      paths: [10.210.1.2:5000/udp]
    - port: 51821
      paths: [10.210.5.2:6000/icmp]
`, filepath.Join(directory, "mup.sock"))
	if err := os.WriteFile(configuration, []byte(content), 0o600); err != nil {
		t.Fatalf("write client configuration: %v", err)
	}
	client := startNamespaced(t, clientNS, binaryPath, "--config", configuration)
	defer client.stop(t)
	time.Sleep(1500 * time.Millisecond)

	// Each target helper exits after one packet, so a packet for the wrong target
	// makes the wait of the other target fail.
	sendThrough := func(destination string, target *process) {
		t.Helper()
		peer := exec.Command("ip", "netns", "exec", peerNS, testExecutable(t), "-test.run=^TestHelperProcess$", "-test.v")
		peer.Env = append(os.Environ(), "MUP_INTEGRATION_HELPER=peer", "MUP_PEER_DESTINATION="+destination)
		if output, err := peer.CombinedOutput(); err != nil {
			t.Fatalf("peer to %s: %v\n%s\nclient log:\n%s", destination, err, output, client.log(t))
		}
		if err := target.wait(5 * time.Second); err != nil {
			t.Fatalf("target of %s: %v\n%s", destination, err, target.log(t))
		}
	}
	sendThrough("10.210.3.1:51820", firstTarget)
	sendThrough("10.210.3.1:51821", secondTarget)
}

func TestHelperProcess(t *testing.T) {
	switch os.Getenv("MUP_INTEGRATION_HELPER") {
	case "":
		t.Skip("integration helper only")
	case "target":
		runTargetHelper(t)
	case "peer":
		runPeerHelper(t)
	default:
		t.Fatalf("unknown integration helper %q", os.Getenv("MUP_INTEGRATION_HELPER"))
	}
}

func runRoundTrip(t *testing.T, binaryPath, transport string, reflected bool) {
	t.Helper()

	suffix := strconv.FormatInt(time.Now().UnixNano()%1_000_000, 10)
	clientNS := "mup-client-" + suffix
	serverNS := "mup-server-" + suffix
	targetNS := "mup-target-" + suffix
	reflectorNS := "mup-reflector-" + suffix
	namespaces := []string{clientNS, serverNS, targetNS}
	if reflected && transport == "icmp" {
		namespaces = append(namespaces, reflectorNS)
	}
	for _, namespace := range namespaces {
		addNamespace(t, namespace)
	}

	linkPair(t, "mc"+suffix, clientNS, "ms"+suffix, serverNS)
	addressLink(t, clientNS, "mc"+suffix, "10.210.1.1/24")
	addressLink(t, serverNS, "ms"+suffix, "10.210.1.2/24")

	linkPair(t, "st"+suffix, serverNS, "ts"+suffix, targetNS)
	addressLink(t, serverNS, "st"+suffix, "10.210.2.1/24")
	addressLink(t, targetNS, "ts"+suffix, "10.210.2.2/24")

	peerNS := "mup-peer-" + suffix
	addNamespace(t, peerNS)
	linkPair(t, "cp"+suffix, clientNS, "pc"+suffix, peerNS)
	addressLink(t, clientNS, "cp"+suffix, "10.210.3.1/24")
	addressLink(t, peerNS, "pc"+suffix, "10.210.3.2/24")

	returnIP := ""
	if reflected {
		returnIP = "10.210.4.2"
	}
	if reflected && transport == "icmp" {
		linkPair(t, "sr"+suffix, serverNS, "rs"+suffix, reflectorNS)
		addressLink(t, serverNS, "sr"+suffix, "10.210.4.1/24")
		addressLink(t, reflectorNS, "rs"+suffix, "10.210.4.2/24")
		runIP(t, "-n", reflectorNS, "route", "add", "default", "via", "10.210.4.1")
		runIP(t, "netns", "exec", serverNS, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
	}

	readyFile := filepath.Join(t.TempDir(), "target-ready")
	target := startHelper(t, targetNS, "target", readyFile)
	defer target.stop(t)
	waitForFile(t, readyFile, 5*time.Second)

	server := startDaemon(
		t,
		serverNS,
		binaryPath,
		"server", "-p", "5000", "-r", "10.210.2.2:51820",
	)
	defer server.stop(t)

	clientArguments := []string{
		"client", "-p", "51820",
		"-u", "10.210.1.2:5000/" + transport,
		"-s", "10.210.1.1",
	}
	if returnIP != "" {
		clientArguments = append(clientArguments, "-r", returnIP)
	}
	client := startDaemon(t, clientNS, binaryPath, clientArguments...)
	defer client.stop(t)

	time.Sleep(1500 * time.Millisecond)
	peer := exec.Command(
		"ip", "netns", "exec", peerNS,
		testExecutable(t), "-test.run=^TestHelperProcess$", "-test.v",
	)
	peer.Env = append(os.Environ(),
		"MUP_INTEGRATION_HELPER=peer",
		"MUP_PEER_DESTINATION=10.210.3.1:51820",
	)
	if output, err := peer.CombinedOutput(); err != nil {
		t.Fatalf(
			"peer round trip: %v\n%s\nserver log:\n%s\nclient log:\n%s",
			err,
			output,
			server.log(t),
			client.log(t),
		)
	}
	if err := target.wait(5 * time.Second); err != nil {
		t.Fatalf("target helper: %v\n%s", err, target.log(t))
	}
}

type process struct {
	command *exec.Cmd
	logPath string
	done    chan error
}

// startDaemon gives the daemon a private control socket, which keeps test
// daemons away from /run/mup.
func startDaemon(t *testing.T, namespace, binaryPath string, arguments ...string) *process {
	t.Helper()
	arguments = append(arguments, "--control-socket", filepath.Join(t.TempDir(), "mup.sock"))
	return startNamespaced(t, namespace, binaryPath, arguments...)
}

func startNamespaced(t *testing.T, namespace, binaryPath string, arguments ...string) *process {
	t.Helper()
	commandArguments := []string{
		"netns", "exec", namespace,
		"unshare", "--mount", "--propagation", "private",
		"sh", "-ceu",
		"mkdir -p /sys/fs/bpf; mount -t bpf bpf /sys/fs/bpf; exec \"$@\"",
		"mup-mount", binaryPath,
	}
	commandArguments = append(commandArguments, arguments...)
	return startProcess(t, exec.Command("ip", commandArguments...))
}

func startHelper(t *testing.T, namespace, mode, readyFile string, environment ...string) *process {
	t.Helper()
	command := exec.Command(
		"ip", "netns", "exec", namespace,
		testExecutable(t), "-test.run=^TestHelperProcess$", "-test.v",
	)
	command.Env = append(os.Environ(),
		"MUP_INTEGRATION_HELPER="+mode,
		"MUP_TARGET_READY="+readyFile,
	)
	command.Env = append(command.Env, environment...)
	return startProcess(t, command)
}

func startProcess(t *testing.T, command *exec.Cmd) *process {
	t.Helper()
	logFile, err := os.CreateTemp(t.TempDir(), "process-*.log")
	if err != nil {
		t.Fatalf("create process log: %v", err)
	}
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		t.Fatalf("start %s: %v", strings.Join(command.Args, " "), err)
	}
	_ = logFile.Close()
	process := &process{command: command, logPath: logFile.Name(), done: make(chan error, 1)}
	go func() {
		process.done <- command.Wait()
	}()
	return process
}

func (p *process) stop(t *testing.T) {
	t.Helper()
	if p.command.ProcessState != nil && p.command.ProcessState.Exited() {
		return
	}
	select {
	case <-p.done:
		return
	default:
	}
	_ = p.command.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
		_ = p.command.Process.Kill()
		<-p.done
	}
}

func testExecutable(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("locate integration test executable: %v", err)
	}
	return executable
}

func (p *process) wait(timeout time.Duration) error {
	select {
	case err := <-p.done:
		return err
	case <-time.After(timeout):
		_ = p.command.Process.Kill()
		<-p.done
		return errors.New("process timeout")
	}
}

func (p *process) log(t *testing.T) string {
	t.Helper()
	content, err := os.ReadFile(p.logPath)
	if err != nil {
		return fmt.Sprintf("<read log: %v>", err)
	}
	return string(content)
}

func runTargetHelper(t *testing.T) {
	address := os.Getenv("MUP_TARGET_ADDRESS")
	if address == "" {
		address = "10.210.2.2:51820"
	}
	connection, err := net.ListenUDP("udp4", mustUDPAddress(t, address))
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer connection.Close()
	if err := os.WriteFile(os.Getenv("MUP_TARGET_READY"), []byte("ready"), 0o600); err != nil {
		t.Fatalf("write target readiness: %v", err)
	}
	if err := connection.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set target deadline: %v", err)
	}
	buffer := make([]byte, 2048)
	count, source, err := connection.ReadFromUDP(buffer)
	if err != nil {
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

func runPeerHelper(t *testing.T) {
	destination := mustUDPAddress(t, os.Getenv("MUP_PEER_DESTINATION"))
	connection, err := net.ListenUDP("udp4", mustUDPAddress(t, "10.210.3.2:0"))
	if err != nil {
		t.Fatalf("listen peer: %v", err)
	}
	defer connection.Close()
	payload := wireGuardFixture()
	deadline := time.Now().Add(12 * time.Second)
	buffer := make([]byte, 2048)
	for time.Now().Before(deadline) {
		if _, err := connection.WriteToUDP(payload, destination); err != nil {
			t.Fatalf("send peer packet: %v", err)
		}
		_ = connection.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		count, source, err := connection.ReadFromUDP(buffer)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			t.Fatalf("read peer reply: %v", err)
		}
		if !source.IP.Equal(destination.IP) || source.Port != destination.Port {
			continue
		}
		if !bytes.Equal(buffer[:count], payload) {
			t.Fatalf("peer payload changed:\ngot  %x\nwant %x", buffer[:count], payload)
		}
		if !bytes.Equal(buffer[1:4], []byte{0, 0, 0}) {
			t.Fatalf("peer received nonzero WireGuard reserved bytes: %x", buffer[1:4])
		}
		return
	}
	t.Fatal("peer did not receive a round-trip response")
}

func wireGuardFixture() []byte {
	payload := make([]byte, protocol.HandshakeInitiationLength)
	payload[0] = protocol.MessageHandshakeInitiation
	binary.LittleEndian.PutUint32(payload[4:8], 0x12345678)
	for index := 8; index < len(payload); index++ {
		payload[index] = byte(index)
	}
	return payload
}

func assertWireGuardFixture(t *testing.T, payload []byte) {
	t.Helper()
	if len(payload) != protocol.HandshakeInitiationLength ||
		payload[0] != protocol.MessageHandshakeInitiation {
		t.Fatalf("invalid WireGuard fixture: length=%d type=%d", len(payload), payload[0])
	}
}

func mustUDPAddress(t *testing.T, address string) *net.UDPAddr {
	t.Helper()
	result, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		t.Fatalf("resolve UDP address %q: %v", address, err)
	}
	return result
}

func linkPair(t *testing.T, first, firstNS, second, secondNS string) {
	t.Helper()
	runIP(t, "link", "add", first, "type", "veth", "peer", "name", second)
	runIP(t, "link", "set", first, "netns", firstNS)
	runIP(t, "link", "set", second, "netns", secondNS)
}

func addressLink(t *testing.T, namespace, link, address string) {
	t.Helper()
	runIP(t, "-n", namespace, "addr", "add", address, "dev", link)
	runIP(t, "-n", namespace, "link", "set", link, "up")
}

func runIP(t *testing.T, arguments ...string) {
	t.Helper()
	command := exec.Command("ip", arguments...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v\n%s", strings.Join(arguments, " "), err, output)
	}
}

func waitForFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s", path)
		case <-ticker.C:
		}
	}
}
