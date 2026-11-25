package integration

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xshecan/mup/api"
)

const (
	// measureHelperEnvironment selects the traffic helper in the test binary.
	measureHelperEnvironment = "MUP_MEASURE_HELPER"
	// measureTrafficDuration is how long the helper sends in each phase.
	measureTrafficDuration = 15 * time.Second
	// measureReadFrom is when the assertions start to read. The loss windows are
	// 10 seconds, so a read at 12 seconds sees only the phase of the rule.
	measureReadFrom = 12 * time.Second
	// measureLossMatch selects the data packets of a path on the switch. A control
	// frame is exactly 76 bytes long (20 byte IP header, 8 byte UDP header, 48 byte
	// frame), and a data packet is longer, so the rule never drops a control frame.
	// Replace it with "udp length != 56" to match the UDP length instead.
	measureLossMatch = "ip length > 76"
	// measureLossNumber drops one packet in four. Replace it to change the loss.
	measureLossNumber = "numgen inc mod 4 == 0"
)

// TestPrivilegedMeasuresLossAndRTT runs one group with separate ingress and
// egress paths over plain UDP and checks the measurement of each path in three
// phases. A clean path shows no loss, a switch rule that drops one data packet in
// four on the ingress path shows about 25 percent loss on that path only, and the
// same rule on the egress path shows about 25 percent loss on the egress path at
// both ends. The rules never touch a control frame, so the probe loss stays low.
func TestPrivilegedMeasuresLossAndRTT(t *testing.T) {
	requirePrivilegedLinux(t)
	binaryPath := buildDaemon(t)

	// The prefix 10.230 belongs to this test. The client is .1.1, the server .1.2,
	// the peer behind the client .3.2, and the echo target behind the server .2.2.
	prefix := "10.230"
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
	clientAddress, serverAddress := prefix+".1.1", prefix+".1.2"
	addressLink(t, clientNS, "mc"+suffix, clientAddress+"/24")
	addressLink(t, serverNS, "ms"+suffix, serverAddress+"/24")
	linkPair(t, "st"+suffix, serverNS, "ts"+suffix, targetNS)
	addressLink(t, serverNS, "st"+suffix, prefix+".2.1/24")
	addressLink(t, targetNS, "ts"+suffix, prefix+".2.2/24")
	linkPair(t, "cp"+suffix, clientNS, "pc"+suffix, peerNS)
	addressLink(t, clientNS, "cp"+suffix, prefix+".3.1/24")
	addressLink(t, peerNS, "pc"+suffix, prefix+".3.2/24")

	// The switch has two chains. The chain forward holds two counting rules that
	// see every data packet of each direction. The chain loss starts empty. A phase
	// adds one drop rule to it, and the next phase flushes it. Both chains hook
	// into forward, so a drop in either chain drops the packet.
	clientPort, serverPort := "bmc"+suffix, "bms"+suffix
	ingressMatch := fmt.Sprintf("iifname %s ip daddr %s udp dport 5000 %s", clientPort, serverAddress, measureLossMatch)
	egressMatch := fmt.Sprintf("iifname %s ip daddr %s udp sport 5001 %s", serverPort, clientAddress, measureLossMatch)
	runInNamespace(t, switchNS, "nft", "add", "table", "bridge", "mup")
	runInNamespace(t, switchNS, "nft", "add", "chain", "bridge", "mup", "forward", "{ type filter hook forward priority 0 ; }")
	runInNamespace(t, switchNS, "nft", "add", "chain", "bridge", "mup", "loss", "{ type filter hook forward priority 10 ; }")
	addRule := func(chain, comment, text string) {
		t.Helper()
		arguments := append([]string{"nft", "add", "rule", "bridge", "mup", chain}, strings.Fields(text)...)
		arguments = append(arguments, "comment", `"`+comment+`"`)
		runInNamespace(t, switchNS, arguments...)
	}
	addRule("forward", "ingress_data", ingressMatch+" counter")
	addRule("forward", "egress_data", egressMatch+" counter")

	target := startEchoTarget(t, targetNS, prefix+".2.2:51820")
	defer target.stop(t)

	directory := t.TempDir()
	serverSocket := filepath.Join(directory, "server.sock")
	clientSocket := filepath.Join(directory, "client.sock")
	server := startNamespaced(t, serverNS, binaryPath, "server", "-p", "5000-5009", "-r", prefix+".2.2:51820", "--control-socket", serverSocket)
	defer server.stop(t)

	configuration := filepath.Join(directory, "client.yaml")
	content := fmt.Sprintf(`client:
  advertise: %s
  control_socket: %s
  servers:
    - port: 51820
      ingress:
        routes: ["%s:5000/udp"]
      egress:
        routes: ["%s:5001/udp"]
`, clientAddress, clientSocket, serverAddress, serverAddress)
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
		return fmt.Sprintf("%s\n%s\n%s\nclient %s\nserver %s\nswitch:\n%s\n%s",
			measuredPathText(clientAPI), measuredServerText(serverAPI), measuredMemberText(clientAPI, serverAPI),
			dropText(t, clientAPI), dropText(t, serverAPI), switchCounters(switchNS), logs())
	}

	// clientPath returns the path of a direction. The group has one of each.
	clientPath := func(direction string) (api.Path, error) {
		paths, err := clientAPI.Paths(context.Background())
		if err != nil {
			return api.Path{}, err
		}
		for _, path := range paths {
			if path.Direction == direction {
				return path, nil
			}
		}
		return api.Path{}, fmt.Errorf("the client has no %s path", direction)
	}
	// serverEgress returns the egress path that the server holds for the client.
	serverEgress := func() (api.EgressPath, error) {
		clients, err := serverAPI.Clients(context.Background())
		if err != nil {
			return api.EgressPath{}, err
		}
		for _, registered := range clients {
			for _, group := range registered.Egresses {
				if len(group.Paths) > 0 {
					return group.Paths[0], nil
				}
			}
		}
		return api.EgressPath{}, fmt.Errorf("the server holds no egress path of the client")
	}

	waitFor(t, 30*time.Second, "both client paths to become healthy", state, func() (bool, error) {
		for _, direction := range []string{"ingress", "egress"} {
			path, err := clientPath(direction)
			if err != nil || !path.Healthy {
				return false, err
			}
		}
		return true, nil
	})

	// runPhase sends data for measureTrafficDuration and calls check from
	// measureReadFrom on, every half second, until it returns no problem. The
	// phase fails with the last problem when the traffic ends first.
	runPhase := func(name string, check func() string) {
		t.Helper()
		helper := startTrafficHelper(t, peerNS, prefix+".3.2:0", prefix+".3.1:51820", measureTrafficDuration)
		start := time.Now()
		time.Sleep(measureReadFrom)
		problem := "no check ran"
		for time.Since(start) < measureTrafficDuration-500*time.Millisecond {
			if problem = check(); problem == "" {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		output, err := helper.finish()
		if problem != "" {
			t.Fatalf("%s: %s\ntraffic: %s %v\n%s", name, problem, output, err, state())
		}
		if err != nil {
			t.Fatalf("%s: traffic helper: %v\n%s\n%s", name, err, output, state())
		}
		t.Logf("%s: traffic %s", name, output)
	}

	// Phase 1: a clean path. Every path has a loss below 2 percent, a probe loss
	// below 10 percent, a round trip time, and a rate.
	runPhase("clean path", func() string {
		for _, direction := range []string{"ingress", "egress"} {
			path, err := clientPath(direction)
			if err != nil {
				return err.Error()
			}
			if problem := checkMeasurement("client "+direction, path.Measurement, 0, 2, true); problem != "" {
				return problem
			}
		}
		egress, err := serverEgress()
		if err != nil {
			return err.Error()
		}
		return checkMeasurement("server egress", egress.Measurement, 0, 2, false)
	})
	// The member lists can be empty or hold the direct server address. The test
	// only needs the request to work on both roles.
	if _, err := clientAPI.Members(context.Background()); err != nil {
		t.Fatalf("client members: %v\n%s", err, state())
	}
	if _, err := serverAPI.Members(context.Background()); err != nil {
		t.Fatalf("server members: %v\n%s", err, state())
	}

	// Phase 2: the switch drops one in four data packets from the client to the
	// server port 5000. The ingress path shows the loss, and its probes get through.
	addRule("loss", "ingress_loss", ingressMatch+" "+measureLossNumber+" counter drop")
	runPhase("ingress loss", func() string {
		path, err := clientPath("ingress")
		if err != nil {
			return err.Error()
		}
		return checkMeasurement("client ingress", path.Measurement, 15, 35, true)
	})

	// Phase 3: the switch drops one in four data packets from the server port 5001
	// to the client. The client and the server both show the loss on the egress path.
	runInNamespace(t, switchNS, "nft", "flush", "chain", "bridge", "mup", "loss")
	addRule("loss", "egress_loss", egressMatch+" "+measureLossNumber+" counter drop")
	runPhase("egress loss", func() string {
		path, err := clientPath("egress")
		if err != nil {
			return err.Error()
		}
		if problem := checkMeasurement("client egress", path.Measurement, 15, 35, true); problem != "" {
			return problem
		}
		egress, err := serverEgress()
		if err != nil {
			return err.Error()
		}
		return checkMeasurement("server egress", egress.Measurement, 15, 35, false)
	})
}

// checkMeasurement returns a problem text, or an empty text when the loss is in
// [lowest, highest) and, for a client path, the probe loss is below 10 percent and
// the round trip time and the rate are above zero. The server path has no rate
// check of its own beyond the rate and the round trip time, so it takes the same
// checks when full is true.
func checkMeasurement(name string, measurement api.Measurement, lowest, highest float64, full bool) string {
	if measurement.LossPercent == nil {
		return name + " has no LossPercent"
	}
	loss := *measurement.LossPercent
	if loss < lowest || loss >= highest {
		return fmt.Sprintf("%s LossPercent = %.1f, want %.0f to %.0f", name, loss, lowest, highest)
	}
	if !full {
		return ""
	}
	// Only an ingress path has a probe loss on the client, because the client
	// sends the MEASURE frames of that direction. The server probes the egress.
	if measurement.ProbeLossPercent == nil {
		if strings.Contains(name, "ingress") {
			return name + " has no ProbeLossPercent"
		}
	} else if *measurement.ProbeLossPercent >= 10 {
		return fmt.Sprintf("%s ProbeLossPercent = %.1f, want below 10", name, *measurement.ProbeLossPercent)
	}
	if measurement.RTTAvgSeconds <= 0 {
		return fmt.Sprintf("%s RTTAvgSeconds = %v, want above 0", name, measurement.RTTAvgSeconds)
	}
	if measurement.RateBitsPerSecond <= 0 || measurement.RatePacketsPerSecond <= 0 {
		return fmt.Sprintf("%s rate = %v bit/s %v packet/s, want above 0", name, measurement.RateBitsPerSecond, measurement.RatePacketsPerSecond)
	}
	return ""
}

// measurementText prints the measurement fields of a path.
func measurementText(measurement api.Measurement) string {
	value := func(percent *float64) string {
		if percent == nil {
			return "nil"
		}
		return strconv.FormatFloat(*percent, 'f', 1, 64)
	}
	return fmt.Sprintf("loss=%s loss60=%s probe_loss=%s rtt_avg=%.4f jitter=%.4f rate=%.0fbit/s %.0fpps",
		value(measurement.LossPercent), value(measurement.LossLongPercent), value(measurement.ProbeLossPercent),
		measurement.RTTAvgSeconds, measurement.RTTJitterSeconds, measurement.RateBitsPerSecond, measurement.RatePacketsPerSecond)
}

// measuredPathText lists the paths of the client with their measurement.
func measuredPathText(client *api.DaemonClient) string {
	paths, err := client.Paths(context.Background())
	if err != nil {
		return fmt.Sprintf("client paths: <%v>", err)
	}
	text := "client paths:"
	for _, path := range paths {
		text += fmt.Sprintf(" [%d %s %s:%d/%s healthy=%v rtt=%.4f %s]",
			path.ID, path.Direction, path.Server, path.Port, path.Transport, path.Healthy, path.RTTSeconds, measurementText(path.Measurement))
	}
	return text
}

// measuredServerText lists the egress paths that the server holds, with their
// measurement.
func measuredServerText(server *api.DaemonClient) string {
	clients, err := server.Clients(context.Background())
	if err != nil {
		return fmt.Sprintf("server clients: <%v>", err)
	}
	text := "server egress paths:"
	for _, registered := range clients {
		for _, group := range registered.Egresses {
			for _, path := range group.Paths {
				text += fmt.Sprintf(" [%s %d %s:%d healthy=%v %d/%d %s]",
					registered.AdvertisedIP, path.ID, path.Transport, path.Port, path.Healthy, path.HealthyMembers, path.Members, measurementText(path.Measurement))
			}
		}
	}
	return text
}

// measuredMemberText lists the members that each role reports.
func measuredMemberText(client, server *api.DaemonClient) string {
	text := "members:"
	for _, role := range []struct {
		name   string
		daemon *api.DaemonClient
	}{{"client", client}, {"server", server}} {
		list, err := role.daemon.Members(context.Background())
		if err != nil {
			text += fmt.Sprintf(" %s <%v>", role.name, err)
			continue
		}
		for _, member := range list.Members {
			text += fmt.Sprintf(" [%s %s %d %s healthy=%v %s]", role.name, member.Direction, member.PathID, member.Address, member.Healthy, measurementText(member.Measurement))
		}
	}
	return text
}

// trafficHelper is a running traffic process in the namespace of the peer.
type trafficHelper struct {
	command *exec.Cmd
	output  *strings.Builder
}

// startTrafficHelper runs the test binary in the namespace of the peer. The
// helper sends about 100 WireGuard messages per second to destination for the
// duration, counts the echoes, and prints both counts. Unlike exchangeFrom, it
// does not wait for an echo before the next message, so a lost packet costs no
// time.
func startTrafficHelper(t *testing.T, namespace, local, destination string, duration time.Duration) *trafficHelper {
	t.Helper()
	command := exec.Command("ip", "netns", "exec", namespace, testExecutable(t), "-test.run=^TestMeasureTrafficHelper$", "-test.v")
	command.Env = append(os.Environ(),
		measureHelperEnvironment+"=1",
		"MUP_PEER_LOCAL="+local,
		"MUP_PEER_DESTINATION="+destination,
		"MUP_TRAFFIC_SECONDS="+strconv.Itoa(int(duration/time.Second)),
	)
	helper := &trafficHelper{command: command, output: &strings.Builder{}}
	command.Stdout, command.Stderr = helper.output, helper.output
	if err := command.Start(); err != nil {
		t.Fatalf("start the traffic helper: %v", err)
	}
	t.Cleanup(func() {
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	return helper
}

// finish waits for the helper and returns the line with its counts.
func (h *trafficHelper) finish() (string, error) {
	err := h.command.Wait()
	for _, line := range strings.Split(h.output.String(), "\n") {
		if strings.Contains(line, "traffic sent=") {
			return strings.TrimSpace(line), err
		}
	}
	return h.output.String(), err
}

// TestMeasureTrafficHelper is the traffic process. It does nothing in a normal
// test run.
func TestMeasureTrafficHelper(t *testing.T) {
	if os.Getenv(measureHelperEnvironment) != "1" {
		t.Skip("traffic helper only")
	}
	destination := mustUDPAddress(t, os.Getenv("MUP_PEER_DESTINATION"))
	connection, err := net.ListenUDP("udp4", mustUDPAddress(t, os.Getenv("MUP_PEER_LOCAL")))
	if err != nil {
		t.Fatalf("listen peer: %v", err)
	}
	defer connection.Close()
	seconds, err := strconv.Atoi(os.Getenv("MUP_TRAFFIC_SECONDS"))
	if err != nil || seconds <= 0 {
		t.Fatalf("invalid MUP_TRAFFIC_SECONDS %q", os.Getenv("MUP_TRAFFIC_SECONDS"))
	}

	var echoes atomic.Int64
	var stop atomic.Bool
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		buffer := make([]byte, 2048)
		for !stop.Load() {
			_ = connection.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			if _, _, err := connection.ReadFromUDP(buffer); err == nil {
				echoes.Add(1)
			}
		}
	}()

	seed := uint64(time.Now().UnixNano())
	sent := 0
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	end := time.Now().Add(time.Duration(seconds) * time.Second)
	for time.Now().Before(end) {
		<-ticker.C
		payload := wireGuardFixture()
		binary.LittleEndian.PutUint64(payload[8:16], seed+uint64(sent))
		if _, err := connection.WriteToUDP(payload, destination); err != nil {
			t.Fatalf("send peer packet: %v", err)
		}
		sent++
	}
	// The reader runs a little longer to collect the late echoes.
	time.Sleep(500 * time.Millisecond)
	stop.Store(true)
	<-finished
	fmt.Printf("traffic sent=%d echoed=%d\n", sent, echoes.Load())
}
