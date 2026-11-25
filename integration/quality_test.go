package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xshecan/mup/api"
)

const (
	// qualityLossMatch and qualityLossNumber have the meaning of the constants of
	// measure_test.go. The rule drops one data packet in four and never a
	// control frame.
	qualityLossMatch  = measureLossMatch
	qualityLossNumber = measureLossNumber
	// qualityDelay is the one way delay that the latency test adds to the slow
	// link.
	qualityDelay = 40 * time.Millisecond
	// qualityMinimumEchoes is the share of echoes that a clean run must reach.
	qualityMinimumEchoes = 0.95
)

// qualityTopology is the network of the loss test. The client is .1.1, the server
// .1.2, the peer behind the client .3.2, and the echo target behind the server
// .2.2. A switch namespace with a bridge sits between the client and the server.
type qualityTopology struct {
	prefix                                         string
	clientNS, serverNS, targetNS, switchNS, peerNS string
	clientAddress, serverAddress                   string
	clientPort, serverPort                         string
}

// TestPrivilegedToleranceMovesTheData runs one group with separate directions and
// a loss tolerance of 5 percent on both. Two ingress routes go to the server ports 5000
// and 5001, and two egress routes to the ports 5002 and 5003. The switch drops
// one data packet in four on the first ingress route, and the client must degrade
// that path and move the data to the second. Then the switch drops the same share
// on the first egress route, and the server must degrade that path and reply on
// the second. A control frame is never dropped, so the degraded paths stay healthy.
func TestPrivilegedToleranceMovesTheData(t *testing.T) {
	requirePrivilegedLinux(t)
	binaryPath := buildDaemon(t)

	// The prefix 10.231 belongs to this test.
	suffix := strconv.FormatInt(time.Now().UnixNano()%1_000_000, 10)
	topology := qualityTopology{
		prefix:   "10.231",
		clientNS: "mup-client-" + suffix, serverNS: "mup-server-" + suffix, targetNS: "mup-target-" + suffix,
		switchNS: "mup-switch-" + suffix, peerNS: "mup-peer-" + suffix,
		clientPort: "bmc" + suffix, serverPort: "bms" + suffix,
	}
	topology.clientAddress, topology.serverAddress = topology.prefix+".1.1", topology.prefix+".1.2"
	for _, namespace := range []string{topology.clientNS, topology.serverNS, topology.targetNS, topology.switchNS, topology.peerNS} {
		addNamespace(t, namespace)
	}
	runIP(t, "-n", topology.switchNS, "link", "add", "br0", "type", "bridge")
	runIP(t, "-n", topology.switchNS, "link", "set", "br0", "up")
	for _, member := range []struct{ link, namespace string }{
		{"mc" + suffix, topology.clientNS}, {"ms" + suffix, topology.serverNS},
	} {
		port := "b" + member.link
		linkPair(t, member.link, member.namespace, port, topology.switchNS)
		runIP(t, "-n", topology.switchNS, "link", "set", port, "master", "br0", "up")
	}
	addressLink(t, topology.clientNS, "mc"+suffix, topology.clientAddress+"/24")
	addressLink(t, topology.serverNS, "ms"+suffix, topology.serverAddress+"/24")
	linkPair(t, "st"+suffix, topology.serverNS, "ts"+suffix, topology.targetNS)
	addressLink(t, topology.serverNS, "st"+suffix, topology.prefix+".2.1/24")
	addressLink(t, topology.targetNS, "ts"+suffix, topology.prefix+".2.2/24")
	linkPair(t, "cp"+suffix, topology.clientNS, "pc"+suffix, topology.peerNS)
	addressLink(t, topology.clientNS, "cp"+suffix, topology.prefix+".3.1/24")
	addressLink(t, topology.peerNS, "pc"+suffix, topology.prefix+".3.2/24")

	// The chain forward holds one counting rule for each of the four routes. The
	// chain loss starts empty and takes the drop rule of a phase. Both chains hook
	// into forward, so a drop in either chain drops the packet.
	ingressMatch := func(port int) string {
		return fmt.Sprintf("iifname %s ip daddr %s udp dport %d %s", topology.clientPort, topology.serverAddress, port, qualityLossMatch)
	}
	egressMatch := func(port int) string {
		return fmt.Sprintf("iifname %s ip daddr %s udp sport %d %s", topology.serverPort, topology.clientAddress, port, qualityLossMatch)
	}
	runInNamespace(t, topology.switchNS, "nft", "add", "table", "bridge", "mup")
	runInNamespace(t, topology.switchNS, "nft", "add", "chain", "bridge", "mup", "forward", "{ type filter hook forward priority 0 ; }")
	runInNamespace(t, topology.switchNS, "nft", "add", "chain", "bridge", "mup", "loss", "{ type filter hook forward priority 10 ; }")
	addRule := func(chain, comment, text string) {
		t.Helper()
		arguments := append([]string{"nft", "add", "rule", "bridge", "mup", chain}, strings.Fields(text)...)
		arguments = append(arguments, "comment", `"`+comment+`"`)
		runInNamespace(t, topology.switchNS, arguments...)
	}
	for _, port := range []int{5000, 5001} {
		addRule("forward", fmt.Sprintf("ingress_data_%d", port), ingressMatch(port)+" counter")
	}
	for _, port := range []int{5002, 5003} {
		addRule("forward", fmt.Sprintf("egress_data_%d", port), egressMatch(port)+" counter")
	}

	target := startEchoTarget(t, topology.targetNS, topology.prefix+".2.2:51820")
	defer target.stop(t)

	directory := t.TempDir()
	serverSocket := filepath.Join(directory, "server.sock")
	clientSocket := filepath.Join(directory, "client.sock")
	server := startNamespaced(t, topology.serverNS, binaryPath, "server", "-p", "5000-5009", "-r", topology.prefix+".2.2:51820", "--control-socket", serverSocket)
	defer server.stop(t)

	configuration := filepath.Join(directory, "client.yaml")
	content := fmt.Sprintf(`client:
  advertise: %[1]s
  control_socket: %[2]s
  servers:
    - port: 51820
      ingress:
        mode: failover
        tolerance: 5%%
        routes: ["%[3]s:5000/udp", "%[3]s:5001/udp"]
      egress:
        mode: failover
        tolerance: 5%%
        routes: ["%[3]s:5002/udp", "%[3]s:5003/udp"]
`, topology.clientAddress, clientSocket, topology.serverAddress)
	if err := os.WriteFile(configuration, []byte(content), 0o600); err != nil {
		t.Fatalf("write client configuration: %v", err)
	}
	client := startNamespaced(t, topology.clientNS, binaryPath, "--config", configuration)
	defer client.stop(t)

	clientAPI := api.NewDaemonClient(clientSocket)
	serverAPI := api.NewDaemonClient(serverSocket)
	state := func() string {
		return fmt.Sprintf("%s\n%s\n%s\nswitch:\n%s\nclient log:\n%s\nserver log:\n%s\ntarget log:\n%s",
			qualityClientText(clientAPI), qualityServerText(serverAPI), measuredMemberText(clientAPI, serverAPI),
			switchCounters(topology.switchNS), client.log(t), server.log(t), target.log(t))
	}
	peerSource, peerDestination := topology.prefix+".3.2:0", topology.prefix+".3.1:51820"

	waitFor(t, 30*time.Second, "all four paths to become healthy", state, func() (bool, error) {
		paths, err := clientAPI.Paths(context.Background())
		if err != nil || len(paths) != 4 {
			return false, err
		}
		for _, path := range paths {
			if !path.Healthy {
				return false, nil
			}
		}
		return true, nil
	})

	// Phase 1: no loss. The first route of each direction carries the data, nothing
	// is degraded, and both sides show the loss tolerance of the group.
	problem := qualityRun(t, peerSource, peerDestination, topology.peerNS, 14*time.Second, 11*time.Second, func() string {
		if problem := qualityCheckPath(clientAPI, 5000, true, false, true); problem != "" {
			return problem
		}
		if problem := qualityCheckPath(clientAPI, 5001, false, false, true); problem != "" {
			return problem
		}
		if problem := qualityCheckPath(clientAPI, 5002, true, false, true); problem != "" {
			return problem
		}
		if problem := qualityCheckPath(clientAPI, 5003, false, false, true); problem != "" {
			return problem
		}
		for _, port := range []uint16{5002, 5003} {
			path, _, err := qualityServerEgress(serverAPI, port)
			if err != nil {
				return err.Error()
			}
			if path.Degraded || path.Reason != "" || !path.Healthy || path.Active != (port == 5002) {
				return fmt.Sprintf("server egress %d healthy=%v degraded=%v active=%v reason=%q, want healthy, not degraded, active=%v",
					port, path.Healthy, path.Degraded, path.Active, path.Reason, port == 5002)
			}
		}
		group, err := qualityClientGroup(clientAPI)
		if err != nil {
			return err.Error()
		}
		if group.TolerancePercent != 5 {
			return fmt.Sprintf("client group TolerancePercent = %v, want 5", group.TolerancePercent)
		}
		_, egress, err := qualityServerEgress(serverAPI, 5002)
		if err != nil {
			return err.Error()
		}
		if egress.TolerancePercent != 5 {
			return fmt.Sprintf("server egress group TolerancePercent = %v, want 5", egress.TolerancePercent)
		}
		return ""
	})
	if problem != "" {
		t.Fatalf("clean paths: %s\n%s", problem, state())
	}

	// Phase 2: the switch drops one in four data packets to the server port 5000.
	// The client degrades the first ingress path and moves the data to the second.
	addRule("loss", "ingress_loss", ingressMatch(5000)+" "+qualityLossNumber+" counter drop")
	problem = qualityRun(t, peerSource, peerDestination, topology.peerNS, 30*time.Second, 5*time.Second, func() string {
		path, err := qualityClientPath(clientAPI, 5000)
		if err != nil {
			return err.Error()
		}
		if !path.Degraded || path.Reason == "" || !path.Healthy || path.InUse {
			return fmt.Sprintf("ingress 5000 degraded=%v reason=%q healthy=%v in_use=%v, want degraded with a reason, healthy, not in use",
				path.Degraded, path.Reason, path.Healthy, path.InUse)
		}
		return qualityCheckPath(clientAPI, 5001, true, false, true)
	})
	if problem != "" {
		t.Fatalf("ingress loss: %s\n%s", problem, state())
	}
	qualityCleanRun(t, "after the ingress switch", peerSource, peerDestination, topology.peerNS, 6*time.Second, state)

	// Phase 3: the loss moves to the first egress path. The server degrades it and
	// replies on the second. The hold time of the ingress path is not awaited.
	runInNamespace(t, topology.switchNS, "nft", "flush", "chain", "bridge", "mup", "loss")
	addRule("loss", "egress_loss", egressMatch(5002)+" "+qualityLossNumber+" counter drop")
	problem = qualityRun(t, peerSource, peerDestination, topology.peerNS, 30*time.Second, 5*time.Second, func() string {
		first, _, err := qualityServerEgress(serverAPI, 5002)
		if err != nil {
			return err.Error()
		}
		second, _, err := qualityServerEgress(serverAPI, 5003)
		if err != nil {
			return err.Error()
		}
		if !first.Degraded || first.Active || first.Reason == "" || !first.Healthy {
			return fmt.Sprintf("server egress 5002 degraded=%v active=%v reason=%q healthy=%v, want degraded with a reason, healthy, not active",
				first.Degraded, first.Active, first.Reason, first.Healthy)
		}
		if !second.Active || second.Degraded {
			return fmt.Sprintf("server egress 5003 active=%v degraded=%v, want active and not degraded", second.Active, second.Degraded)
		}
		return ""
	})
	if problem != "" {
		t.Fatalf("egress loss: %s\n%s", problem, state())
	}
	qualityCleanRun(t, "after the egress switch", peerSource, peerDestination, topology.peerNS, 6*time.Second, state)
}

// qualityLatencyNetwork is the network of the latency test. The client and the server
// have two direct links, A and B, with the addresses prefix.1.x and prefix.2.x. The
// client is .1 and the server is .2 on both. A delay on the first link makes it the
// slow one. The egress subtest delays the server packets that leave from the address
// of link A, so the replies of the first egress route are slow and the others are not.
type qualityLatencyNetwork struct {
	clientNS, serverNS, targetNS, peerNS string
	prefix                               string
	clientLinks                          [2]string
}

// TestPrivilegedLatencyChoicePicksTheFasterPath gives the client two links to the
// server and puts a 40 ms delay on the first one. A group with `prefer: latency`
// lists the slow link first and must still use the fast one.
func TestPrivilegedLatencyChoicePicksTheFasterPath(t *testing.T) {
	requirePrivilegedLinux(t)
	if _, err := exec.LookPath("tc"); err != nil {
		t.Skip("tc is not installed")
	}
	binaryPath := buildDaemon(t)
	// The prefixes 10.232 and 10.233 belong to this test.
	t.Run("ingress", func(t *testing.T) {
		runLatencyChoice(t, binaryPath, "10.232", false)
	})
	t.Run("egress", func(t *testing.T) {
		runLatencyChoice(t, binaryPath, "10.233", true)
	})
}

// runLatencyChoice builds the two links and runs the daemons. With egressChoice
// false the group has two ingress routes and one egress route, and the test
// looks at the ingress choice of the client. With egressChoice true the ingress
// has one route on the fast link, the egress has two routes with the slow one
// first, and the test looks at the egress choice of the server.
func runLatencyChoice(t *testing.T, binaryPath, prefix string, egressChoice bool) {
	suffix := strconv.FormatInt(time.Now().UnixNano()%1_000_000, 10)
	network := qualityLatencyNetwork{
		prefix:   prefix,
		clientNS: "mup-client-" + suffix, serverNS: "mup-server-" + suffix, targetNS: "mup-target-" + suffix, peerNS: "mup-peer-" + suffix,
	}
	for _, namespace := range []string{network.clientNS, network.serverNS, network.targetNS, network.peerNS} {
		addNamespace(t, namespace)
	}
	var serverLinks [2]string
	for index, name := range []string{"a", "b"} {
		network.clientLinks[index] = "mc" + name + suffix
		serverLinks[index] = "ms" + name + suffix
		linkPair(t, network.clientLinks[index], network.clientNS, serverLinks[index], network.serverNS)
		addressLink(t, network.clientNS, network.clientLinks[index], fmt.Sprintf("%s.%d.1/24", prefix, index+1))
		addressLink(t, network.serverNS, serverLinks[index], fmt.Sprintf("%s.%d.2/24", prefix, index+1))
	}
	linkPair(t, "st"+suffix, network.serverNS, "ts"+suffix, network.targetNS)
	addressLink(t, network.serverNS, "st"+suffix, prefix+".3.1/24")
	addressLink(t, network.targetNS, "ts"+suffix, prefix+".3.2/24")
	linkPair(t, "cp"+suffix, network.clientNS, "pc"+suffix, network.peerNS)
	addressLink(t, network.clientNS, "cp"+suffix, prefix+".4.1/24")
	addressLink(t, network.peerNS, "pc"+suffix, prefix+".4.2/24")

	delay := fmt.Sprintf("%dms", qualityDelay/time.Millisecond)
	// The client link A always gets a plain delay. The egress subtest delays the
	// replies of one egress path only. The server sends every reply and probe to the
	// advertised client address over link A, whatever the source address is, so a
	// filter on the source address of the first egress route picks the packets.
	commands := [][]string{{network.clientNS, "tc", "qdisc", "add", "dev", network.clientLinks[0], "root", "netem", "delay", delay}}
	if egressChoice {
		link := serverLinks[0]
		commands = append(commands,
			[]string{network.serverNS, "tc", "qdisc", "add", "dev", link, "root", "handle", "1:", "prio"},
			[]string{network.serverNS, "tc", "qdisc", "add", "dev", link, "parent", "1:3", "handle", "30:", "netem", "delay", delay},
			[]string{network.serverNS, "tc", "filter", "add", "dev", link, "protocol", "ip", "parent", "1:0", "prio", "1",
				"u32", "match", "ip", "src", prefix + ".1.2/32", "flowid", "1:3"})
	}
	for _, command := range commands {
		output, err := exec.Command("ip", append([]string{"netns", "exec"}, command...)...).CombinedOutput()
		if err != nil {
			t.Skipf("tc setup is not available (the module sch_netem, sch_prio or cls_u32 may be missing): %v: %v\n%s", command[1:], err, output)
		}
	}

	target := startEchoTarget(t, network.targetNS, prefix+".3.2:51820")
	defer target.stop(t)
	directory := t.TempDir()
	serverSocket := filepath.Join(directory, "server.sock")
	clientSocket := filepath.Join(directory, "client.sock")
	server := startNamespaced(t, network.serverNS, binaryPath, "server", "-p", "5000-5009", "-r", prefix+".3.2:51820", "--control-socket", serverSocket)
	defer server.stop(t)

	// The first route of each list is the slow one. The server addresses end in .2.
	slowIngress := fmt.Sprintf("%s.1.2%%%s:5000/udp", prefix, network.clientLinks[0])
	fastIngress := fmt.Sprintf("%s.2.2%%%s:5001/udp", prefix, network.clientLinks[1])
	ingress := fmt.Sprintf(`        mode: failover
        prefer: latency
        routes: ["%s", "%s"]`, slowIngress, fastIngress)
	egress := fmt.Sprintf(`        routes: ["%s.1.2:5002/udp"]`, prefix)
	if egressChoice {
		ingress = fmt.Sprintf(`        routes: ["%s"]`, fastIngress)
		egress = fmt.Sprintf(`        mode: failover
        prefer: latency
        routes: ["%[1]s.1.2:5002/udp", "%[1]s.2.2:5003/udp"]`, prefix)
	}
	configuration := filepath.Join(directory, "client.yaml")
	content := fmt.Sprintf(`client:
  advertise: %s.1.1
  control_socket: %s
  servers:
    - port: 51820
      ingress:
%s
      egress:
%s
`, prefix, clientSocket, ingress, egress)
	if err := os.WriteFile(configuration, []byte(content), 0o600); err != nil {
		t.Fatalf("write client configuration: %v", err)
	}
	client := startNamespaced(t, network.clientNS, binaryPath, "--config", configuration)
	defer client.stop(t)

	clientAPI := api.NewDaemonClient(clientSocket)
	serverAPI := api.NewDaemonClient(serverSocket)
	state := func() string {
		return fmt.Sprintf("%s\n%s\n%s\nconfiguration:\n%s\ntc client:\n%s\ntc server:\n%s\nclient log:\n%s\nserver log:\n%s\ntarget log:\n%s",
			qualityClientText(clientAPI), qualityServerText(serverAPI), measuredMemberText(clientAPI, serverAPI), content,
			qualityTC(network.clientNS), qualityTC(network.serverNS), client.log(t), server.log(t), target.log(t))
	}

	// The chooser needs RTT samples and 10 seconds of a better path before it
	// switches, so the wait is 40 seconds.
	slowPort, fastPort := uint16(5000), uint16(5001)
	waitFor(t, 40*time.Second, "the latency choice", state, func() (bool, error) {
		if !egressChoice {
			slow, err := qualityClientPath(clientAPI, slowPort)
			if err != nil {
				return false, err
			}
			fast, err := qualityClientPath(clientAPI, fastPort)
			if err != nil {
				return false, err
			}
			ok := fast.InUse && !slow.InUse && slow.Healthy && fast.Healthy && !slow.Degraded && !fast.Degraded &&
				slow.RTTAvgSeconds > 0 && fast.RTTAvgSeconds > 0 && slow.RTTAvgSeconds > fast.RTTAvgSeconds+qualityDelay.Seconds()/2
			return ok, nil
		}
		slow, _, err := qualityServerEgress(serverAPI, 5002)
		if err != nil {
			return false, err
		}
		fast, _, err := qualityServerEgress(serverAPI, 5003)
		if err != nil {
			return false, err
		}
		ok := fast.Active && !slow.Active && slow.Healthy && fast.Healthy && !slow.Degraded && !fast.Degraded &&
			slow.RTTAvgSeconds > 0 && fast.RTTAvgSeconds > 0 && slow.RTTAvgSeconds > fast.RTTAvgSeconds+qualityDelay.Seconds()/2
		return ok, nil
	})
	group, err := qualityClientGroup(clientAPI)
	if err != nil {
		t.Fatalf("client group: %v\n%s", err, state())
	}
	if egressChoice && group.EgressPrefer != "latency" || !egressChoice && group.Prefer != "latency" {
		t.Fatalf("client group prefer = %q, egress prefer = %q, want latency on the tested direction\n%s", group.Prefer, group.EgressPrefer, state())
	}
	if egressChoice {
		if _, egressGroup, err := qualityServerEgress(serverAPI, 5002); err != nil || egressGroup.Prefer != "latency" {
			t.Fatalf("server egress group prefer = %q (%v), want latency\n%s", egressGroup.Prefer, err, state())
		}
	}
	qualityCleanRun(t, "with the latency choice", prefix+".4.2:0", prefix+".4.1:51820", network.peerNS, 6*time.Second, state)
}

// qualityRun sends traffic for the duration, checks the condition every half
// second from the given time on, and stops the traffic as soon as the check
// returns no problem. It returns the last problem, or an empty text.
func qualityRun(t *testing.T, local, destination, peerNS string, duration, from time.Duration, check func() string) string {
	t.Helper()
	helper := startTrafficHelper(t, peerNS, local, destination, duration)
	defer func() {
		_ = helper.command.Process.Kill()
		_ = helper.command.Wait()
	}()
	start := time.Now()
	time.Sleep(from)
	problem := "no check ran"
	for time.Since(start) < duration-500*time.Millisecond {
		if problem = check(); problem == "" {
			return ""
		}
		time.Sleep(500 * time.Millisecond)
	}
	return problem
}

// qualityCleanRun sends a fresh run of traffic and requires at least 95 percent
// echoes.
func qualityCleanRun(t *testing.T, name, local, destination, peerNS string, duration time.Duration, state func() string) {
	t.Helper()
	helper := startTrafficHelper(t, peerNS, local, destination, duration)
	line, err := helper.finish()
	var sent, echoed int
	index := strings.Index(line, "traffic sent=")
	if index < 0 {
		t.Fatalf("%s: no traffic result: %s %v\n%s", name, line, err, state())
	}
	if _, scanErr := fmt.Sscanf(line[index:], "traffic sent=%d echoed=%d", &sent, &echoed); scanErr != nil || sent == 0 {
		t.Fatalf("%s: cannot read %q: %v\n%s", name, line, scanErr, state())
	}
	if float64(echoed) < qualityMinimumEchoes*float64(sent) {
		t.Fatalf("%s: echoed %d of %d packets, want at least %.0f percent\n%s", name, echoed, sent, qualityMinimumEchoes*100, state())
	}
	t.Logf("%s: traffic %s", name, line)
}

// qualityClientPath returns the client path with the server port.
func qualityClientPath(client *api.DaemonClient, port uint16) (api.Path, error) {
	paths, err := client.Paths(context.Background())
	if err != nil {
		return api.Path{}, err
	}
	for _, path := range paths {
		if path.Port == port {
			return path, nil
		}
	}
	return api.Path{}, fmt.Errorf("the client has no path to the server port %d", port)
}

// qualityCheckPath checks the use of a client path: whether it carries data,
// whether it is degraded, and whether it is healthy. It returns a problem text.
func qualityCheckPath(client *api.DaemonClient, port uint16, inUse, degraded, healthy bool) string {
	path, err := qualityClientPath(client, port)
	if err != nil {
		return err.Error()
	}
	if path.InUse != inUse || path.Degraded != degraded || path.Healthy != healthy {
		return fmt.Sprintf("%s path %d in_use=%v degraded=%v healthy=%v reason=%q, want in_use=%v degraded=%v healthy=%v",
			path.Direction, port, path.InUse, path.Degraded, path.Healthy, path.Reason, inUse, degraded, healthy)
	}
	return ""
}

// qualityClientGroup returns the first group of the client.
func qualityClientGroup(client *api.DaemonClient) (api.Group, error) {
	status, err := client.Status(context.Background())
	if err != nil {
		return api.Group{}, err
	}
	if status.Client == nil || len(status.Client.Groups) == 0 {
		return api.Group{}, fmt.Errorf("the client reports no group")
	}
	return status.Client.Groups[0], nil
}

// qualityServerEgress returns the egress path with the server port and the egress
// group that holds it.
func qualityServerEgress(server *api.DaemonClient, port uint16) (api.EgressPath, api.EgressGroup, error) {
	clients, err := server.Clients(context.Background())
	if err != nil {
		return api.EgressPath{}, api.EgressGroup{}, err
	}
	for _, registered := range clients {
		for _, group := range registered.Egresses {
			for _, path := range group.Paths {
				if path.Port == port {
					return path, group, nil
				}
			}
		}
	}
	return api.EgressPath{}, api.EgressGroup{}, fmt.Errorf("the server holds no egress path on the port %d", port)
}

// qualityClientText lists the client paths with their state and measurement, and
// the groups with their settings.
func qualityClientText(client *api.DaemonClient) string {
	paths, err := client.Paths(context.Background())
	if err != nil {
		return fmt.Sprintf("client paths: <%v>", err)
	}
	text := "client paths:"
	for _, path := range paths {
		text += fmt.Sprintf("\n  [%d %s %s%%%s:%d/%s healthy=%v degraded=%v in_use=%v reason=%q %s]",
			path.ID, path.Direction, path.Server, path.Interface, path.Port, path.Transport,
			path.Healthy, path.Degraded, path.InUse, path.Reason, measurementText(path.Measurement))
	}
	status, err := client.Status(context.Background())
	if err != nil || status.Client == nil {
		return text + fmt.Sprintf("\nclient groups: <%v>", err)
	}
	for _, group := range status.Client.Groups {
		text += fmt.Sprintf("\n  client group %d: mode=%s tolerance=%v prefer=%q egress_mode=%s egress_tolerance=%v egress_prefer=%q",
			group.ListenPort, group.Mode, group.TolerancePercent, group.Prefer, group.EgressMode, group.EgressTolerancePercent, group.EgressPrefer)
	}
	return text
}

// qualityServerText lists the egress paths of the server with their state and
// measurement, and the egress groups with their settings.
func qualityServerText(server *api.DaemonClient) string {
	clients, err := server.Clients(context.Background())
	if err != nil {
		return fmt.Sprintf("server clients: <%v>", err)
	}
	text := "server egress paths:"
	for _, registered := range clients {
		for _, group := range registered.Egresses {
			text += fmt.Sprintf("\n  egress group %d (%s): mode=%s tolerance=%v prefer=%q",
				group.ListenPort, registered.AdvertisedIP, group.Mode, group.TolerancePercent, group.Prefer)
			for _, path := range group.Paths {
				text += fmt.Sprintf("\n    [%d %s:%d/%s healthy=%v active=%v degraded=%v reason=%q %s]",
					path.ID, path.Server, path.Port, path.Transport, path.Healthy, path.Active, path.Degraded, path.Reason, measurementText(path.Measurement))
			}
		}
	}
	return text
}

// qualityTC prints the queueing disciplines of a namespace for a failure message.
func qualityTC(namespace string) string {
	output, err := exec.Command("ip", "netns", "exec", namespace, "tc", "qdisc", "show").CombinedOutput()
	if err != nil {
		return fmt.Sprintf("<tc qdisc show: %v>", err)
	}
	return string(output)
}
