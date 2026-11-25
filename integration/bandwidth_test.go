package integration

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xshecan/mup/api"
)

const (
	// bandwidthRun is how long the traffic helper sends in each run.
	bandwidthRun = 15 * time.Second
	// bandwidthReadFrom is when the checks of the client and server state start.
	// The rate of a path is measured over a few seconds, so a read at 9 seconds
	// sees the limited rate.
	bandwidthReadFrom = 9 * time.Second
	// bandwidthLimitText is the limit of the tests as the route text has it, and
	// bandwidthLimit is the same limit in bits per second.
	bandwidthLimitText = "64kbit"
	bandwidthLimit     = 64000.0
)

// bandwidthRoute is one route of a test. Limit is the text after `bw`, or empty
// for a plain route.
type bandwidthRoute struct {
	port  int
	limit string
}

// bandwidthNetwork is the network of the bandwidth tests. The client is .1.1, the
// server .1.2, the peer behind the client .3.2, and the echo target behind the
// server .2.2. A switch namespace with a bridge sits between the client and the
// server and counts the data bytes of each route.
type bandwidthNetwork struct {
	prefix                 string
	switchNS, peerNS       string
	clientAddress          string
	serverAddress          string
	clientAPI, serverAPI   *api.DaemonClient
	ingress, egress        []bandwidthRoute
	state                  func() string
	switchClient, switchSv string
}

// bandwidthRuleExpression matches one counting rule of the switch in the output of
// nft.
var bandwidthRuleExpression = regexp.MustCompile(`counter packets (\d+) bytes (\d+) comment "([^"]+)"`)

// startBandwidthNetwork builds the topology, starts the daemons, and waits until
// every path is healthy. The group has separate directions, the failover mode on
// both, and the given routes. The server listens on the ports 5000 to 5009.
func startBandwidthNetwork(t *testing.T, binaryPath, prefix string, ingress, egress []bandwidthRoute) *bandwidthNetwork {
	t.Helper()
	suffix := strconv.FormatInt(time.Now().UnixNano()%1_000_000, 10)
	clientNS, serverNS, targetNS := "mup-client-"+suffix, "mup-server-"+suffix, "mup-target-"+suffix
	network := &bandwidthNetwork{
		prefix:   prefix,
		switchNS: "mup-switch-" + suffix, peerNS: "mup-peer-" + suffix,
		clientAddress: prefix + ".1.1", serverAddress: prefix + ".1.2",
		switchClient: "bmc" + suffix, switchSv: "bms" + suffix,
		ingress: ingress, egress: egress,
	}
	for _, namespace := range []string{clientNS, serverNS, targetNS, network.switchNS, network.peerNS} {
		addNamespace(t, namespace)
	}
	runIP(t, "-n", network.switchNS, "link", "add", "br0", "type", "bridge")
	runIP(t, "-n", network.switchNS, "link", "set", "br0", "up")
	for _, member := range []struct{ link, namespace string }{{"mc" + suffix, clientNS}, {"ms" + suffix, serverNS}} {
		port := "b" + member.link
		linkPair(t, member.link, member.namespace, port, network.switchNS)
		runIP(t, "-n", network.switchNS, "link", "set", port, "master", "br0", "up")
	}
	addressLink(t, clientNS, "mc"+suffix, network.clientAddress+"/24")
	addressLink(t, serverNS, "ms"+suffix, network.serverAddress+"/24")
	linkPair(t, "st"+suffix, serverNS, "ts"+suffix, targetNS)
	addressLink(t, serverNS, "st"+suffix, prefix+".2.1/24")
	addressLink(t, targetNS, "ts"+suffix, prefix+".2.2/24")
	linkPair(t, "cp"+suffix, clientNS, "pc"+suffix, network.peerNS)
	addressLink(t, clientNS, "cp"+suffix, prefix+".3.1/24")
	addressLink(t, network.peerNS, "pc"+suffix, prefix+".3.2/24")

	// The chain forward holds one counting rule for each route. The rule counts
	// only data packets: a control frame is exactly 76 bytes long, so the match
	// "ip length > 76" never sees one. An ingress rule matches the client to
	// server direction by the server port, an egress rule matches the replies by the
	// source port of the server.
	runInNamespace(t, network.switchNS, "nft", "add", "table", "bridge", "mup")
	runInNamespace(t, network.switchNS, "nft", "add", "chain", "bridge", "mup", "forward", "{ type filter hook forward priority 0 ; }")
	addRule := func(comment, text string) {
		t.Helper()
		arguments := append([]string{"nft", "add", "rule", "bridge", "mup", "forward"}, strings.Fields(text)...)
		arguments = append(arguments, "counter", "comment", `"`+comment+`"`)
		runInNamespace(t, network.switchNS, arguments...)
	}
	for _, route := range ingress {
		addRule(fmt.Sprintf("ingress_%d", route.port),
			fmt.Sprintf("iifname %s ip daddr %s udp dport %d %s", network.switchClient, network.serverAddress, route.port, measureLossMatch))
	}
	for _, route := range egress {
		addRule(fmt.Sprintf("egress_%d", route.port),
			fmt.Sprintf("iifname %s ip daddr %s udp sport %d %s", network.switchSv, network.clientAddress, route.port, measureLossMatch))
	}

	target := startEchoTarget(t, targetNS, prefix+".2.2:51820")
	t.Cleanup(func() { target.stop(t) })
	directory := t.TempDir()
	serverSocket := filepath.Join(directory, "server.sock")
	clientSocket := filepath.Join(directory, "client.sock")
	server := startNamespaced(t, serverNS, binaryPath, "server", "-p", "5000-5009", "-r", prefix+".2.2:51820", "--control-socket", serverSocket)
	t.Cleanup(func() { server.stop(t) })

	routeList := func(routes []bandwidthRoute) string {
		texts := make([]string, 0, len(routes))
		for _, route := range routes {
			text := fmt.Sprintf(`"%s:%d/udp`, network.serverAddress, route.port)
			if route.limit != "" {
				text += " bw " + route.limit
			}
			texts = append(texts, text+`"`)
		}
		return "[" + strings.Join(texts, ", ") + "]"
	}
	configuration := filepath.Join(directory, "client.yaml")
	content := fmt.Sprintf(`client:
  advertise: %s
  control_socket: %s
  servers:
    - port: 51820
      ingress:
        mode: failover
        routes: %s
      egress:
        mode: failover
        routes: %s
`, network.clientAddress, clientSocket, routeList(ingress), routeList(egress))
	if err := os.WriteFile(configuration, []byte(content), 0o600); err != nil {
		t.Fatalf("write client configuration: %v", err)
	}
	client := startNamespaced(t, clientNS, binaryPath, "--config", configuration)
	t.Cleanup(func() { client.stop(t) })

	network.clientAPI = api.NewDaemonClient(clientSocket)
	network.serverAPI = api.NewDaemonClient(serverSocket)
	network.state = func() string {
		return fmt.Sprintf("%s\n%s\nclient %s\nserver %s\nswitch:\n%s\nconfiguration:\n%s\nclient log:\n%s\nserver log:\n%s\ntarget log:\n%s",
			bandwidthClientText(network.clientAPI), bandwidthServerText(network.serverAPI),
			dropText(t, network.clientAPI), dropText(t, network.serverAPI),
			switchCounters(network.switchNS), content, client.log(t), server.log(t), target.log(t))
	}

	paths := len(ingress) + len(egress)
	waitFor(t, 30*time.Second, "every path to become healthy", network.state, func() (bool, error) {
		list, err := network.clientAPI.Paths(context.Background())
		if err != nil || len(list) != paths {
			return false, err
		}
		for _, path := range list {
			if !path.Healthy {
				return false, nil
			}
		}
		return true, nil
	})
	return network
}

// counters returns the data bytes and packets that the switch counted for each
// rule, keyed by the comment of the rule.
func (n *bandwidthNetwork) counters(t *testing.T) (bytes, packets map[string]uint64) {
	t.Helper()
	output, err := exec.Command("ip", "netns", "exec", n.switchNS, "nft", "list", "chain", "bridge", "mup", "forward").CombinedOutput()
	if err != nil {
		t.Fatalf("list the switch counters: %v\n%s", err, output)
	}
	bytes, packets = map[string]uint64{}, map[string]uint64{}
	for _, match := range bandwidthRuleExpression.FindAllStringSubmatch(string(output), -1) {
		count, _ := strconv.ParseUint(match[1], 10, 64)
		size, _ := strconv.ParseUint(match[2], 10, 64)
		packets[match[3]], bytes[match[3]] = count, size
	}
	return bytes, packets
}

// bandwidthResult is what one traffic run measured.
type bandwidthResult struct {
	sent, echoed int
	// seconds is the time that the helper ran, with the wait for late echoes.
	seconds float64
	// bytes and packets are the switch counters of each rule over the run.
	bytes, packets map[string]uint64
	// problem is the last problem that the check reported, or empty when the check
	// passed once.
	problem string
}

// share returns the part of the bytes of the rule in the bytes of all the rules
// in names.
func (r bandwidthResult) share(name string, names ...string) float64 {
	var total uint64
	for _, other := range names {
		total += r.bytes[other]
	}
	if total == 0 {
		return 0
	}
	return float64(r.bytes[name]) / float64(total)
}

// run sends traffic for bandwidthRun and calls check every half second from
// bandwidthReadFrom on, until it returns no problem. It returns the counts of the
// helper and the counter deltas.
func (n *bandwidthNetwork) run(t *testing.T, check func() string) bandwidthResult {
	t.Helper()
	beforeBytes, beforePackets := n.counters(t)
	helper := startTrafficHelper(t, n.peerNS, n.prefix+".3.2:0", n.prefix+".3.1:51820", bandwidthRun)
	start := time.Now()
	time.Sleep(bandwidthReadFrom)
	problem := "no check ran"
	for time.Since(start) < bandwidthRun-500*time.Millisecond {
		if problem = check(); problem == "" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	line, err := helper.finish()
	seconds := time.Since(start).Seconds()
	result := bandwidthResult{seconds: seconds, problem: problem}
	index := strings.Index(line, "traffic sent=")
	if index < 0 {
		t.Fatalf("no traffic result: %s %v\n%s", line, err, n.state())
	}
	if _, scanErr := fmt.Sscanf(line[index:], "traffic sent=%d echoed=%d", &result.sent, &result.echoed); scanErr != nil || result.sent == 0 {
		t.Fatalf("cannot read %q: %v\n%s", line, scanErr, n.state())
	}
	afterBytes, afterPackets := n.counters(t)
	result.bytes, result.packets = map[string]uint64{}, map[string]uint64{}
	for name := range afterBytes {
		result.bytes[name] = afterBytes[name] - beforeBytes[name]
		result.packets[name] = afterPackets[name] - beforePackets[name]
	}
	t.Logf("traffic %s, switch bytes %v", line, result.bytes)
	return result
}

// echoShare returns the part of the sent packets that came back.
func (r bandwidthResult) echoShare() float64 {
	return float64(r.echoed) / float64(r.sent)
}

// requireShare fails the test when the share is outside [low, high].
func (n *bandwidthNetwork) requireShare(t *testing.T, name string, result bandwidthResult, names []string, low, high float64) {
	t.Helper()
	share := result.share(name, names...)
	if share < low || share > high {
		t.Fatalf("the switch counted %.0f%% of the data bytes on %s (bytes %v), want %.0f%% to %.0f%%\n%s",
			share*100, name, result.bytes, low*100, high*100, n.state())
	}
}

// requireDrop fails the test when the daemon has a different RATE_LIMIT count than
// wanted. With wantSome the count must be above zero, otherwise it must be zero.
func (n *bandwidthNetwork) requireDrop(t *testing.T, role string, daemon *api.DaemonClient, wantSome bool) {
	t.Helper()
	status, err := daemon.Status(context.Background())
	if err != nil {
		t.Fatalf("%s status: %v\n%s", role, err, n.state())
	}
	count := dropCount(status.Drops, "RATE_LIMIT")
	if wantSome && count == 0 {
		t.Fatalf("%s has no RATE_LIMIT drop, want some\n%s", role, n.state())
	}
	if !wantSome && count != 0 {
		t.Fatalf("%s has %d RATE_LIMIT drops, want none\n%s", role, count, n.state())
	}
}

// TestPrivilegedBandwidthSpillsToTheNextPath limits the first of two ingress routes
// to 64 kbit per second. The traffic of about 141 kbit per second does not fit, so
// the client must send the rest on the second route. Nothing is lost.
func TestPrivilegedBandwidthSpillsToTheNextPath(t *testing.T) {
	requirePrivilegedLinux(t)
	binaryPath := buildDaemon(t)
	// The prefix 10.240 belongs to this test.
	network := startBandwidthNetwork(t, binaryPath, "10.240",
		[]bandwidthRoute{{5000, bandwidthLimitText}, {5001, ""}}, []bandwidthRoute{{5002, ""}})

	result := network.run(t, func() string {
		limited, err := qualityClientPath(network.clientAPI, 5000)
		if err != nil {
			return err.Error()
		}
		open, err := qualityClientPath(network.clientAPI, 5001)
		if err != nil {
			return err.Error()
		}
		if math.Abs(limited.BandwidthBitsPerSecond-bandwidthLimit) > 1 || limited.BandwidthPerMember {
			return fmt.Sprintf("path 5000 bw = %v per_member=%v, want %v and no per-member",
				limited.BandwidthBitsPerSecond, limited.BandwidthPerMember, bandwidthLimit)
		}
		if open.BandwidthBitsPerSecond != 0 || open.BandwidthPerMember {
			return fmt.Sprintf("path 5001 bw = %v per_member=%v, want none", open.BandwidthBitsPerSecond, open.BandwidthPerMember)
		}
		if rate := limited.RateBitsPerSecond; rate < 45000 || rate > 80000 {
			return fmt.Sprintf("path 5000 rate = %.0f bit/s, want 45000 to 80000", rate)
		}
		if open.RateBitsPerSecond <= 0 {
			return fmt.Sprintf("path 5001 rate = %.0f bit/s, want above 0", open.RateBitsPerSecond)
		}
		if !(limited.InUse || limited.RateBitsPerSecond > 0) || !(open.InUse || open.RateBitsPerSecond > 0) {
			return fmt.Sprintf("in_use 5000=%v 5001=%v, want both paths to carry data", limited.InUse, open.InUse)
		}
		return ""
	})
	if result.problem != "" {
		t.Fatalf("path state: %s\n%s", result.problem, network.state())
	}
	if result.echoShare() < 0.97 {
		t.Fatalf("echoed %d of %d packets, want at least 97 percent (the rest must spill)\n%s", result.echoed, result.sent, network.state())
	}
	names := []string{"ingress_5000", "ingress_5001"}
	network.requireShare(t, "ingress_5000", result, names, 0.30, 0.60)
	network.requireShare(t, "ingress_5001", result, names, 0.40, 0.70)
	network.requireDrop(t, "client", network.clientAPI, false)
}

// TestPrivilegedBandwidthDropsWhenEveryPathIsFull limits the only ingress route to
// 64 kbit per second. About 45 percent of the traffic fits, mup drops the rest with
// RATE_LIMIT, and the path stays healthy because the limit never touches a control
// frame.
func TestPrivilegedBandwidthDropsWhenEveryPathIsFull(t *testing.T) {
	requirePrivilegedLinux(t)
	binaryPath := buildDaemon(t)
	// The prefix 10.241 belongs to this test.
	network := startBandwidthNetwork(t, binaryPath, "10.241",
		[]bandwidthRoute{{5000, bandwidthLimitText}}, []bandwidthRoute{{5002, ""}})

	result := network.run(t, func() string {
		path, err := qualityClientPath(network.clientAPI, 5000)
		if err != nil {
			return err.Error()
		}
		if math.Abs(path.BandwidthBitsPerSecond-bandwidthLimit) > 1 {
			return fmt.Sprintf("path 5000 bw = %v, want %v", path.BandwidthBitsPerSecond, bandwidthLimit)
		}
		if !path.Healthy {
			return fmt.Sprintf("path 5000 is not healthy (reason %q), the limit must not make it unhealthy", path.Reason)
		}
		return ""
	})
	if result.problem != "" {
		t.Fatalf("path state: %s\n%s", result.problem, network.state())
	}
	if share := result.echoShare(); share < 0.30 || share > 0.60 {
		t.Fatalf("echoed %d of %d packets (%.0f%%), want 30 to 60 percent\n%s", result.echoed, result.sent, share*100, network.state())
	}
	network.requireDrop(t, "client", network.clientAPI, true)
	// The route carries at most the rate for the whole run, with 30 percent of
	// tolerance, one burst of 3000 bytes, and the 14 byte link header that the
	// counter may include.
	limit := bandwidthLimit/8*result.seconds*1.3 + 3000 + float64(result.packets["ingress_5000"])*14
	if carried := float64(result.bytes["ingress_5000"]); carried > limit {
		t.Fatalf("route 5000 carried %.0f bytes in %.1f s, want at most %.0f\n%s", carried, result.seconds, limit, network.state())
	}
	if problem := qualityCheckPath(network.clientAPI, 5000, true, false, true); problem != "" {
		t.Fatalf("after the run: %s\n%s", problem, network.state())
	}
}

// TestPrivilegedBandwidthLimitsTheEgress limits the first of two egress routes to
// 64 kbit per second, which the client sends to the server in EGRESS_LIMIT. The
// server must reply on the second route for the rest. The second phase keeps only
// the limited egress route, so the server drops what does not fit.
func TestPrivilegedBandwidthLimitsTheEgress(t *testing.T) {
	requirePrivilegedLinux(t)
	binaryPath := buildDaemon(t)

	// The prefix 10.242 belongs to the spill phase and 10.243 to the drop phase.
	t.Run("spill", func(t *testing.T) {
		network := startBandwidthNetwork(t, binaryPath, "10.242",
			[]bandwidthRoute{{5000, ""}}, []bandwidthRoute{{5002, bandwidthLimitText}, {5003, ""}})
		result := network.run(t, func() string {
			path, _, err := qualityServerEgress(network.serverAPI, 5002)
			if err != nil {
				return err.Error()
			}
			if math.Abs(path.BandwidthBitsPerSecond-bandwidthLimit) > 1 || path.BandwidthPerMember {
				return fmt.Sprintf("server egress 5002 bw = %v per_member=%v, want %v and no per-member",
					path.BandwidthBitsPerSecond, path.BandwidthPerMember, bandwidthLimit)
			}
			other, _, err := qualityServerEgress(network.serverAPI, 5003)
			if err != nil {
				return err.Error()
			}
			if other.BandwidthBitsPerSecond != 0 {
				return fmt.Sprintf("server egress 5003 bw = %v, want none", other.BandwidthBitsPerSecond)
			}
			return ""
		})
		if result.problem != "" {
			t.Fatalf("server state: %s\n%s", result.problem, network.state())
		}
		if result.echoShare() < 0.97 {
			t.Fatalf("echoed %d of %d packets, want at least 97 percent (the rest must spill)\n%s", result.echoed, result.sent, network.state())
		}
		names := []string{"egress_5002", "egress_5003"}
		network.requireShare(t, "egress_5002", result, names, 0.30, 0.60)
		network.requireShare(t, "egress_5003", result, names, 0.40, 0.70)
		network.requireDrop(t, "server", network.serverAPI, false)
		network.requireDrop(t, "client", network.clientAPI, false)
	})

	t.Run("full", func(t *testing.T) {
		network := startBandwidthNetwork(t, binaryPath, "10.243",
			[]bandwidthRoute{{5000, ""}}, []bandwidthRoute{{5002, bandwidthLimitText}})
		result := network.run(t, func() string {
			path, _, err := qualityServerEgress(network.serverAPI, 5002)
			if err != nil {
				return err.Error()
			}
			if math.Abs(path.BandwidthBitsPerSecond-bandwidthLimit) > 1 {
				return fmt.Sprintf("server egress 5002 bw = %v, want %v", path.BandwidthBitsPerSecond, bandwidthLimit)
			}
			if !path.Healthy {
				return fmt.Sprintf("server egress 5002 is not healthy (reason %q), the limit must not make it unhealthy", path.Reason)
			}
			return ""
		})
		if result.problem != "" {
			t.Fatalf("server state: %s\n%s", result.problem, network.state())
		}
		if share := result.echoShare(); share < 0.30 || share > 0.60 {
			t.Fatalf("echoed %d of %d packets (%.0f%%), want 30 to 60 percent\n%s", result.echoed, result.sent, share*100, network.state())
		}
		network.requireDrop(t, "server", network.serverAPI, true)
		limit := bandwidthLimit/8*result.seconds*1.3 + 3000 + float64(result.packets["egress_5002"])*14
		if carried := float64(result.bytes["egress_5002"]); carried > limit {
			t.Fatalf("egress route 5002 carried %.0f bytes in %.1f s, want at most %.0f\n%s", carried, result.seconds, limit, network.state())
		}
	})
}

// bandwidthClientText lists the client paths with their limit, rate, and state.
func bandwidthClientText(client *api.DaemonClient) string {
	paths, err := client.Paths(context.Background())
	if err != nil {
		return fmt.Sprintf("client paths: <%v>", err)
	}
	text := "client paths:"
	for _, path := range paths {
		text += fmt.Sprintf("\n  [%d %s %s:%d/%s bw=%.0f per_member=%v rate=%.0fbit/s healthy=%v in_use=%v degraded=%v reason=%q]",
			path.ID, path.Direction, path.Server, path.Port, path.Transport, path.BandwidthBitsPerSecond, path.BandwidthPerMember,
			path.RateBitsPerSecond, path.Healthy, path.InUse, path.Degraded, path.Reason)
	}
	return text
}

// bandwidthServerText lists the egress paths of the server with their limit, rate,
// and state.
func bandwidthServerText(server *api.DaemonClient) string {
	clients, err := server.Clients(context.Background())
	if err != nil {
		return fmt.Sprintf("server clients: <%v>", err)
	}
	text := "server egress paths:"
	for _, registered := range clients {
		for _, group := range registered.Egresses {
			for _, path := range group.Paths {
				text += fmt.Sprintf("\n  [%d %s:%d/%s bw=%.0f per_member=%v rate=%.0fbit/s healthy=%v active=%v degraded=%v reason=%q]",
					path.ID, path.Server, path.Port, path.Transport, path.BandwidthBitsPerSecond, path.BandwidthPerMember,
					path.RateBitsPerSecond, path.Healthy, path.Active, path.Degraded, path.Reason)
			}
		}
	}
	return text
}
