package integration

import (
	"context"
	"encoding/json"
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

// sourceRangeScenario is one group of the source range test. Body holds the lines
// of the group below its listen port. Ingress and egress are the source ranges that
// the switch allows in each direction. Separate says that the group has its own
// egress path.
type sourceRangeScenario struct {
	transport       string
	body            string
	ingress, egress [2]int
	separate        bool
}

// TestPrivilegedSourceRange runs a group whose routes end with a source range. The
// switch drops every data packet of the path with a source port or an Echo
// identifier outside the range of its direction, and it counts the data packets
// inside the range. A data packet is told from a control frame by its size. A
// control frame has a 48 byte payload, so its IP total length is 76 for UDP and for
// ICMP. A tunneled WireGuard handshake message has 148 bytes, so a data packet
// is at least 176 bytes long.
func TestPrivilegedSourceRange(t *testing.T) {
	t.Run("udp both directions", func(t *testing.T) {
		runSourceRange(t, "10.220", sourceRangeScenario{
			transport: "udp",
			body: `      mode: failover
      routes: ["SERVER:5000/udp src 20000-20999"]
`,
			ingress: [2]int{20000, 20999},
			egress:  [2]int{20000, 20999},
		})
	})
	t.Run("icmp both directions", func(t *testing.T) {
		runSourceRange(t, "10.221", sourceRangeScenario{
			transport: "icmp",
			body: `      mode: failover
      routes: ["SERVER:5000/icmp src 20000-20999"]
`,
			ingress: [2]int{20000, 20999},
			egress:  [2]int{20000, 20999},
		})
	})
	t.Run("udp separate egress", func(t *testing.T) {
		runSourceRange(t, "10.222", sourceRangeScenario{
			transport: "udp",
			body: `      ingress:
        routes: ["SERVER:5000/udp src 20000-20999"]
      egress:
        routes: ["SERVER:5010/udp src 30000-30999"]
`,
			ingress:  [2]int{20000, 20999},
			egress:   [2]int{30000, 30999},
			separate: true,
		})
	})
	t.Run("icmp separate egress", func(t *testing.T) {
		runSourceRange(t, "10.223", sourceRangeScenario{
			transport: "icmp",
			body: `      ingress:
        routes: ["SERVER:5000/icmp src 20000-20999"]
      egress:
        routes: ["SERVER:5010/icmp src 30000-30999"]
`,
			ingress:  [2]int{20000, 20999},
			egress:   [2]int{30000, 30999},
			separate: true,
		})
	})
}

// sourceRangeRule is one rule of the switch. The test reads its counter by the
// comment. A drop rule must keep the counter at zero, and a counting rule must
// raise it above zero.
type sourceRangeRule struct {
	comment string
	text    string
	drop    bool
}

// runSourceRange builds the topology in the range prefix.1.0/24 (client .1, server
// .2), with the peer behind the client on prefix.3.0/24 and the echo target behind
// the server on prefix.2.0/24. The peer sends to the client address on the peer
// link, prefix.3.1.
func runSourceRange(t *testing.T, prefix string, scenario sourceRangeScenario) {
	t.Helper()
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
	clientAddress, serverAddress := prefix+".1.1", prefix+".1.2"
	addressLink(t, clientNS, "mc"+suffix, clientAddress+"/24")
	addressLink(t, serverNS, "ms"+suffix, serverAddress+"/24")
	linkPair(t, "st"+suffix, serverNS, "ts"+suffix, targetNS)
	addressLink(t, serverNS, "st"+suffix, prefix+".2.1/24")
	addressLink(t, targetNS, "ts"+suffix, prefix+".2.2/24")
	linkPair(t, "cp"+suffix, clientNS, "pc"+suffix, peerNS)
	addressLink(t, clientNS, "cp"+suffix, prefix+".3.1/24")
	addressLink(t, peerNS, "pc"+suffix, prefix+".3.2/24")

	// The switch rules exist before the daemons start. The rules match the packets
	// by the switch port, so they see only the wrapped packets of the group. A data
	// packet is longer than 76 bytes, and a control frame is exactly 76 bytes.
	clientPort, serverPort := "bmc"+suffix, "bms"+suffix
	var field, ingressType, egressType string
	protocolMatch := "ip protocol " + scenario.transport
	if scenario.transport == "udp" {
		field = "udp sport"
	} else {
		field = "icmp id"
		ingressType, egressType = "icmp type echo-request ", "icmp type echo-reply "
	}
	ingressMatch := fmt.Sprintf("iifname %s ip daddr %s %s ip length > 76 %s", clientPort, serverAddress, protocolMatch, ingressType)
	egressMatch := fmt.Sprintf("iifname %s ip daddr %s %s ip length > 76 %s", serverPort, clientAddress, protocolMatch, egressType)
	ingressRange := fmt.Sprintf("%d-%d", scenario.ingress[0], scenario.ingress[1])
	egressRange := fmt.Sprintf("%d-%d", scenario.egress[0], scenario.egress[1])
	rules := []sourceRangeRule{
		{"ingress_outside_range", ingressMatch + field + " != " + ingressRange + " counter drop", true},
		{"egress_outside_range", egressMatch + field + " != " + egressRange + " counter drop", true},
	}
	if scenario.transport == "icmp" {
		// An Echo sequence with the tag 0 would mean that the range was ignored. The
		// tags 1 to 8 give the sequences 4096 to 36863.
		rules = append(rules,
			sourceRangeRule{"ingress_tag_zero", ingressMatch + "icmp sequence 0-4095 counter drop", true},
			sourceRangeRule{"egress_tag_zero", egressMatch + "icmp sequence 0-4095 counter drop", true},
		)
	}
	rules = append(rules,
		sourceRangeRule{"ingress_inside_range", ingressMatch + field + " " + ingressRange + " counter", false},
		sourceRangeRule{"egress_inside_range", egressMatch + field + " " + egressRange + " counter", false},
	)
	if scenario.transport == "icmp" {
		rules = append(rules,
			sourceRangeRule{"ingress_tagged", ingressMatch + "icmp sequence 4096-36863 counter", false},
			sourceRangeRule{"egress_tagged", egressMatch + "icmp sequence 4096-36863 counter", false},
		)
	}
	runInNamespace(t, switchNS, "nft", "add", "table", "bridge", "mup")
	runInNamespace(t, switchNS, "nft", "add", "chain", "bridge", "mup", "forward", "{ type filter hook forward priority 0 ; }")

	// The set collects the distinct source values of the ingress data packets. A
	// kernel that refuses the dynamic set in the bridge family only skips that one
	// assertion.
	setType := "type inet_service"
	if scenario.transport == "icmp" {
		setType = "typeof icmp id"
	}
	seenSet := tryNft(switchNS, "add", "set", "bridge", "mup", "seen", "{ "+setType+" ; flags dynamic ; size 65536 ; }") == nil
	if seenSet {
		setRule := ingressMatch + "add @seen { " + field + " }"
		if err := tryNft(switchNS, append([]string{"add", "rule", "bridge", "mup", "forward"}, strings.Fields(setRule)...)...); err != nil {
			t.Logf("the bridge family refused the dynamic set rule, so the test skips the distinct value assertion: %v", err)
			seenSet = false
		}
	} else {
		t.Log("the bridge family refused the dynamic set, so the test skips the distinct value assertion")
	}
	for _, rule := range rules {
		arguments := append([]string{"nft", "add", "rule", "bridge", "mup", "forward"}, strings.Fields(rule.text)...)
		arguments = append(arguments, "comment", `"`+rule.comment+`"`)
		runInNamespace(t, switchNS, arguments...)
	}

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
%s`, clientAddress, clientSocket, strings.ReplaceAll(scenario.body, "SERVER", serverAddress))
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
	// serverView shows the paths that the server holds for the client, which
	// tells a registration fault from a probe fault.
	serverView := func() string {
		clients, err := serverAPI.Clients(context.Background())
		if err != nil {
			return fmt.Sprintf("server clients: <%v>", err)
		}
		text := "server clients:"
		for _, registered := range clients {
			text += fmt.Sprintf(" [%s paths=%d", registered.AdvertisedIP, len(registered.Paths))
			for _, path := range registered.Paths {
				text += fmt.Sprintf(" path %d %s src %d-%d", path.ID, path.Transport, path.SrcFirst, path.SrcLast)
			}
			for _, group := range registered.Egresses {
				for _, path := range group.Paths {
					text += fmt.Sprintf(" egress %d %s:%d healthy=%v %d/%d src %d-%d", path.ID, path.Transport, path.Port, path.Healthy, path.HealthyMembers, path.Members, path.SrcFirst, path.SrcLast)
				}
			}
			text += "]"
		}
		return text
	}
	state := func() string {
		return fmt.Sprintf("%s\n%s\nclient %s\nserver %s\nswitch:\n%s\n%s",
			pathText(t, clientAPI), serverView(), dropText(t, clientAPI), dropText(t, serverAPI), switchCounters(switchNS), logs())
	}

	waitForRegisteredPaths(t, serverAPI, 1, logs)
	wantPaths := 1
	if scenario.separate {
		wantPaths = 2
	}
	waitFor(t, 30*time.Second, "all client paths to become healthy", state, func() (bool, error) {
		paths, err := clientAPI.Paths(context.Background())
		if err != nil || len(paths) < wantPaths {
			return false, err
		}
		for _, path := range paths {
			if !path.Healthy {
				return false, nil
			}
		}
		return true, nil
	})
	if scenario.separate {
		waitFor(t, 30*time.Second, "the server to see the egress path healthy", state, func() (bool, error) {
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
		// The server takes a new egress path as healthy for its first 6 seconds.
		// After that it sends a reply only through a path that a probe reply of the
		// client confirmed. The wait passes the first window, so the exchange needs
		// the confirmed path.
		time.Sleep(8 * time.Second)
	}

	// Three rounds of ten messages give about thirty data packets in each direction.
	// The peer sends to the client address on the peer link.
	for round := 0; round < 3; round++ {
		exchangeFrom(t, peerNS, prefix+".3.2:0", prefix+".3.1:51820", 10, state)
	}

	result, err := readSwitch(switchNS)
	if err != nil {
		t.Fatalf("read the switch rules: %v\n%s", err, state())
	}
	for _, rule := range rules {
		packets, ok := result.packets[rule.comment]
		if !ok {
			t.Fatalf("the switch has no counter %s\n%s", rule.comment, state())
		}
		if rule.drop && packets != 0 {
			t.Fatalf("the switch dropped %d packets by rule %s (%s)\n%s", packets, rule.comment, rule.text, state())
		}
		if !rule.drop && packets == 0 {
			t.Fatalf("the switch counted no packets by rule %s (%s)\n%s", rule.comment, rule.text, state())
		}
	}
	if seenSet {
		if len(result.seen) < 3 {
			t.Fatalf("the ingress data packets used %d distinct source values %v, want at least 3\n%s", len(result.seen), result.seen, state())
		}
		for _, value := range result.seen {
			if value < scenario.ingress[0] || value > scenario.ingress[1] {
				t.Fatalf("the ingress source value %d is outside %s\n%s", value, ingressRange, state())
			}
		}
	}

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
	for _, name := range []string{"NO_PATH", "NOT_REGISTERED"} {
		if dropped := dropCount(serverStatus.Drops, name); dropped != 0 {
			t.Fatalf("server dropped %d packets as %s\n%s", dropped, name, state())
		}
	}
}

// switchResult holds the packet counters of the rules by comment and the distinct
// values of the dynamic set.
type switchResult struct {
	packets map[string]uint64
	seen    []int
}

// nftListing is the part of the JSON output of nft that the test reads.
type nftListing struct {
	Nftables []struct {
		Rule *struct {
			Comment string                       `json:"comment"`
			Expr    []map[string]json.RawMessage `json:"expr"`
		} `json:"rule"`
		Set *struct {
			Name string            `json:"name"`
			Elem []json.RawMessage `json:"elem"`
		} `json:"set"`
	} `json:"nftables"`
}

// readSwitch reads the counters and the set of the table mup in the switch.
func readSwitch(switchNS string) (switchResult, error) {
	result := switchResult{packets: map[string]uint64{}}
	output, err := exec.Command("ip", "netns", "exec", switchNS, "nft", "-j", "list", "table", "bridge", "mup").CombinedOutput()
	if err != nil {
		return result, fmt.Errorf("nft list: %w\n%s", err, output)
	}
	var listing nftListing
	if err := json.Unmarshal(output, &listing); err != nil {
		return result, fmt.Errorf("parse nft output: %w\n%s", err, output)
	}
	for _, item := range listing.Nftables {
		if item.Rule != nil && item.Rule.Comment != "" {
			for _, expression := range item.Rule.Expr {
				raw, ok := expression["counter"]
				if !ok {
					continue
				}
				var counter struct {
					Packets uint64 `json:"packets"`
				}
				if err := json.Unmarshal(raw, &counter); err != nil {
					return result, fmt.Errorf("parse counter of %s: %w", item.Rule.Comment, err)
				}
				result.packets[item.Rule.Comment] = counter.Packets
			}
		}
		if item.Set != nil && item.Set.Name == "seen" {
			for _, raw := range item.Set.Elem {
				// An element is a number, or an object that wraps the number.
				var value int
				if err := json.Unmarshal(raw, &value); err == nil {
					result.seen = append(result.seen, value)
					continue
				}
				var wrapped struct {
					Elem struct {
						Val int `json:"val"`
					} `json:"elem"`
				}
				if err := json.Unmarshal(raw, &wrapped); err != nil {
					return result, fmt.Errorf("parse set element %s: %w", raw, err)
				}
				result.seen = append(result.seen, wrapped.Elem.Val)
			}
		}
	}
	return result, nil
}

// switchCounters prints the table of the switch for a failure message.
func switchCounters(switchNS string) string {
	output, err := exec.Command("ip", "netns", "exec", switchNS, "nft", "list", "table", "bridge", "mup").CombinedOutput()
	if err != nil {
		return fmt.Sprintf("<nft list: %v>", err)
	}
	return string(output)
}

// tryNft runs nft in the namespace and returns its error, so the caller can skip
// a feature that the kernel refuses.
func tryNft(namespace string, arguments ...string) error {
	command := exec.Command("ip", append([]string{"netns", "exec", namespace, "nft"}, arguments...)...)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("nft %v: %w\n%s", arguments, err, output)
	}
	return nil
}
