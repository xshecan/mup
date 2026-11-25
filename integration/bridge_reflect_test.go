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

// TestPrivilegedEgressBridgeReflect runs a group whose egress is a bridge entry
// with the transport icmp and a via. The server reflects the wrapper off the via
// host. It sends an Echo Request from the address of the bridge (forged) to the via
// host, with the port of the entry as the identifier. The kernel of the via host
// answers with an Echo Reply to the bridge. The bridge removes the wrapper and sends
// the inner reply to the client. The switch drops every packet from the server to
// the bridge, every UDP packet from the via host to the bridge (the old forged
// wrapper), and every packet from the server to the client, so only the reflection
// can carry the egress path.
func TestPrivilegedEgressBridgeReflect(t *testing.T) {
	runEgressBridgeReflect(t, "10.225", true)
}

// TestPrivilegedEgressBridgeReflectNeedsAllow starts the same group with a bridge
// that does not list the via host. The bridge unwraps only packets from allowed
// sources, so it drops every Echo Reply of the via host and the egress path never
// becomes healthy.
func TestPrivilegedEgressBridgeReflectNeedsAllow(t *testing.T) {
	runEgressBridgeReflect(t, "10.226", false)
}

// runEgressBridgeReflect builds the topology in the range prefix.1.0/24 (client .1,
// server .2, bridge .4, via host .5), with the peer behind the client on
// prefix.3.0/24 and the echo target behind the server on prefix.2.0/24. The via host
// is a plain namespace without mup. When allowed is false, the bridge does not list
// the via host.
func runEgressBridgeReflect(t *testing.T, prefix string, allowed bool) {
	t.Helper()
	requirePrivilegedLinux(t)
	if _, err := exec.LookPath("ethtool"); err != nil {
		t.Skip("the bridge reflect test needs ethtool")
	}
	binaryPath := buildDaemon(t)

	suffix := strconv.FormatInt(time.Now().UnixNano()%1_000_000, 10)
	clientNS, serverNS, targetNS := "mup-client-"+suffix, "mup-server-"+suffix, "mup-target-"+suffix
	bridgeNS, viaNS := "mup-bridge-"+suffix, "mup-via-"+suffix
	switchNS, peerNS := "mup-switch-"+suffix, "mup-peer-"+suffix
	for _, namespace := range []string{clientNS, serverNS, targetNS, bridgeNS, viaNS, switchNS, peerNS} {
		addNamespace(t, namespace)
	}
	runIP(t, "-n", switchNS, "link", "add", "br0", "type", "bridge")
	runIP(t, "-n", switchNS, "link", "set", "br0", "up")
	for _, member := range []struct{ link, namespace string }{
		{"mc" + suffix, clientNS}, {"ms" + suffix, serverNS}, {"mb" + suffix, bridgeNS}, {"mv" + suffix, viaNS},
	} {
		port := "b" + member.link
		linkPair(t, member.link, member.namespace, port, switchNS)
		runIP(t, "-n", switchNS, "link", "set", port, "master", "br0", "up")
	}
	clientAddress, serverAddress := prefix+".1.1", prefix+".1.2"
	bridgeAddress, viaAddress := prefix+".1.4", prefix+".1.5"
	addressLink(t, clientNS, "mc"+suffix, clientAddress+"/24")
	addressLink(t, serverNS, "ms"+suffix, serverAddress+"/24")
	addressLink(t, bridgeNS, "mb"+suffix, bridgeAddress+"/24")
	addressLink(t, viaNS, "mv"+suffix, viaAddress+"/24")
	linkPair(t, "st"+suffix, serverNS, "ts"+suffix, targetNS)
	addressLink(t, serverNS, "st"+suffix, prefix+".2.1/24")
	addressLink(t, targetNS, "ts"+suffix, prefix+".2.2/24")
	// A veth leaves the checksum of a local packet to a device that never comes,
	// and each namespace trusts such a packet. The via host is a real host that
	// builds a new packet from the bytes, so that trust ends there. The target
	// sends complete checksums, as a target behind a network card does.
	runInNamespace(t, targetNS, "ethtool", "-K", "ts"+suffix, "tx", "off")
	linkPair(t, "cp"+suffix, clientNS, "pc"+suffix, peerNS)
	addressLink(t, clientNS, "cp"+suffix, prefix+".3.1/24")
	addressLink(t, peerNS, "pc"+suffix, prefix+".3.2/24")
	runInNamespace(t, bridgeNS, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	// The via host and the server accept the forged request and its reply on any
	// path, so a strict reverse path filter of the host cannot hide a fault.
	for _, namespace := range []string{viaNS, serverNS, bridgeNS} {
		runInNamespace(t, namespace, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0")
		runInNamespace(t, namespace, "sysctl", "-qw", "net.ipv4.conf.default.rp_filter=0")
	}

	// The switch rules exist before the daemons start. Each rule has a comment, so
	// the test reads its counter. The drop rules must keep the counter at zero,
	// and the counting rules must see the reflection.
	//
	// The first rule drops every IPv4 packet from the port of the bridge with another
	// source than the bridge, so the bridge cannot spoof. The next rules drop every
	// packet of the server to the bridge, the old forged UDP wrapper of the via
	// host, and every packet of the server to the client. The last rules count the
	// forged Echo Request from the server to the via host, and the Echo Reply of
	// the via host to the bridge.
	serverPort, bridgePort, viaPort := "bms"+suffix, "bmb"+suffix, "bmv"+suffix
	rules := []sourceRangeRule{
		{"bridge_spoof", fmt.Sprintf("iifname %s ip saddr != %s counter drop", bridgePort, bridgeAddress), false},
		{"server_to_bridge", fmt.Sprintf("ip saddr %s ip daddr %s counter drop", serverAddress, bridgeAddress), true},
		{"old_wrapper", fmt.Sprintf("iifname %s ip saddr %s ip daddr %s ip protocol udp counter drop", viaPort, viaAddress, bridgeAddress), true},
		{"server_to_client", fmt.Sprintf("iifname %s ip daddr %s counter drop", serverPort, clientAddress), false},
		{"request_to_via", fmt.Sprintf("iifname %s ip saddr %s ip daddr %s ip protocol icmp icmp type echo-request icmp id 5010 counter", serverPort, bridgeAddress, viaAddress), false},
		{"reply_to_bridge", fmt.Sprintf("iifname %s ip saddr %s ip daddr %s ip protocol icmp icmp type echo-reply icmp id 5010 counter", viaPort, viaAddress, bridgeAddress), false},
	}
	runInNamespace(t, switchNS, "nft", "add", "table", "bridge", "mup")
	runInNamespace(t, switchNS, "nft", "add", "chain", "bridge", "mup", "forward", "{ type filter hook forward priority 0 ; }")
	for _, rule := range rules {
		arguments := append([]string{"nft", "add", "rule", "bridge", "mup", "forward"}, strings.Fields(rule.text)...)
		arguments = append(arguments, "comment", `"`+rule.comment+`"`)
		runInNamespace(t, switchNS, arguments...)
	}

	target := startEchoTarget(t, targetNS, prefix+".2.2:51820")
	defer target.stop(t)

	directory := t.TempDir()
	serverSocket := filepath.Join(directory, "server.sock")
	bridgeSocket := filepath.Join(directory, "bridge.sock")
	clientSocket := filepath.Join(directory, "client.sock")
	server := startNamespaced(t, serverNS, binaryPath, "server", "-p", "5000-5009", "-r", prefix+".2.2:51820", "--control-socket", serverSocket)
	defer server.stop(t)
	// The bridge accepts the server and, when allowed, the via host. Without the via
	// host in its allow list, it drops every wrapper that comes back from the host.
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
          - "%s:5010/icmp via %s"
`, clientAddress, clientSocket, serverAddress, bridgeAddress, viaAddress)
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
		return fmt.Sprintf("%s\nclient %s\nserver %s\nbridge %s\nvia host echo requests %d, replies %d\nswitch:\n%s\n%s",
			pathText(t, clientAPI), dropText(t, clientAPI), dropText(t, serverAPI), dropText(t, bridgeAPI),
			viaHostCounter(viaNS, "InEchos"), viaHostCounter(viaNS, "OutEchoReps"), switchCounters(switchNS), logs())
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
	switchPackets := func(comment string) uint64 {
		result, err := readSwitch(switchNS)
		if err != nil {
			t.Fatalf("read the switch rules: %v\n%s", err, state())
		}
		packets, ok := result.packets[comment]
		if !ok {
			t.Fatalf("the switch has no counter %s\n%s", comment, state())
		}
		return packets
	}

	if !allowed {
		// The bridge drops every Echo Reply of the via host, so no probe reaches the
		// client and the egress path stays unhealthy. The server still reflects its
		// probes, and the bridge counts each reply as a drop of its source.
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
				t.Fatalf("the egress path became healthy although the bridge does not allow the via host\n%s", state())
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

	// The egress path becomes healthy once the server probes it through the via
	// host and the probe reply reaches the server. The ingress path becomes healthy
	// once its ACK returns on the egress path, because the direct ACK is dropped.
	waitFor(t, 30*time.Second, "the egress bridge path to become healthy", state, directionHealthy("egress"))
	waitFor(t, 30*time.Second, "the ingress path to become healthy", state, directionHealthy("ingress"))

	// The health of the path rests on the probes alone, so the via host has
	// answered requests for them before any data packet exists.
	probeRequests := viaHostCounter(viaNS, "InEchos")
	if probeRequests == 0 {
		t.Fatalf("the via host received no Echo Request for the probes\n%s", state())
	}

	// The server takes a new egress path as healthy for its first 6 seconds.
	// After that it sends a reply only through a member that a probe reply of
	// the client confirmed. The wait passes the first window, so the exchange
	// needs the confirmed path.
	time.Sleep(8 * time.Second)
	beforeData := viaHostCounter(viaNS, "InEchos")
	exchangeFrom(t, peerNS, prefix+".3.2:0", prefix+".3.1:51820", 3, state)
	if afterData := viaHostCounter(viaNS, "InEchos"); afterData <= beforeData {
		t.Fatalf("the via host received no Echo Request for the data packets (%d before, %d after)\n%s", beforeData, afterData, state())
	}

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

	// The counters prove the path. The server sent Echo Requests from the address
	// of the bridge to the via host, the via host answered the bridge, and no
	// packet used the old routes.
	for _, comment := range []string{"request_to_via", "reply_to_bridge"} {
		if packets := switchPackets(comment); packets == 0 {
			t.Fatalf("the switch counted no packets by rule %s\n%s", comment, state())
		}
	}
	for _, comment := range []string{"server_to_bridge", "old_wrapper"} {
		if packets := switchPackets(comment); packets != 0 {
			t.Fatalf("the switch dropped %d packets by rule %s\n%s", packets, comment, state())
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

// viaHostCounter reads one ICMP counter of the network namespace of the via host
// from /proc/net/snmp, for example InEchos (Echo Requests that the kernel received)
// or OutEchoReps (Echo Replies that it sent). It returns zero when it cannot read
// the counter.
func viaHostCounter(namespace, name string) uint64 {
	output, err := exec.Command("ip", "netns", "exec", namespace, "cat", "/proc/net/snmp").Output()
	if err != nil {
		return 0
	}
	var names []string
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "Icmp:" {
			continue
		}
		if names == nil {
			names = fields
			continue
		}
		for index, field := range names {
			if field == name && index < len(fields) {
				value, err := strconv.ParseUint(fields[index], 10, 64)
				if err != nil {
					return 0
				}
				return value
			}
		}
	}
	return 0
}
