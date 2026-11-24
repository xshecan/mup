package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/xshecan/mup/api"
)

// TestPrivilegedBridgeWithTwoEntries runs one bridge with two entries and one
// client with two groups. Entry 1 sends the ports 5000-5009 to server A, and entry
// 2 sends the ports 5100-5109 to server B. Group 1 (listen port 51820) uses the
// bridge ports 5000 and 5001, and group 2 (listen port 51821) uses 5100 and 5101,
// both for its ingress and for its egress. So the port of a packet picks the
// server in both directions. The switch drops every IPv4 packet between the
// client and the servers, so only the bridge carries the traffic.
func TestPrivilegedBridgeWithTwoEntries(t *testing.T) {
	requirePrivilegedLinux(t)
	binaryPath := buildDaemon(t)

	const prefix = "10.218"
	suffix := strconv.FormatInt(time.Now().UnixNano()%1_000_000, 10)
	clientNS, serverANS, serverBNS := "mup-client-"+suffix, "mup-servera-"+suffix, "mup-serverb-"+suffix
	targetANS, targetBNS := "mup-targeta-"+suffix, "mup-targetb-"+suffix
	bridgeNS, switchNS, peerNS := "mup-bridge-"+suffix, "mup-switch-"+suffix, "mup-peer-"+suffix
	for _, namespace := range []string{clientNS, serverANS, serverBNS, targetANS, targetBNS, bridgeNS, switchNS, peerNS} {
		addNamespace(t, namespace)
	}
	runIP(t, "-n", switchNS, "link", "add", "br0", "type", "bridge")
	runIP(t, "-n", switchNS, "link", "set", "br0", "up")
	for _, member := range []struct{ link, namespace string }{
		{"mc" + suffix, clientNS}, {"msa" + suffix, serverANS}, {"msb" + suffix, serverBNS}, {"mb" + suffix, bridgeNS},
	} {
		port := "b" + member.link
		linkPair(t, member.link, member.namespace, port, switchNS)
		runIP(t, "-n", switchNS, "link", "set", port, "master", "br0", "up")
	}
	clientAddress, serverA, serverB, bridgeAddress := prefix+".1.1", prefix+".1.2", prefix+".1.3", prefix+".1.4"
	addressLink(t, clientNS, "mc"+suffix, clientAddress+"/24")
	addressLink(t, serverANS, "msa"+suffix, serverA+"/24")
	addressLink(t, serverBNS, "msb"+suffix, serverB+"/24")
	addressLink(t, bridgeNS, "mb"+suffix, bridgeAddress+"/24")
	// Each server has its own echo target with its own address.
	linkPair(t, "sta"+suffix, serverANS, "tsa"+suffix, targetANS)
	addressLink(t, serverANS, "sta"+suffix, prefix+".2.1/24")
	addressLink(t, targetANS, "tsa"+suffix, prefix+".2.2/24")
	linkPair(t, "stb"+suffix, serverBNS, "tsb"+suffix, targetBNS)
	addressLink(t, serverBNS, "stb"+suffix, prefix+".4.1/24")
	addressLink(t, targetBNS, "tsb"+suffix, prefix+".4.2/24")
	linkPair(t, "cp"+suffix, clientNS, "pc"+suffix, peerNS)
	addressLink(t, clientNS, "cp"+suffix, prefix+".3.1/24")
	addressLink(t, peerNS, "pc"+suffix, prefix+".3.2/24")
	runInNamespace(t, bridgeNS, "sysctl", "-qw", "net.ipv4.ip_forward=1")

	// The switch rules exist before the daemons start. The first rule drops every
	// IPv4 packet from the port of the client to a server, so no ingress packet
	// goes straight. The next two rules drop every IPv4 packet from the port of
	// a server to the client, so no reply goes straight. A packet that arrives
	// at a server or at the client therefore came through the bridge.
	runInNamespace(t, switchNS, "nft", "add", "table", "bridge", "mup")
	runInNamespace(t, switchNS, "nft", "add", "chain", "bridge", "mup", "forward", "{ type filter hook forward priority 0 ; }")
	runInNamespace(t, switchNS, "nft", "add", "rule", "bridge", "mup", "forward", "iifname", "bmc"+suffix,
		"ip", "daddr", "{ "+serverA+", "+serverB+" }", "drop")
	runInNamespace(t, switchNS, "nft", "add", "rule", "bridge", "mup", "forward", "iifname", "bmsa"+suffix,
		"ip", "daddr", clientAddress, "drop")
	runInNamespace(t, switchNS, "nft", "add", "rule", "bridge", "mup", "forward", "iifname", "bmsb"+suffix,
		"ip", "daddr", clientAddress, "drop")

	targetA := startEchoTarget(t, targetANS, prefix+".2.2:51820")
	defer targetA.stop(t)
	targetB := startEchoTarget(t, targetBNS, prefix+".4.2:51820")
	defer targetB.stop(t)

	directory := t.TempDir()
	serverASocket := filepath.Join(directory, "servera.sock")
	serverBSocket := filepath.Join(directory, "serverb.sock")
	bridgeSocket := filepath.Join(directory, "bridge.sock")
	clientSocket := filepath.Join(directory, "client.sock")
	serverAProcess := startNamespaced(t, serverANS, binaryPath, "server", "-p", "5000-5009", "-r", prefix+".2.2:51820", "--control-socket", serverASocket)
	defer serverAProcess.stop(t)
	serverBProcess := startNamespaced(t, serverBNS, binaryPath, "server", "-p", "5100-5109", "-r", prefix+".4.2:51820", "--control-socket", serverBSocket)
	defer serverBProcess.stop(t)

	// A list of bridge entries needs a configuration file. The socket of the
	// list is the socket of its first entry. The second entry lists an address
	// that no host uses, so the status shows an allow list for it.
	bridgeConfiguration := filepath.Join(directory, "bridge.yaml")
	bridgeContent := fmt.Sprintf(`bridges:
  - server: %s
    port: 5000-5009
    control_socket: %s
  - server: %s
    port: 5100-5109
    allow:
      - %s.1.9/32
`, serverA, bridgeSocket, serverB, prefix)
	if err := os.WriteFile(bridgeConfiguration, []byte(bridgeContent), 0o600); err != nil {
		t.Fatalf("write bridge configuration: %v", err)
	}
	bridge := startNamespaced(t, bridgeNS, binaryPath, "--config", bridgeConfiguration)
	defer bridge.stop(t)

	configuration := filepath.Join(directory, "client.yaml")
	content := fmt.Sprintf(`client:
  advertise: %[1]s
  control_socket: %[2]s
  servers:
    - port: 51820
      ingress:
        bridges: [%[3]s:5000/udp]
      egress:
        bridges: [%[3]s:5001/udp]
    - port: 51821
      ingress:
        bridges: [%[3]s:5100/udp]
      egress:
        bridges: [%[3]s:5101/udp]
`, clientAddress, clientSocket, bridgeAddress)
	if err := os.WriteFile(configuration, []byte(content), 0o600); err != nil {
		t.Fatalf("write client configuration: %v", err)
	}
	client := startNamespaced(t, clientNS, binaryPath, "--config", configuration)
	defer client.stop(t)

	clientAPI := api.NewDaemonClient(clientSocket)
	serverAAPI := api.NewDaemonClient(serverASocket)
	serverBAPI := api.NewDaemonClient(serverBSocket)
	bridgeAPI := api.NewDaemonClient(bridgeSocket)
	logs := func() string {
		return fmt.Sprintf("client log:\n%s\nserver A log:\n%s\nserver B log:\n%s\nbridge log:\n%s\ntarget A log:\n%s\ntarget B log:\n%s",
			client.log(t), serverAProcess.log(t), serverBProcess.log(t), bridge.log(t), targetA.log(t), targetB.log(t))
	}
	state := func() string {
		return fmt.Sprintf("%s\nclient %s\nserver A %s\nserver B %s\nbridge %s\n%s",
			pathText(t, clientAPI), dropText(t, clientAPI), dropText(t, serverAAPI), dropText(t, serverBAPI), dropText(t, bridgeAPI), logs())
	}

	// Each group has an ingress path and an egress path. All four paths are
	// healthy when the client sees them healthy and each server sees the egress
	// path of its own group healthy.
	waitFor(t, 30*time.Second, "the paths of both groups to become healthy", state, func() (bool, error) {
		paths, err := clientAPI.Paths(context.Background())
		if err != nil {
			return false, err
		}
		healthy := map[string]int{}
		for _, path := range paths {
			if !path.Bridge || !path.Healthy {
				return false, nil
			}
			healthy[fmt.Sprintf("%d/%s", path.ListenPort, path.Direction)]++
		}
		for _, key := range []string{"51820/ingress", "51820/egress", "51821/ingress", "51821/egress"} {
			if healthy[key] != 1 {
				return false, nil
			}
		}
		for _, server := range []*api.DaemonClient{serverAAPI, serverBAPI} {
			clients, err := server.Clients(context.Background())
			if err != nil {
				return false, err
			}
			seen := false
			for _, registered := range clients {
				for _, group := range registered.Egresses {
					for _, path := range group.Paths {
						if !path.Healthy {
							return false, nil
						}
						seen = true
					}
				}
			}
			if !seen {
				return false, nil
			}
		}
		return true, nil
	})

	// The server takes a new egress path as healthy for its first 6 seconds.
	// After that it sends a reply only through a member that a probe reply of
	// the client confirmed. The wait passes the first window, so the exchange
	// needs the confirmed bridge member.
	time.Sleep(8 * time.Second)
	for round := 0; round < 2; round++ {
		exchangeFrom(t, peerNS, prefix+".3.2:0", prefix+".3.1:51820", 3, state)
		exchangeFrom(t, peerNS, prefix+".3.2:0", prefix+".3.1:51821", 3, state)
	}

	// Server A must hold only the paths of group 1, and server B only the paths
	// of group 2. A path of the other group on a server means the bridge sent a
	// packet to the wrong entry. Both servers must hold at least one ingress path
	// and one egress group of their own group.
	for _, server := range []struct {
		name       string
		api        *api.DaemonClient
		listenPort uint16
	}{
		{"A", serverAAPI, 51820}, {"B", serverBAPI, 51821},
	} {
		clients, err := server.api.Clients(context.Background())
		if err != nil {
			t.Fatalf("clients of server %s: %v", server.name, err)
		}
		ingress, egress := 0, 0
		for _, registered := range clients {
			for _, path := range registered.Paths {
				if path.ListenPort != server.listenPort {
					t.Fatalf("server %s holds an ingress path of listen port %d, want only %d\n%s", server.name, path.ListenPort, server.listenPort, state())
				}
				ingress++
			}
			for _, group := range registered.Egresses {
				if group.ListenPort != server.listenPort {
					t.Fatalf("server %s holds an egress group of listen port %d, want only %d\n%s", server.name, group.ListenPort, server.listenPort, state())
				}
				egress += len(group.Paths)
			}
		}
		if ingress == 0 || egress == 0 {
			t.Fatalf("server %s holds %d ingress paths and %d egress paths of group %d, want both\n%s", server.name, ingress, egress, server.listenPort, state())
		}
	}

	// The bridge lists both entries. The test reads the JSON of the status
	// endpoint, so it compiles without the Entries field of api.BridgeStatus.
	// TODO: when api.BridgeStatus has Entries, read them from bridgeAPI.Status.
	entries := bridgeEntries(t, bridgeSocket)
	if len(entries) != 2 {
		t.Fatalf("bridge status has %d entries, want 2: %#v\n%s", len(entries), entries, state())
	}
	for index, want := range []struct {
		server         string
		port, portLast uint16
		allow          int
	}{
		{serverA, 5000, 5009, 0}, {serverB, 5100, 5109, 1},
	} {
		got := entries[index]
		if got.Server != want.server || got.Port != want.port || got.PortLast != want.portLast || len(got.Allow) != want.allow {
			t.Fatalf("bridge entry %d = %#v, want server %s ports %d-%d and %d allow ranges\n%s",
				index+1, got, want.server, want.port, want.portLast, want.allow, state())
		}
	}

	// Both directions pass the bridge, and no daemon drops a packet.
	bridgeStatus, err := bridgeAPI.Status(context.Background())
	if err != nil || bridgeStatus.Bridge == nil {
		t.Fatalf("bridge status = %#v, %v", bridgeStatus, err)
	}
	if bridgeStatus.Bridge.IngressPackets == 0 || bridgeStatus.Bridge.EgressPackets == 0 {
		t.Fatalf("bridge sent %d packets ingress and %d egress, want both\n%s", bridgeStatus.Bridge.IngressPackets, bridgeStatus.Bridge.EgressPackets, state())
	}
	for _, drop := range bridgeStatus.Drops {
		if drop.Count != 0 {
			t.Fatalf("bridge drop %s = %d, want 0\n%s", drop.Name, drop.Count, state())
		}
	}
	clientStatus, err := clientAPI.Status(context.Background())
	if err != nil {
		t.Fatalf("client status: %v", err)
	}
	if refused := dropCount(clientStatus.Drops, "EGRESS_SOURCE"); refused != 0 {
		t.Fatalf("client refused %d egress packets\n%s", refused, state())
	}
}

// bridgeEntry is one entry of the bridge status, as the JSON of the status
// endpoint shows it.
type bridgeEntry struct {
	Server   string   `json:"server"`
	Port     uint16   `json:"port"`
	PortLast uint16   `json:"port_last"`
	Allow    []string `json:"allow"`
}

// bridgeEntries reads the entries of the bridge status from the JSON of the
// status endpoint. It returns nil when the status has no entries.
func bridgeEntries(t *testing.T, socket string) []bridgeEntry {
	t.Helper()
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socket)
		}},
	}
	response, err := httpClient.Get("http://mup/v1/status")
	if err != nil {
		t.Fatalf("read the bridge status: %v", err)
	}
	defer response.Body.Close()
	var status struct {
		Bridge struct {
			Entries []bridgeEntry `json:"entries"`
		} `json:"bridge"`
	}
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		t.Fatalf("decode the bridge status: %v", err)
	}
	return status.Bridge.Entries
}
