package main

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/xshecan/mup/api"
	"github.com/xshecan/mup/protocol"
)

func newTable(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
}

func row(table *tabwriter.Writer, cells ...string) {
	_, _ = fmt.Fprintln(table, strings.Join(cells, "\t"))
}

func printStatus(w io.Writer, status api.Status, clients []api.RegisteredClient, wide bool, now time.Time) {
	fields := newTable(w)
	field := func(name, value string) { row(fields, name+":", value) }
	field("Role", status.Role)
	switch {
	case status.Client != nil:
		client := status.Client
		healthy, total, egressHealthy, egressTotal := 0, 0, 0, 0
		for _, path := range client.Paths {
			if path.Direction == "egress" {
				egressTotal++
				if path.Healthy {
					egressHealthy++
				}
				continue
			}
			total++
			if path.Healthy {
				healthy++
			}
		}
		field("IP", client.AdvertisedIP)
		field("Uptime", humanDuration(now.Sub(status.StartedAt)))
		field("Paths", fmt.Sprintf("%d/%d healthy, generation %d", healthy, total, client.Generation))
		if egressTotal > 0 {
			field("Egress paths", fmt.Sprintf("%d/%d healthy", egressHealthy, egressTotal))
		}
		field("Peers", strconv.FormatUint(client.Peers, 10))
		field("Tokens", tokenUsage(client))
		field("Drops", dropSummary(status.Drops))
		_ = fields.Flush()
		_, _ = fmt.Fprintln(w)
		printGroups(w, client.Groups)
		_, _ = fmt.Fprintln(w)
		printPaths(w, client.Paths, wide, now)
	case status.Server != nil:
		server := status.Server
		port := strconv.Itoa(int(server.Port))
		if server.PortLast > server.Port {
			port += "-" + strconv.Itoa(int(server.PortLast))
		}
		field("Port", port)
		target := server.Target
		if server.TargetIngress {
			target += " (ingress delivery)"
		}
		field("Target", target)
		field("Uptime", humanDuration(now.Sub(status.StartedAt)))
		field("Clients", fmt.Sprintf("%d, with %d paths", server.Clients, server.Paths))
		field("Peers", strconv.FormatUint(server.Peers, 10))
		field("Target ports", fmt.Sprintf("%d free, %d quarantined", server.PortsFree, server.PortsQuarantined))
		field("Duplicates", fmt.Sprintf("%d in the cache", server.Duplicates))
		field("Drops", dropSummary(status.Drops))
		_ = fields.Flush()
		_, _ = fmt.Fprintln(w)
		printClients(w, clients, wide)
	case status.Bridge != nil:
		bridge := status.Bridge
		// A bridge with several entries shows them in a table after the
		// fields. One entry keeps the Server, Port, and Allow fields.
		several := len(bridge.Entries) > 1
		if !several {
			field("Server", bridge.Server)
			field("Port", bridgePort(bridge.Port, bridge.PortLast))
			field("Allow", orDash(strings.Join(bridge.Allow, ", ")))
		}
		field("Addresses", orDash(strings.Join(bridge.Addresses, ", ")))
		field("Uptime", humanDuration(now.Sub(status.StartedAt)))
		field("Ingress", fmt.Sprintf("%d packets, %s", bridge.IngressPackets, humanBytes(bridge.IngressBytes)))
		field("Egress", fmt.Sprintf("%d packets, %s", bridge.EgressPackets, humanBytes(bridge.EgressBytes)))
		field("Drops", dropSummary(status.Drops))
		_ = fields.Flush()
		if several {
			_, _ = fmt.Fprintln(w)
			printBridgeEntries(w, bridge.Entries)
		}
	default:
		_ = fields.Flush()
	}
}

// bridgePort shows the ports of a bridge as FIRST-LAST, or as PORT for one
// port.
func bridgePort(first, last uint16) string {
	port := strconv.Itoa(int(first))
	if last > first {
		port += "-" + strconv.Itoa(int(last))
	}
	return port
}

// printBridgeEntries shows one row for each entry of a bridge.
func printBridgeEntries(w io.Writer, entries []api.BridgeEntryStatus) {
	table := newTable(w)
	row(table, "SERVER", "PORT", "ALLOW")
	for _, entry := range entries {
		row(table, entry.Server, bridgePort(entry.Port, entry.PortLast), orDash(strings.Join(entry.Allow, ", ")))
	}
	_ = table.Flush()
}

// humanBytes shows a byte count with a binary unit.
func humanBytes(count uint64) string {
	const unit = 1024
	if count < unit {
		return fmt.Sprintf("%d B", count)
	}
	value, prefix := float64(count)/unit, 0
	for value >= unit && prefix < 4 {
		value /= unit
		prefix++
	}
	return fmt.Sprintf("%.1f %ciB", value, "KMGTP"[prefix])
}

// tokenUsage shows the peer tokens in use against the quota. A quarantined
// token waits before its next use, so it counts as used.
func tokenUsage(client *api.ClientStatus) string {
	quota := client.TokensQuota
	if quota == 0 {
		quota = uint64(protocol.MaxPeerToken)
	}
	used := quota - min(client.TokensFree, quota)
	return fmt.Sprintf("%d/%d", used, quota)
}

func printGroups(w io.Writer, groups []api.Group) {
	if len(groups) == 0 {
		_, _ = fmt.Fprintln(w, "No groups found.")
		return
	}
	split := false
	for _, group := range groups {
		split = split || group.EgressMode != ""
	}
	table := newTable(w)
	if split {
		row(table, "GROUP", "MODE", "PATHS", "EGRESS MODE", "EGRESS PATHS", "PEERS")
	} else {
		row(table, "GROUP", "MODE", "PATHS", "PEERS")
	}
	for _, group := range groups {
		cells := []string{
			strconv.Itoa(int(group.ListenPort)),
			group.Mode,
			fmt.Sprintf("%d/%d healthy", group.HealthyPaths, group.Paths),
		}
		if split {
			egressPaths := "-"
			if group.EgressMode != "" {
				egressPaths = fmt.Sprintf("%d/%d healthy", group.HealthyEgressPaths, group.EgressPaths)
			}
			cells = append(cells, orDash(group.EgressMode), egressPaths)
		}
		row(table, append(cells, strconv.Itoa(group.Peers))...)
	}
	_ = table.Flush()
}

func printPaths(w io.Writer, paths []api.Path, wide bool, now time.Time) {
	if len(paths) == 0 {
		_, _ = fmt.Fprintln(w, "No paths found.")
		return
	}
	split, bridged := false, false
	for _, path := range paths {
		split = split || path.Direction != ""
		bridged = bridged || path.Bridge
	}
	table := newTable(w)
	// STATE joins the health of a path and its use: a healthy path is active
	// when the group sends on it, and standby when it waits. SEEN is the age of
	// the latest answer of the server: the ACK of an ingress path, or the probe
	// of an egress path.
	header := []string{"ID", "GROUP", "SERVER", "TRANSPORT", "VIA", "INTERFACE", "STATE", "SEEN", "RTT"}
	if split {
		header = []string{"ID", "PATH", "GROUP", "SERVER", "TRANSPORT", "VIA", "INTERFACE", "STATE", "SEEN", "RTT"}
	}
	if bridged {
		// A bridge path shows the bridge address in the SERVER column. KIND
		// bridge-via marks an egress bridge whose via is on the leg from the
		// server to the bridge. On a bridge, the via is the source that the
		// bridge sends from.
		header = slices.Insert(header, 2, "KIND")
	}
	if wide {
		header = append(header, "PORTS", "PRIORITY", "MISSES")
	}
	row(table, header...)
	for _, path := range paths {
		latest := path.LastACK
		if path.Direction == "egress" {
			latest = path.LastProbe
		}
		seen := "never"
		if !latest.IsZero() {
			seen = humanDuration(now.Sub(latest)) + " ago"
		}
		cells := []string{strconv.Itoa(path.ID)}
		if split {
			cells = append(cells, orDash(path.Direction))
		}
		if bridged {
			kind := "route"
			switch {
			case path.BridgeVia:
				kind = "bridge-via"
			case path.Bridge:
				kind = "bridge"
			}
			cells = append(cells, kind)
		}
		cells = append(cells,
			strconv.Itoa(int(path.ListenPort)),
			fmt.Sprintf("%s:%d", path.Server, path.Port),
			path.Transport,
			orDash(path.ReturnIP),
			orDash(path.Interface),
			pathStateText(path),
			seen,
			formatRTT(path.RTTSeconds),
		)
		if wide {
			ports := "-"
			if path.LastPort > path.FirstPort {
				ports = fmt.Sprintf("%d-%d", path.FirstPort, path.LastPort)
			}
			cells = append(cells, ports, strconv.Itoa(int(path.Priority)), strconv.Itoa(path.Misses))
		}
		row(table, cells...)
	}
	_ = table.Flush()
}

func printPeers(w io.Writer, peers []api.Peer) {
	if len(peers) == 0 {
		_, _ = fmt.Fprintln(w, "No peers found.")
		return
	}
	table := newTable(w)
	row(table, "TOKEN", "PEER", "LOCAL", "INTERFACE", "IDLE")
	for _, peer := range peers {
		row(table,
			strconv.FormatUint(uint64(peer.Token), 10),
			peer.Address,
			peer.Local,
			orDash(peer.Interface),
			humanSeconds(peer.IdleSeconds),
		)
	}
	_ = table.Flush()
}

func printRoutes(w io.Writer, routes []api.Route, wide bool) {
	table := newTable(w)
	header := []string{"CLIENT", "TOKEN", "TARGET PORT", "TRANSPORT", "PATH", "IDLE"}
	if wide {
		header = append(header, "NONCE", "SOURCE", "LOCAL", "RETURN IP", "INTERFACE")
	}
	row(table, header...)
	for _, route := range routes {
		cells := []string{
			route.Client,
			strconv.FormatUint(uint64(route.Token), 10),
			strconv.Itoa(int(route.TargetPort)),
			route.Transport,
			strconv.Itoa(int(route.PathID)),
			humanSeconds(route.IdleSeconds),
		}
		if wide {
			cells = append(cells, route.Nonce, route.Source, route.Local, orDash(route.ReturnIP), orDash(route.Interface))
		}
		row(table, cells...)
	}
	_ = table.Flush()
}

func printReflectors(w io.Writer, reflectors []api.Reflector) {
	if len(reflectors) == 0 {
		_, _ = fmt.Fprintln(w, "No return pools found.")
		return
	}
	table := newTable(w)
	row(table, "POOL", "ADDRESS", "TRANSPORT", "HEALTHY")
	for _, reflector := range reflectors {
		healthy := "no"
		if reflector.Healthy {
			healthy = "yes"
		}
		row(table, reflector.Pool, reflector.Address, reflector.Transport, healthy)
	}
	_ = table.Flush()
}

func printClients(w io.Writer, clients []api.RegisteredClient, wide bool) {
	if len(clients) == 0 {
		_, _ = fmt.Fprintln(w, "No clients found.")
		return
	}
	split := false
	for _, client := range clients {
		split = split || client.Egress != nil || len(client.Egresses) > 0
	}
	table := newTable(w)
	header := []string{"CLIENT", "NONCE", "PATHS", "PEERS", "RETURN IP", "LEASE"}
	if split {
		header = append(header, "EGRESS")
	}
	if wide {
		header = append(header, "LISTEN PORT", "PATH LIST")
		if split {
			header = append(header, "EGRESS LIST")
		}
	}
	row(table, header...)
	for _, client := range clients {
		nonce := client.Nonce
		if !wide && len(nonce) > 8 {
			nonce = nonce[:8]
		}
		lease := "expired"
		if client.LeaseSeconds > 0 {
			lease = humanSeconds(client.LeaseSeconds)
		}
		cells := []string{
			client.AdvertisedIP,
			nonce,
			strconv.Itoa(len(client.Paths)),
			strconv.Itoa(client.Peers),
			orDash(client.ReturnIP),
			lease,
		}
		if split {
			cells = append(cells, egressSummary(clientEgresses(client)))
		}
		if wide {
			list := make([]string, 0, len(client.Paths))
			for _, path := range client.Paths {
				list = append(list, fmt.Sprintf("%d:%s:%s", path.ID, path.Transport, path.Local))
			}
			cells = append(cells, listenPorts(client), orDash(strings.Join(list, ",")))
			if split {
				cells = append(cells, egressList(clientEgresses(client)))
			}
		}
		row(table, cells...)
	}
	_ = table.Flush()
}

// clientEgresses returns every egress group of a client. An older server sends
// only Egress.
func clientEgresses(client api.RegisteredClient) []api.EgressGroup {
	if len(client.Egresses) > 0 {
		return client.Egresses
	}
	if client.Egress != nil {
		return []api.EgressGroup{*client.Egress}
	}
	return nil
}

// listenPorts shows the distinct listen ports of the paths of a client. An older
// server sends none, and the listen port of the client stands in.
func listenPorts(client api.RegisteredClient) string {
	seen := make(map[uint16]bool)
	var ports []int
	for _, path := range client.Paths {
		if path.ListenPort != 0 && !seen[path.ListenPort] {
			seen[path.ListenPort] = true
			ports = append(ports, int(path.ListenPort))
		}
	}
	if len(ports) == 0 {
		return strconv.Itoa(int(client.ListenPort))
	}
	sort.Ints(ports)
	text := make([]string, len(ports))
	for i, port := range ports {
		text[i] = strconv.Itoa(port)
	}
	return strings.Join(text, ",")
}

// joinGroups shows the text of one group as it is, and the text of each group
// of a client with more than one prefixed by its listen port.
func joinGroups(groups []api.EgressGroup, text func(api.EgressGroup) string) string {
	if len(groups) == 0 {
		return "-"
	}
	if len(groups) == 1 {
		return text(groups[0])
	}
	list := make([]string, 0, len(groups))
	for _, group := range groups {
		list = append(list, fmt.Sprintf("%d:%s", group.ListenPort, text(group)))
	}
	return strings.Join(list, "; ")
}

// egressSummary shows the healthy egress paths of each group of a client and
// its egress mode.
func egressSummary(groups []api.EgressGroup) string {
	return joinGroups(groups, func(group api.EgressGroup) string {
		healthy := 0
		for _, path := range group.Paths {
			if path.Healthy {
				healthy++
			}
		}
		return fmt.Sprintf("%d/%d healthy, %s", healthy, len(group.Paths), group.Mode)
	})
}

// egressList shows each egress path as ID:TRANSPORT:SERVER:PORT, with the
// healthy members of a path that reflects. A bridge that sends the replies from
// the via shows "reflects via". A bridge via path shows "via" alone, because
// the server sends to the bridge from the via.
func egressList(groups []api.EgressGroup) string {
	return joinGroups(groups, func(group api.EgressGroup) string {
		list := make([]string, 0, len(group.Paths))
		for _, path := range group.Paths {
			text := fmt.Sprintf("%d:%s:%s:%d", path.ID, path.Transport, path.Server, path.Port)
			if path.Bridge {
				text = fmt.Sprintf("%d:%s:bridge %s:%d", path.ID, path.Transport, path.Server, path.Port)
			}
			if path.ReturnIP != "" {
				via := "via"
				if path.Bridge && !path.BridgeVia {
					via = "reflects via"
				}
				text += fmt.Sprintf(" %s %s (%d/%d)", via, path.ReturnIP, path.HealthyMembers, path.Members)
			}
			list = append(list, text)
		}
		return orDash(strings.Join(list, ","))
	})
}

// printDrops lists the nonzero counters, or every counter in wide output.
func printDrops(w io.Writer, drops []api.Drop, wide bool) {
	shown := make([]api.Drop, 0, len(drops))
	for _, drop := range drops {
		if wide || drop.Count > 0 {
			shown = append(shown, drop)
		}
	}
	if len(shown) == 0 {
		_, _ = fmt.Fprintln(w, "No drops.")
		return
	}
	table := newTable(w)
	row(table, "REASON", "NAME", "COUNT")
	for _, drop := range shown {
		row(table, strconv.Itoa(int(drop.Reason)), drop.Name, strconv.FormatUint(drop.Count, 10))
	}
	_ = table.Flush()
}

// dropSummary shows the total and the three largest counters.
func dropSummary(drops []api.Drop) string {
	var total uint64
	nonzero := make([]api.Drop, 0, len(drops))
	for _, drop := range drops {
		total += drop.Count
		if drop.Count > 0 {
			nonzero = append(nonzero, drop)
		}
	}
	if total == 0 {
		return "0"
	}
	slices.SortStableFunc(nonzero, func(a, b api.Drop) int { return cmp.Compare(b.Count, a.Count) })
	parts := make([]string, 0, 3)
	for _, drop := range nonzero[:min(3, len(nonzero))] {
		parts = append(parts, fmt.Sprintf("%s %d", drop.Name, drop.Count))
	}
	return fmt.Sprintf("%d (%s)", total, strings.Join(parts, ", "))
}

// humanDuration formats a duration like kubectl: 45s, 3m20s, 5h12m, 2d4h.
func humanDuration(duration time.Duration) string {
	seconds := int64(max(duration, 0).Round(time.Second) / time.Second)
	switch {
	case seconds < 60:
		return fmt.Sprintf("%ds", seconds)
	case seconds < 3600:
		return twoUnits(seconds/60, "m", seconds%60, "s")
	case seconds < 86400:
		return twoUnits(seconds/3600, "h", seconds%3600/60, "m")
	}
	return twoUnits(seconds/86400, "d", seconds%86400/3600, "h")
}

func twoUnits(major int64, majorUnit string, minor int64, minorUnit string) string {
	if minor == 0 {
		return fmt.Sprintf("%d%s", major, majorUnit)
	}
	return fmt.Sprintf("%d%s%d%s", major, majorUnit, minor, minorUnit)
}

func humanSeconds(seconds float64) string {
	return humanDuration(time.Duration(seconds * float64(time.Second)))
}

func formatRTT(seconds float64) string {
	if seconds <= 0 {
		return "-"
	}
	return time.Duration(seconds * float64(time.Second)).Round(100 * time.Microsecond).String()
}

func healthText(healthy bool) string {
	if healthy {
		return "healthy"
	}
	return "unhealthy"
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

// pathStatusText shows the health of a path, and the reason of an unhealthy
// path when the daemon knows it.
// pathStateText gives one word for the health and the use of a path: active
// for a healthy path that the group sends on, standby for a healthy path that
// waits, and unhealthy, with the reason if the daemon gave one.
func pathStateText(path api.Path) string {
	if !path.Healthy {
		return pathStatusText(path)
	}
	if path.InUse {
		return "active"
	}
	return "standby"
}

func pathStatusText(path api.Path) string {
	text := healthText(path.Healthy)
	if !path.Healthy && path.Reason != "" {
		text += " (" + path.Reason + ")"
	}
	return text
}
