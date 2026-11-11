package main

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/xshecan/mup/api"
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
		healthy := 0
		for _, path := range client.Paths {
			if path.Healthy {
				healthy++
			}
		}
		field("Advertised IP", client.AdvertisedIP)
		field("Uptime", humanDuration(now.Sub(status.StartedAt)))
		field("Paths", fmt.Sprintf("%d/%d healthy, generation %d", healthy, len(client.Paths), client.Generation))
		field("Peers", strconv.FormatUint(client.Peers, 10))
		field("Peer tokens", fmt.Sprintf("%d free, %d quarantined", client.TokensFree, client.TokensQuarantined))
		field("Drops", dropSummary(status.Drops))
		_ = fields.Flush()
		_, _ = fmt.Fprintln(w)
		printGroups(w, client.Groups)
		_, _ = fmt.Fprintln(w)
		printPaths(w, client.Paths, wide, now)
	case status.Server != nil:
		server := status.Server
		field("Port", strconv.Itoa(int(server.Port)))
		field("Target", server.Target)
		field("Uptime", humanDuration(now.Sub(status.StartedAt)))
		field("Clients", fmt.Sprintf("%d, with %d paths", server.Clients, server.Paths))
		field("Peers", strconv.FormatUint(server.Peers, 10))
		field("Target ports", fmt.Sprintf("%d free, %d quarantined", server.PortsFree, server.PortsQuarantined))
		field("Duplicates", fmt.Sprintf("%d in the cache", server.Duplicates))
		field("Drops", dropSummary(status.Drops))
		_ = fields.Flush()
		_, _ = fmt.Fprintln(w)
		printClients(w, clients, wide)
	default:
		_ = fields.Flush()
	}
}

func printGroups(w io.Writer, groups []api.Group) {
	if len(groups) == 0 {
		_, _ = fmt.Fprintln(w, "No groups found.")
		return
	}
	table := newTable(w)
	row(table, "GROUP", "MODE", "PATHS", "PEERS")
	for _, group := range groups {
		row(table,
			strconv.Itoa(int(group.ListenPort)),
			group.Mode,
			fmt.Sprintf("%d/%d healthy", group.HealthyPaths, group.Paths),
			strconv.Itoa(group.Peers),
		)
	}
	_ = table.Flush()
}

func printPaths(w io.Writer, paths []api.Path, wide bool, now time.Time) {
	if len(paths) == 0 {
		_, _ = fmt.Fprintln(w, "No paths found.")
		return
	}
	table := newTable(w)
	header := []string{"ID", "GROUP", "SERVER", "TRANSPORT", "VIA", "INTERFACE", "STATUS", "IN USE", "LAST ACK", "RTT"}
	if wide {
		header = append(header, "PRIORITY", "MISSES")
	}
	row(table, header...)
	for _, path := range paths {
		lastACK := "never"
		if !path.LastACK.IsZero() {
			lastACK = humanDuration(now.Sub(path.LastACK))
		}
		cells := []string{
			strconv.Itoa(path.ID),
			strconv.Itoa(int(path.ListenPort)),
			fmt.Sprintf("%s:%d", path.Server, path.Port),
			path.Transport,
			orDash(path.ReturnIP),
			orDash(path.Interface),
			healthText(path.Healthy),
			yesNo(path.InUse),
			lastACK,
			formatRTT(path.RTTSeconds),
		}
		if wide {
			cells = append(cells, strconv.Itoa(int(path.Priority)), strconv.Itoa(path.Misses))
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

func printClients(w io.Writer, clients []api.RegisteredClient, wide bool) {
	if len(clients) == 0 {
		_, _ = fmt.Fprintln(w, "No clients found.")
		return
	}
	table := newTable(w)
	header := []string{"CLIENT", "NONCE", "PATHS", "PEERS", "RETURN IP", "LEASE"}
	if wide {
		header = append(header, "LISTEN PORT", "PATH LIST")
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
		if wide {
			list := make([]string, 0, len(client.Paths))
			for _, path := range client.Paths {
				list = append(list, fmt.Sprintf("%d:%s:%s", path.ID, path.Transport, path.Local))
			}
			cells = append(cells, strconv.Itoa(int(client.ListenPort)), orDash(strings.Join(list, ",")))
		}
		row(table, cells...)
	}
	_ = table.Flush()
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
