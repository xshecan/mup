// Package api defines the control API that the mup daemon serves on a Unix
// socket and that mupctl uses. The API is JSON over HTTP/1.1.
package api

import "time"

const (
	DefaultClientSocket = "/run/mup/client.sock"
	DefaultServerSocket = "/run/mup/server.sock"
	DefaultBridgeSocket = "/run/mup/bridge.sock"

	RoleClient = "client"
	RoleServer = "server"
	RoleBridge = "bridge"
)

// Status is the overview of a daemon. Exactly one of Client, Server, and
// Bridge is set.
type Status struct {
	Role      string        `json:"role"`
	StartedAt time.Time     `json:"started_at"`
	Client    *ClientStatus `json:"client,omitempty"`
	Server    *ServerStatus `json:"server,omitempty"`
	Bridge    *BridgeStatus `json:"bridge,omitempty"`
	Drops     []Drop        `json:"drops"`
}

// BridgeStatus describes a bridge. Entries holds every entry of the bridge.
// Server, Port, PortLast, and Allow repeat the first entry, so an older mupctl
// still shows a bridge. The counters count the packets and bytes that it sent.
type BridgeStatus struct {
	Server         string              `json:"server"`
	Port           uint16              `json:"port"`
	PortLast       uint16              `json:"port_last,omitempty"`
	Allow          []string            `json:"allow,omitempty"`
	Entries        []BridgeEntryStatus `json:"entries,omitempty"`
	Addresses      []string            `json:"addresses"`
	IngressPackets uint64              `json:"ingress_packets"`
	IngressBytes   uint64              `json:"ingress_bytes"`
	EgressPackets  uint64              `json:"egress_packets"`
	EgressBytes    uint64              `json:"egress_bytes"`
}

// BridgeEntryStatus describes one entry of a bridge. It takes the ports from
// Port to PortLast, sends the ingress to Server, and takes wrapped replies
// from Server and the Allow ranges.
type BridgeEntryStatus struct {
	Server   string   `json:"server"`
	Port     uint16   `json:"port"`
	PortLast uint16   `json:"port_last,omitempty"`
	Allow    []string `json:"allow,omitempty"`
}

type ClientStatus struct {
	AdvertisedIP      string  `json:"advertised_ip"`
	Generation        uint32  `json:"generation"`
	Groups            []Group `json:"groups"`
	Paths             []Path  `json:"paths"`
	Peers             uint64  `json:"peers"`
	TokensFree        uint64  `json:"tokens_free"`
	TokensQuarantined uint64  `json:"tokens_quarantined"`
	// TokensQuota is the number of peer tokens. A daemon before v0.3.4 does
	// not send it.
	TokensQuota uint64 `json:"tokens_quota,omitempty"`
}

// Group is the set of servers for the peers of one listen port. A group with
// separate egress paths also has EgressMode and its egress path counts.
type Group struct {
	ListenPort         uint16 `json:"listen_port"`
	Mode               string `json:"mode"`
	Paths              int    `json:"paths"`
	HealthyPaths       int    `json:"healthy_paths"`
	Peers              int    `json:"peers"`
	EgressMode         string `json:"egress_mode,omitempty"`
	EgressPaths        int    `json:"egress_paths,omitempty"`
	HealthyEgressPaths int    `json:"healthy_egress_paths,omitempty"`
}

// ServerStatus describes a server. It accepts the ports from Port to
// PortLast.
type ServerStatus struct {
	Port             uint16 `json:"port"`
	PortLast         uint16 `json:"port_last,omitempty"`
	Target           string `json:"target"`
	TargetIngress    bool   `json:"target_ingress,omitempty"`
	Clients          uint64 `json:"clients"`
	Paths            uint64 `json:"paths"`
	Peers            uint64 `json:"peers"`
	PortsFree        uint64 `json:"ports_free"`
	PortsQuarantined uint64 `json:"ports_quarantined"`
	Duplicates       uint64 `json:"duplicates"`
}

// Path is one client path. ListenPort names its group. InUse reports whether
// the mode of the group sends traffic on the path. Direction is "ingress" for an ingress
// path and "egress" for an egress path of a group with separate egress paths, and
// empty for a path that carries both directions. An egress path is healthy while
// its probes arrive, and LastProbe is the time of the latest one. A path with
// Bridge goes through a MUP bridge, and Server is the bridge address. An egress
// bridge path with BridgeVia has its via on the leg from the server to the
// bridge, and the bridge sends from its own address. Without BridgeVia, the
// bridge sends the replies from the via.
type Path struct {
	ID         int    `json:"id"`
	Direction  string `json:"direction,omitempty"`
	Bridge     bool   `json:"bridge,omitempty"`
	BridgeVia  bool   `json:"bridge_via,omitempty"`
	ListenPort uint16 `json:"listen_port"`
	Server     string `json:"server"`
	Port       uint16 `json:"port"`
	// FirstPort and LastPort are the server port range of a path that can
	// move between server ports. Port is the server port that it uses now.
	FirstPort  uint16    `json:"first_port,omitempty"`
	LastPort   uint16    `json:"last_port,omitempty"`
	Transport  string    `json:"transport"`
	ReturnIP   string    `json:"return_ip,omitempty"`
	Interface  string    `json:"interface,omitempty"`
	Priority   uint8     `json:"priority"`
	Healthy    bool      `json:"healthy"`
	Reason     string    `json:"reason,omitempty"`
	InUse      bool      `json:"in_use"`
	Misses     int       `json:"misses"`
	LastACK    time.Time `json:"last_ack,omitzero"`
	LastProbe  time.Time `json:"last_probe,omitzero"`
	RTTSeconds float64   `json:"rtt_seconds,omitzero"`
}

// Peer is one WireGuard peer of a client.
type Peer struct {
	Token       uint32  `json:"token"`
	Address     string  `json:"address"`
	Local       string  `json:"local"`
	Interface   string  `json:"interface,omitempty"`
	IdleSeconds float64 `json:"idle_seconds"`
}

// Route is one peer of one client, as a server sees it.
type Route struct {
	Client      string  `json:"client"`
	Nonce       string  `json:"nonce"`
	Token       uint32  `json:"token"`
	TargetPort  uint16  `json:"target_port"`
	Transport   string  `json:"transport"`
	PathID      uint16  `json:"path_id"`
	Source      string  `json:"source"`
	Local       string  `json:"local"`
	ReturnIP    string  `json:"return_ip,omitempty"`
	Interface   string  `json:"interface,omitempty"`
	IdleSeconds float64 `json:"idle_seconds"`
}

// PeerList holds the peers of a client or the routes of a server.
type PeerList struct {
	Peers  []Peer  `json:"peers,omitempty"`
	Routes []Route `json:"routes,omitempty"`
}

// ReflectorList is the reflector pool health of a server.
type ReflectorList struct {
	Reflectors []Reflector `json:"reflectors"`
}

// Reflector is one address of a return pool, with its health.
type Reflector struct {
	Pool      string `json:"pool"`
	Address   string `json:"address"`
	Transport string `json:"transport"`
	Healthy   bool   `json:"healthy"`
}

// RegisteredClient is one client registration on a server.
type RegisteredClient struct {
	AdvertisedIP string `json:"advertised_ip"`
	Nonce        string `json:"nonce"`
	// ReturnIP and ListenPort are the values of the latest REGISTER frame. A
	// client with more than one group has the listen port of each path in Paths.
	ReturnIP     string           `json:"return_ip,omitempty"`
	ListenPort   uint16           `json:"listen_port"`
	LeaseSeconds float64          `json:"lease_seconds"`
	Paths        []RegisteredPath `json:"paths"`
	Peers        int              `json:"peers"`
	// Egress is the egress group with the lowest listen port of a client with
	// separate egress paths. Old readers use it. Egresses holds every egress
	// group of the client, sorted by listen port.
	Egress   *EgressGroup  `json:"egress,omitempty"`
	Egresses []EgressGroup `json:"egresses,omitempty"`
}

// EgressGroup is the egress mode and the egress paths of one group of a client
// (one listen port), as a server sees them.
type EgressGroup struct {
	ListenPort uint16       `json:"listen_port,omitempty"`
	Mode       string       `json:"mode"`
	Paths      []EgressPath `json:"paths"`
}

// EgressPath is one egress path of a client on a server. Members counts the
// reflectors that the path can use, and HealthyMembers the ones whose probes
// reach the client. A bridge path with BridgeVia sends its replies to the
// bridge from the via, and a bridge path without it lets the bridge send them
// from the via.
type EgressPath struct {
	ID             uint16  `json:"id"`
	Bridge         bool    `json:"bridge,omitempty"`
	BridgeVia      bool    `json:"bridge_via,omitempty"`
	Server         string  `json:"server"`
	Port           uint16  `json:"port"`
	Transport      string  `json:"transport"`
	ReturnIP       string  `json:"return_ip,omitempty"`
	Healthy        bool    `json:"healthy"`
	Members        int     `json:"members"`
	HealthyMembers int     `json:"healthy_members"`
	LeaseSeconds   float64 `json:"lease_seconds"`
}

type RegisteredPath struct {
	ID           uint16  `json:"id"`
	ListenPort   uint16  `json:"listen_port,omitempty"`
	Source       string  `json:"source"`
	Local        string  `json:"local"`
	Transport    string  `json:"transport"`
	ReturnIP     string  `json:"return_ip,omitempty"`
	LeaseSeconds float64 `json:"lease_seconds"`
}

type Drop struct {
	Reason uint32 `json:"reason"`
	Name   string `json:"name"`
	Count  uint64 `json:"count"`
}

// AddPathRequest adds a client path. Path uses the form of the mup client
// -u flag: SERVER[%IFACE]:PORT/udp or /icmp. ListenPort names the group. A
// client with one group accepts zero.
type AddPathRequest struct {
	Path       string `json:"path"`
	ListenPort uint16 `json:"listen_port,omitempty"`
	// Egress adds an egress path to a group with separate egress paths.
	Egress bool `json:"egress,omitempty"`
	// Bridge adds a path through a MUP bridge. Path then names the bridge.
	Bridge bool `json:"bridge,omitempty"`
}

// ModeRequest changes the mode of a group. ListenPort names the group. A client
// with one group accepts zero.
type ModeRequest struct {
	Mode       string `json:"mode"`
	ListenPort uint16 `json:"listen_port,omitempty"`
	// Egress changes the egress mode of a group with separate egress paths.
	Egress bool `json:"egress,omitempty"`
}

type Error struct {
	Error string `json:"error"`
}
