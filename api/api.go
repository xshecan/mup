// Package api defines the control API that the mup daemon serves on a Unix
// socket and that mupctl uses. The API is JSON over HTTP/1.1.
package api

import "time"

const (
	DefaultClientSocket = "/run/mup/client.sock"
	DefaultServerSocket = "/run/mup/server.sock"

	RoleClient = "client"
	RoleServer = "server"
)

// Status is the overview of a daemon. Exactly one of Client and Server is set.
type Status struct {
	Role      string        `json:"role"`
	StartedAt time.Time     `json:"started_at"`
	Client    *ClientStatus `json:"client,omitempty"`
	Server    *ServerStatus `json:"server,omitempty"`
	Drops     []Drop        `json:"drops"`
}

type ClientStatus struct {
	AdvertisedIP      string  `json:"advertised_ip"`
	Generation        uint32  `json:"generation"`
	Groups            []Group `json:"groups"`
	Paths             []Path  `json:"paths"`
	Peers             uint64  `json:"peers"`
	TokensFree        uint64  `json:"tokens_free"`
	TokensQuarantined uint64  `json:"tokens_quarantined"`
}

// Group is the set of servers for the peers of one listen port.
type Group struct {
	ListenPort   uint16 `json:"listen_port"`
	Mode         string `json:"mode"`
	Paths        int    `json:"paths"`
	HealthyPaths int    `json:"healthy_paths"`
	Peers        int    `json:"peers"`
}

type ServerStatus struct {
	Port             uint16 `json:"port"`
	Target           string `json:"target"`
	Clients          uint64 `json:"clients"`
	Paths            uint64 `json:"paths"`
	Peers            uint64 `json:"peers"`
	PortsFree        uint64 `json:"ports_free"`
	PortsQuarantined uint64 `json:"ports_quarantined"`
	Duplicates       uint64 `json:"duplicates"`
}

// Path is one client path. ListenPort names its group. InUse reports whether
// the mode of the group sends traffic on the path.
type Path struct {
	ID         int       `json:"id"`
	ListenPort uint16    `json:"listen_port"`
	Server     string    `json:"server"`
	Port       uint16    `json:"port"`
	Transport  string    `json:"transport"`
	ReturnIP   string    `json:"return_ip,omitempty"`
	Interface  string    `json:"interface,omitempty"`
	Priority   uint8     `json:"priority"`
	Healthy    bool      `json:"healthy"`
	InUse      bool      `json:"in_use"`
	Misses     int       `json:"misses"`
	LastACK    time.Time `json:"last_ack,omitzero"`
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

// RegisteredClient is one client registration on a server.
type RegisteredClient struct {
	AdvertisedIP string           `json:"advertised_ip"`
	Nonce        string           `json:"nonce"`
	ReturnIP     string           `json:"return_ip,omitempty"`
	ListenPort   uint16           `json:"listen_port"`
	LeaseSeconds float64          `json:"lease_seconds"`
	Paths        []RegisteredPath `json:"paths"`
	Peers        int              `json:"peers"`
}

type RegisteredPath struct {
	ID           uint16  `json:"id"`
	Source       string  `json:"source"`
	Local        string  `json:"local"`
	Transport    string  `json:"transport"`
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
}

// ModeRequest changes the mode of a group. ListenPort names the group. A client
// with one group accepts zero.
type ModeRequest struct {
	Mode       string `json:"mode"`
	ListenPort uint16 `json:"listen_port,omitempty"`
}

type Error struct {
	Error string `json:"error"`
}
