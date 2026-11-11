package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/xshecan/mup/api"
	"github.com/xshecan/mup/protocol"
	"github.com/xshecan/mup/transport"
)

const MaxPaths = 8

// MaxServerPorts limits a server port range, because the server opens one UDP
// socket for each port.
const MaxServerPorts = 4096

// PortRange is a range of server ports from First to Last. A single port has
// First equal to Last.
type PortRange struct {
	First uint16
	Last  uint16
}

// SinglePort returns the range of one port.
func SinglePort(port uint16) PortRange {
	return PortRange{First: port, Last: port}
}

// ParsePortRange parses PORT or FIRST-LAST.
func ParsePortRange(raw string) (PortRange, error) {
	firstText, lastText, isRange := strings.Cut(strings.TrimSpace(raw), "-")
	first, err := strconv.ParseUint(firstText, 10, 16)
	if err != nil || first == 0 {
		return PortRange{}, fmt.Errorf("invalid server port %q", raw)
	}
	last := first
	if isRange {
		last, err = strconv.ParseUint(lastText, 10, 16)
		if err != nil || last < first {
			return PortRange{}, fmt.Errorf("invalid server port range %q", raw)
		}
	}
	return PortRange{First: uint16(first), Last: uint16(last)}, nil
}

// String formats the range as PORT or FIRST-LAST.
func (r PortRange) String() string {
	if r.First == r.Last {
		return strconv.Itoa(int(r.First))
	}
	return fmt.Sprintf("%d-%d", r.First, r.Last)
}

// Contains reports whether port is in the range.
func (r PortRange) Contains(port uint16) bool {
	return port >= r.First && port <= r.Last
}

// Len returns the number of ports in the range.
func (r PortRange) Len() int {
	if r.Last < r.First {
		return 0
	}
	return int(r.Last) - int(r.First) + 1
}

// UnmarshalText reads PORT or FIRST-LAST from a configuration file.
func (r *PortRange) UnmarshalText(text []byte) error {
	parsed, err := ParsePortRange(string(text))
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

// MarshalText writes the range in the form that ParsePortRange accepts.
func (r PortRange) MarshalText() ([]byte, error) {
	return []byte(r.String()), nil
}

type Mode uint8

const (
	ModeFallback Mode = iota
	ModeBalancer
	ModeBurst
)

func (m Mode) String() string {
	switch m {
	case ModeFallback:
		return "fallback"
	case ModeBalancer:
		return "balancer"
	case ModeBurst:
		return "burst"
	default:
		return fmt.Sprintf("mode(%d)", uint8(m))
	}
}

// UnmarshalText reads a mode name from a configuration file.
func (m *Mode) UnmarshalText(text []byte) error {
	mode, err := ParseMode(string(text))
	if err != nil {
		return err
	}
	*m = mode
	return nil
}

// App is the configuration of one daemon. Exactly one of Client and Server is
// set.
type App struct {
	Client *Client `yaml:"client"`
	Server *Server `yaml:"server"`
}

// Validate applies the rules that are common to the flags and the
// configuration file.
func (a App) Validate() error {
	if (a.Client == nil) == (a.Server == nil) {
		return errors.New("the configuration must have exactly one of client and server")
	}
	if a.Client != nil {
		return a.Client.Validate()
	}
	return a.Server.Validate()
}

type Client struct {
	AdvertisedIP  netip.Addr `yaml:"advertise"`
	ControlSocket string     `yaml:"control_socket"`
	Groups        []Group    `yaml:"servers"`
}

// Group is the set of servers for the peers of one listen port. All servers of
// a group forward to the same WireGuard target, because a WireGuard handshake
// fails against another identity. The configuration file calls a group a
// server and its paths routes.
type Group struct {
	ListenPort uint16 `yaml:"port"`
	Mode       Mode   `yaml:"mode"`
	Paths      []Path `yaml:"routes"`
}

// UnmarshalYAML keeps the default socket when the file does not set one. An
// empty value in the file turns the socket off.
func (c *Client) UnmarshalYAML(unmarshal func(any) error) error {
	type client Client
	c.ControlSocket = api.DefaultClientSocket
	return unmarshal((*client)(c))
}

func (c Client) Validate() error {
	if !isNonzeroIPv4(c.AdvertisedIP) {
		return errors.New("client advertised IP must be a nonzero IPv4 address")
	}
	if len(c.Groups) == 0 {
		return errors.New("client requires at least one server")
	}
	listenPorts := make(map[uint16]struct{}, len(c.Groups))
	owners := make(map[netip.AddrPort]uint16, MaxPaths)
	seen := make(map[Path]struct{}, MaxPaths)
	for _, group := range c.Groups {
		if err := group.validate(); err != nil {
			return err
		}
		if _, exists := listenPorts[group.ListenPort]; exists {
			return fmt.Errorf("duplicate server for listen port %d", group.ListenPort)
		}
		listenPorts[group.ListenPort] = struct{}{}
		for _, path := range group.Paths {
			if _, exists := seen[path.Route()]; exists {
				return fmt.Errorf("duplicate client route %s", path.Route())
			}
			seen[path.Route()] = struct{}{}
			owner, exists := owners[path.Endpoint()]
			if exists && owner != group.ListenPort {
				return fmt.Errorf("%s is in the servers of listen ports %d and %d, but an address and port can serve one listen port", path.Endpoint(), owner, group.ListenPort)
			}
			owners[path.Endpoint()] = group.ListenPort
		}
	}
	if len(seen) > MaxPaths {
		return fmt.Errorf("client accepts at most %d paths in all groups", MaxPaths)
	}
	return nil
}

func (g Group) validate() error {
	if g.ListenPort == 0 {
		return errors.New("server listen port must be between 1 and 65535")
	}
	if g.Mode > ModeBurst {
		return fmt.Errorf("server %d: invalid mode %d", g.ListenPort, uint8(g.Mode))
	}
	if len(g.Paths) == 0 {
		return fmt.Errorf("server %d: requires at least one route", g.ListenPort)
	}
	for index, path := range g.Paths {
		if err := path.validate(); err != nil {
			return fmt.Errorf("server %d: route %d: %w", g.ListenPort, index, err)
		}
	}
	return nil
}

// Path is one route to a server. If ReturnIP is set, the server returns the
// replies of the path through it: a UDP reply has the return IP as its source,
// and an ICMP reply goes to the return IP as an Echo Request.
type Path struct {
	Server     netip.Addr
	ServerPort uint16
	Transport  protocol.TransportID
	Interface  string
	ReturnIP   netip.Addr
}

// String formats the path as SERVER[%IFACE]:PORT/TRANSPORT [via RETURN_IP],
// the form that ParsePath accepts.
func (p Path) String() string {
	host := p.Server.String()
	if p.Interface != "" {
		host += "%" + p.Interface
	}
	text := fmt.Sprintf("%s:%d/%s", host, p.ServerPort, p.Transport)
	if p.ReturnIP.IsValid() {
		text += " via " + p.ReturnIP.String()
	}
	return text
}

// Route returns the path without its return IP. Two paths with the same route
// are the same path.
func (p Path) Route() Path {
	p.ReturnIP = netip.Addr{}
	return p
}

// Endpoint returns the address and port of the server of the path.
func (p Path) Endpoint() netip.AddrPort {
	return netip.AddrPortFrom(p.Server, p.ServerPort)
}

// UnmarshalText reads a path from a configuration file, in the form that
// ParsePath accepts.
func (p *Path) UnmarshalText(text []byte) error {
	path, err := ParsePath(string(text))
	if err != nil {
		return fmt.Errorf("path %q: %w", text, err)
	}
	*p = path
	return nil
}

func (p Path) validate() error {
	if !isNonzeroIPv4(p.Server) {
		return errors.New("server path address must be a nonzero IPv4")
	}
	if p.ServerPort == 0 {
		return errors.New("server path port must be nonzero")
	}
	if p.Transport > protocol.TransportICMP {
		return fmt.Errorf("invalid transport %d", uint8(p.Transport))
	}
	if p.ReturnIP.IsValid() && !isNonzeroIPv4(p.ReturnIP) {
		return errors.New("return IP must be a nonzero IPv4 address")
	}
	return nil
}

type Server struct {
	Port          PortRange      `yaml:"port"`
	Target        netip.AddrPort `yaml:"target"`
	ControlSocket string         `yaml:"control_socket"`
}

// UnmarshalYAML keeps the default socket when the file does not set one. An
// empty value in the file turns the socket off.
func (s *Server) UnmarshalYAML(unmarshal func(any) error) error {
	type server Server
	s.ControlSocket = api.DefaultServerSocket
	return unmarshal((*server)(s))
}

func (s Server) Validate() error {
	if s.Port.First == 0 || s.Port.Last < s.Port.First {
		return errors.New("server port must be PORT or FIRST-LAST between 1 and 65535")
	}
	if s.Port.Len() > MaxServerPorts {
		return fmt.Errorf("server port range %s has more than %d ports", s.Port, MaxServerPorts)
	}
	if !isNonzeroIPv4(s.Target.Addr()) || s.Target.Port() == 0 {
		return errors.New("server target must be a nonzero IPv4:PORT")
	}
	return nil
}

// ParsePath parses SERVER[%IFACE]:PORT/udp or SERVER[%IFACE]:PORT/icmp, with
// an optional "via RETURN_IP" after it.
func ParsePath(raw string) (Path, error) {
	fields := strings.Fields(raw)
	var returnIP netip.Addr
	switch {
	case len(fields) == 1:
	case len(fields) == 3 && fields[1] == "via":
		address, err := netip.ParseAddr(fields[2])
		if err != nil || !isNonzeroIPv4(address) {
			return Path{}, errors.New("return IP must be a nonzero IPv4 address")
		}
		returnIP = address
	default:
		return Path{}, errors.New("path must use IPv4:PORT/udp or /icmp, with an optional via RETURN_IP")
	}
	raw = fields[0]
	slash := strings.LastIndexByte(raw, '/')
	if slash <= 0 || slash == len(raw)-1 {
		return Path{}, errors.New("path must use IPv4:PORT/udp or /icmp")
	}
	endpoint, transportName := raw[:slash], raw[slash+1:]
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return Path{}, fmt.Errorf("invalid server endpoint: %w", err)
	}
	serverPort, transportID, err := transport.ParsePortSpec(portText + "/" + transportName)
	if err != nil {
		return Path{}, err
	}
	addressText, interfaceName, hasInterface := strings.Cut(host, "%")
	if hasInterface && (interfaceName == "" || strings.Contains(interfaceName, "%")) {
		return Path{}, errors.New("invalid interface suffix")
	}
	address, err := netip.ParseAddr(addressText)
	if err != nil {
		return Path{}, errors.New("server path address must be a nonzero IPv4")
	}
	path := Path{Server: address, ServerPort: serverPort, Transport: transportID, Interface: interfaceName, ReturnIP: returnIP}
	if err := path.validate(); err != nil {
		return Path{}, err
	}
	return path, nil
}

func ParseMode(raw string) (Mode, error) {
	switch raw {
	case "fallback":
		return ModeFallback, nil
	case "balancer":
		return ModeBalancer, nil
	case "burst":
		return ModeBurst, nil
	default:
		return 0, fmt.Errorf("invalid mode %q: use fallback, balancer, or burst", raw)
	}
}

func isNonzeroIPv4(address netip.Addr) bool {
	return address.Is4() && !address.IsUnspecified()
}
