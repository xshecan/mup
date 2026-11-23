package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
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
	ModeFailover Mode = iota
	ModeBalancer
	ModeRepeater
)

func (m Mode) String() string {
	switch m {
	case ModeFailover:
		return "failover"
	case ModeBalancer:
		return "balancer"
	case ModeRepeater:
		return "repeater"
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

// Balance is how a return pool spreads the egress replies of a route.
type Balance uint8

const (
	// BalancePerPeer sends all replies of one peer through one reflector.
	BalancePerPeer Balance = iota
	// BalancePerPacket sends each reply through the next reflector in turn.
	BalancePerPacket
)

func (b Balance) String() string {
	switch b {
	case BalancePerPeer:
		return "per-peer"
	case BalancePerPacket:
		return "per-packet"
	default:
		return fmt.Sprintf("balance(%d)", uint8(b))
	}
}

// ParseBalance parses a balance mode name.
func ParseBalance(raw string) (Balance, error) {
	switch raw {
	case "per-peer":
		return BalancePerPeer, nil
	case "per-packet":
		return BalancePerPacket, nil
	default:
		return 0, fmt.Errorf("invalid balance %q: use per-peer or per-packet", raw)
	}
}

// App is the configuration of one daemon. Exactly one of Client, Server, and
// Bridge is set.
type App struct {
	Client *Client `yaml:"client"`
	Server *Server `yaml:"server"`
	Bridge *Bridge `yaml:"bridge"`
}

// Validate applies the rules that are common to the flags and the
// configuration file.
func (a App) Validate() error {
	roles := 0
	for _, set := range []bool{a.Client != nil, a.Server != nil, a.Bridge != nil} {
		if set {
			roles++
		}
	}
	if roles != 1 {
		return errors.New("the configuration must have exactly one of client, server, and bridge")
	}
	switch {
	case a.Client != nil:
		return a.Client.Validate()
	case a.Server != nil:
		return a.Server.Validate()
	default:
		return a.Bridge.Validate()
	}
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
//
// Paths and Mode are the ingress paths and the ingress mode. A group without egress
// paths sends each reply back on the path of the latest ingress packet. A
// group with egress paths lets the server pick the egress path of each reply with
// EgressMode, so the two directions use separate paths.
type Group struct {
	ListenPort  uint16
	Mode        Mode
	Paths       []Path
	EgressMode  Mode
	EgressPaths []Path
}

// Direction is the ingress or the egress block of a group in the
// configuration file. Bridges are paths through a MUP bridge. They come after
// the routes, so a route gets a lower path ID than a bridge.
type Direction struct {
	Mode    Mode   `yaml:"mode"`
	Paths   []Path `yaml:"routes"`
	Bridges []Path `yaml:"bridges"`
}

// all returns the routes and then the bridges of the direction, with the
// bridges marked.
func (d Direction) all() []Path {
	paths := slices.Clone(d.Paths)
	for _, bridge := range d.Bridges {
		bridge.Bridge = true
		paths = append(paths, bridge)
	}
	return paths
}

// Split reports whether the group has its own egress paths.
func (g Group) Split() bool {
	return len(g.EgressPaths) > 0
}

// UnmarshalYAML reads a group in one of two forms: "mode" and "routes" for
// paths that carry both directions, or "ingress" and "egress" blocks for
// separate ingress paths and egress paths.
func (g *Group) UnmarshalYAML(unmarshal func(any) error) error {
	var raw struct {
		ListenPort uint16     `yaml:"port"`
		Mode       *Mode      `yaml:"mode"`
		Paths      []Path     `yaml:"routes"`
		Ingress    *Direction `yaml:"ingress"`
		Egress     *Direction `yaml:"egress"`
	}
	if err := unmarshal(&raw); err != nil {
		return err
	}
	*g = Group{ListenPort: raw.ListenPort, Paths: raw.Paths}
	if raw.Mode != nil {
		g.Mode = *raw.Mode
	}
	if raw.Ingress == nil && raw.Egress == nil {
		return nil
	}
	if raw.Mode != nil || len(raw.Paths) > 0 {
		return fmt.Errorf("server %d: use mode and routes, or ingress and egress, not both", raw.ListenPort)
	}
	if raw.Ingress == nil || raw.Egress == nil {
		return fmt.Errorf("server %d: ingress and egress go together", raw.ListenPort)
	}
	if len(raw.Egress.Paths)+len(raw.Egress.Bridges) == 0 {
		return fmt.Errorf("server %d: egress requires at least one route or bridge", raw.ListenPort)
	}
	g.Mode = raw.Ingress.Mode
	g.Paths = raw.Ingress.all()
	g.EgressMode = raw.Egress.Mode
	g.EgressPaths = raw.Egress.all()
	return nil
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
	type groupPath struct {
		path       Path
		listenPort uint16
	}
	var seen []groupPath
	var egresses []Path
	for _, group := range c.Groups {
		if err := group.validate(); err != nil {
			return err
		}
		if _, exists := listenPorts[group.ListenPort]; exists {
			return fmt.Errorf("duplicate server for listen port %d", group.ListenPort)
		}
		listenPorts[group.ListenPort] = struct{}{}
		for _, path := range group.Paths {
			for _, earlier := range seen {
				if earlier.path.SameRoute(path) {
					return fmt.Errorf("client routes %s and %s share a server port", earlier.path, path)
				}
				if earlier.listenPort != group.ListenPort && earlier.path.SharesServerPort(path) {
					return fmt.Errorf("%s and %s are in the servers of listen ports %d and %d, but an address and port can serve one listen port", earlier.path, path, earlier.listenPort, group.ListenPort)
				}
			}
			seen = append(seen, groupPath{path: path, listenPort: group.ListenPort})
		}
		for _, egress := range group.EgressPaths {
			for _, earlier := range egresses {
				if earlier.SameEgressPath(egress) {
					return fmt.Errorf("client has the egress route %s twice", egress)
				}
			}
			egresses = append(egresses, egress)
		}
	}
	if len(seen) > MaxPaths {
		return fmt.Errorf("client accepts at most %d paths in all groups", MaxPaths)
	}
	if len(egresses) > MaxPaths {
		return fmt.Errorf("client accepts at most %d egress routes in all groups", MaxPaths)
	}
	return nil
}

func (g Group) validate() error {
	if g.ListenPort == 0 {
		return errors.New("server listen port must be between 1 and 65535")
	}
	if g.Mode > ModeRepeater {
		return fmt.Errorf("server %d: invalid mode %d", g.ListenPort, uint8(g.Mode))
	}
	if len(g.Paths) == 0 {
		return fmt.Errorf("server %d: requires at least one route", g.ListenPort)
	}
	for index, path := range g.Paths {
		if err := path.validate(); err != nil {
			return fmt.Errorf("server %d: route %d: %w", g.ListenPort, index, err)
		}
		if path.Bridge && !g.Split() {
			return fmt.Errorf("server %d: route %d: a bridge needs a group with ingress and egress", g.ListenPort, index)
		}
		if path.Bridge && path.ReturnIP.IsValid() {
			return fmt.Errorf("server %d: ingress route %d: an ingress bridge has no via, because it passes the client packets on to the server", g.ListenPort, index)
		}
		if path.ProxyBridge.IsValid() {
			if path.Bridge {
				return fmt.Errorf("server %d: route %d: a route is a bridge or a bridge reflect, not both", g.ListenPort, index)
			}
			if !g.Split() {
				return fmt.Errorf("server %d: route %d: a bridge reflect needs a group with ingress and egress", g.ListenPort, index)
			}
			if !path.ReturnIP.IsValid() {
				return fmt.Errorf("server %d: route %d: a bridge reflect needs a via, because the bridge emits the reflected ingress", g.ListenPort, index)
			}
		}
	}
	if g.EgressMode > ModeRepeater {
		return fmt.Errorf("server %d: invalid egress mode %d", g.ListenPort, uint8(g.EgressMode))
	}
	for index, path := range g.EgressPaths {
		if err := path.ValidateEgress(); err != nil {
			return fmt.Errorf("server %d: egress route %d: %w", g.ListenPort, index, err)
		}
	}
	return nil
}

// Path is one route to a server. If ReturnIP is set, the server returns the
// replies of the path through it: a UDP reply has the return IP as its source,
// and an ICMP reply goes to the return IP as an Echo Request. If ReturnPrefix
// is nonzero, ReturnIP is a pool base and the server spreads the replies over
// the pool by Balance.
//
// If Bridge is set, Server is the address of a MUP bridge. An ingress bridge passes
// the packets of the path to its server. An egress bridge sends the replies that
// a server wraps for it, and the address of the path is the bridge address.
//
// If LastPort is nonzero, the path has the server ports from ServerPort to
// LastPort. It starts on ServerPort, and the client moves it to another port
// of the range when the server stops answering it.
type Path struct {
	Server       netip.Addr
	ServerPort   uint16
	LastPort     uint16
	Transport    protocol.TransportID
	Interface    string
	ReturnIP     netip.Addr
	ReturnPrefix uint8
	Balance      Balance
	Bridge       bool
	// ProxyBridge is set on an ingress reflect route that a bridge emits. The client
	// reflects the ingress to Server through the via, but it cannot send the
	// spoofed packet, so it wraps the packet for the bridge at ProxyBridge, and
	// the bridge emits the spoofed packet.
	ProxyBridge netip.Addr
}

// Kind names the path type for the status output: "bridge" or "route".
func (p Path) Kind() string {
	if p.Bridge {
		return "bridge"
	}
	return "route"
}

// IsPool reports whether the path returns through a pool of addresses.
func (p Path) IsPool() bool {
	return p.ReturnPrefix != 0
}

// IngressReflect reports whether the path reflects the ingress. An ingress route of a
// group with egress paths that has a return IP, and is not a bridge, reflects the
// ingress through the return IP or the pool. The split argument is true for a
// group with egress paths.
func (p Path) IngressReflect(split bool) bool {
	return split && !p.Bridge && p.ReturnIP.IsValid()
}

// BridgeReflect reports whether an ingress reflect route emits through a bridge,
// because the client cannot send the spoofed packet itself.
func (p Path) BridgeReflect() bool {
	return p.ProxyBridge.IsValid()
}

// HasPortRange reports whether the path has more than one server port.
func (p Path) HasPortRange() bool {
	return p.LastPort > p.ServerPort
}

// Ports returns the server ports of the path.
func (p Path) Ports() PortRange {
	if p.HasPortRange() {
		return PortRange{First: p.ServerPort, Last: p.LastPort}
	}
	return SinglePort(p.ServerPort)
}

// AtPort returns the path on one server port of its range.
func (p Path) AtPort(port uint16) Path {
	p.ServerPort = port
	p.LastPort = 0
	return p
}

// SameRoute reports whether two paths go to the same server with the same
// transport and interface, on server port ranges that share a port. Two such
// paths can register as one path on the server.
func (p Path) SameRoute(other Path) bool {
	return p.Server == other.Server && p.Transport == other.Transport &&
		p.Interface == other.Interface && p.SharesServerPort(other)
}

// SharesServerPort reports whether two paths go to the same server on server
// port ranges that share a port.
func (p Path) SharesServerPort(other Path) bool {
	ports, otherPorts := p.Ports(), other.Ports()
	return p.Server == other.Server &&
		ports.First <= otherPorts.Last && otherPorts.First <= ports.Last
}

// String formats the path as SERVER[%IFACE]:PORT[-LAST]/TRANSPORT
// [via RETURN_IP], the form that ParsePath accepts.
func (p Path) String() string {
	host := p.Server.String()
	if p.Interface != "" {
		host += "%" + p.Interface
	}
	text := fmt.Sprintf("%s:%s/%s", host, p.Ports(), p.Transport)
	if p.IsPool() {
		text += fmt.Sprintf(" via %s/%d %s", p.ReturnIP, p.ReturnPrefix, p.Balance)
	} else if p.ReturnIP.IsValid() {
		text += " via " + p.ReturnIP.String()
	}
	if p.ProxyBridge.IsValid() {
		text += " bridge " + p.ProxyBridge.String()
	}
	return text
}

// Endpoint returns the address and the first server port of the path.
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

// ValidateEgress applies the rules of an egress path. The server sends the replies
// from the address and port of the path, so the path has no interface and one
// port.
func (p Path) ValidateEgress() error {
	if err := p.validate(); err != nil {
		return err
	}
	if p.Interface != "" {
		return errors.New("an egress route has no interface, because the server picks the interface")
	}
	if p.HasPortRange() {
		return errors.New("an egress route has one server port")
	}
	if p.ProxyBridge.IsValid() {
		return errors.New("an egress route has no bridge reflect, because the server sends the replies")
	}
	return nil
}

// SameEgressPath reports whether two egress paths send from the same server
// address, port, and transport. The client cannot tell their replies apart.
func (p Path) SameEgressPath(other Path) bool {
	return p.Server == other.Server && p.ServerPort == other.ServerPort && p.Transport == other.Transport
}

func (p Path) validate() error {
	if !isNonzeroIPv4(p.Server) {
		return errors.New("server path address must be a nonzero IPv4")
	}
	if p.ServerPort == 0 {
		return errors.New("server path port must be nonzero")
	}
	if p.LastPort != 0 && p.LastPort <= p.ServerPort {
		return errors.New("the last server port of a path must be above the first")
	}
	if p.Transport > protocol.TransportICMP {
		return fmt.Errorf("invalid transport %d", uint8(p.Transport))
	}
	if p.ReturnIP.IsValid() && !isNonzeroIPv4(p.ReturnIP) {
		return errors.New("return IP must be a nonzero IPv4 address")
	}
	if p.IsPool() {
		if p.ReturnPrefix < 1 || p.ReturnPrefix > 31 {
			return errors.New("return pool prefix must be between 1 and 31")
		}
		prefix := netip.PrefixFrom(p.ReturnIP, int(p.ReturnPrefix))
		if prefix.Masked().Addr() != p.ReturnIP {
			return errors.New("return pool base must be the network address of the prefix")
		}
	}
	if p.Balance != BalancePerPeer && !p.IsPool() {
		return errors.New("per-peer and per-packet apply only to a return pool")
	}
	return nil
}

type Server struct {
	Port          PortRange      `yaml:"port"`
	Target        netip.AddrPort `yaml:"target"`
	ControlSocket string         `yaml:"control_socket"`
	// TargetIngress delivers each ingress packet into the ingress hook of
	// the interface that holds the target address, from the advertised IP
	// of the client. A program on that hook, for example the TC fast path of
	// a WireGuard router, then sees the packet as a packet from the client.
	// The target must be an address of this host on an Ethernet interface.
	TargetIngress bool `yaml:"target_ingress"`
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
	if s.TargetIngress {
		if s.Target.Addr().IsLoopback() {
			return errors.New("server target_ingress needs a target on an Ethernet interface, not on loopback")
		}
		if s.Port.Contains(s.Target.Port()) {
			return errors.New("server target_ingress needs a target port outside the server ports")
		}
	}
	return nil
}

// MaxBridgeAllow limits the extra sender ranges of a bridge. It mirrors the
// size of the bridge_allow map, which also holds the server address.
const MaxBridgeAllow = 63

// Bridge is the configuration of a MUP bridge. The bridge passes the packets
// of the clients on its ports to Server, and it sends the replies that
// Server wraps for it. It takes wrapped replies only from Server and from
// the Allow ranges, for example the NAT address of a server.
type Bridge struct {
	Server        netip.Addr     `yaml:"server"`
	Port          PortRange      `yaml:"port"`
	Allow         []netip.Prefix `yaml:"allow"`
	ControlSocket string         `yaml:"control_socket"`
}

// UnmarshalYAML keeps the default socket when the file does not set one. An
// empty value in the file turns the socket off.
func (b *Bridge) UnmarshalYAML(unmarshal func(any) error) error {
	type bridge Bridge
	b.ControlSocket = api.DefaultBridgeSocket
	return unmarshal((*bridge)(b))
}

func (b Bridge) Validate() error {
	if !isNonzeroIPv4(b.Server) {
		return errors.New("bridge server must be a nonzero IPv4 address")
	}
	if b.Port.First == 0 || b.Port.Last < b.Port.First {
		return errors.New("bridge port must be PORT or FIRST-LAST between 1 and 65535")
	}
	if len(b.Allow) > MaxBridgeAllow {
		return fmt.Errorf("bridge accepts at most %d allow ranges", MaxBridgeAllow)
	}
	for _, prefix := range b.Allow {
		if !prefix.IsValid() || !prefix.Addr().Is4() {
			return fmt.Errorf("bridge allow range %s must be an IPv4 CIDR", prefix)
		}
		if prefix.Bits() == 0 {
			return errors.New("a bridge allow range of 0.0.0.0/0 lets any host use the bridge")
		}
	}
	return nil
}

// ParsePath parses SERVER[%IFACE]:PORT/udp or SERVER[%IFACE]:PORT/icmp, where
// PORT can be a range FIRST-LAST. It accepts an optional "via RETURN_IP", or
// "via POOL_CIDR" with an optional "per-peer" or "per-packet" after the pool.
func ParsePath(raw string) (Path, error) {
	fields := strings.Fields(raw)
	var returnIP netip.Addr
	var returnPrefix uint8
	var proxyBridge netip.Addr
	balance := BalancePerPeer
	usage := errors.New("path must use IPv4:PORT/udp or /icmp, with an optional via RETURN_IP, or via POOL_CIDR with an optional per-peer or per-packet")
	// A trailing "bridge BRIDGE" names a bridge that emits the reflected ingress.
	if n := len(fields); n >= 2 && fields[n-2] == "bridge" {
		address, err := netip.ParseAddr(fields[n-1])
		if err != nil || !isNonzeroIPv4(address) {
			return Path{}, errors.New("bridge address must be a nonzero IPv4 address")
		}
		proxyBridge = address
		fields = fields[:n-2]
	}
	switch {
	case len(fields) == 1:
	case (len(fields) == 3 || len(fields) == 4) && fields[1] == "via":
		target := fields[2]
		if strings.Contains(target, "/") {
			prefix, err := netip.ParsePrefix(target)
			if err != nil || !isNonzeroIPv4(prefix.Addr()) {
				return Path{}, errors.New("return pool must be a nonzero IPv4 CIDR")
			}
			if prefix.Bits() < 1 || prefix.Bits() > 31 {
				return Path{}, errors.New("return pool prefix must be between 1 and 31")
			}
			returnIP = prefix.Masked().Addr()
			returnPrefix = uint8(prefix.Bits())
		} else {
			address, err := netip.ParseAddr(target)
			if err != nil || !isNonzeroIPv4(address) {
				return Path{}, errors.New("return IP must be a nonzero IPv4 address")
			}
			returnIP = address
		}
		if len(fields) == 4 {
			if returnPrefix == 0 {
				return Path{}, errors.New("per-peer and per-packet apply only to a return pool")
			}
			parsed, err := ParseBalance(fields[3])
			if err != nil {
				return Path{}, err
			}
			balance = parsed
		}
	default:
		return Path{}, usage
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
	ports, err := ParsePortRange(portText)
	if err != nil {
		return Path{}, err
	}
	serverPort, transportID, err := transport.ParsePortSpec(strconv.Itoa(int(ports.First)) + "/" + transportName)
	if err != nil {
		return Path{}, err
	}
	var lastPort uint16
	if ports.Last > ports.First {
		lastPort = ports.Last
	}
	addressText, interfaceName, hasInterface := strings.Cut(host, "%")
	if hasInterface && (interfaceName == "" || strings.Contains(interfaceName, "%")) {
		return Path{}, errors.New("invalid interface suffix")
	}
	address, err := netip.ParseAddr(addressText)
	if err != nil {
		return Path{}, errors.New("server path address must be a nonzero IPv4")
	}
	path := Path{Server: address, ServerPort: serverPort, LastPort: lastPort, Transport: transportID, Interface: interfaceName, ReturnIP: returnIP, ReturnPrefix: returnPrefix, Balance: balance, ProxyBridge: proxyBridge}
	if err := path.validate(); err != nil {
		return Path{}, err
	}
	return path, nil
}

func ParseMode(raw string) (Mode, error) {
	switch raw {
	case "failover":
		return ModeFailover, nil
	case "balancer":
		return ModeBalancer, nil
	case "repeater":
		return ModeRepeater, nil
	default:
		return 0, fmt.Errorf("invalid mode %q: use failover, balancer, or repeater", raw)
	}
}

func isNonzeroIPv4(address netip.Addr) bool {
	return address.Is4() && !address.IsUnspecified()
}
