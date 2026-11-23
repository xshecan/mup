package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/xshecan/mup/api"
	"github.com/xshecan/mup/app"
	"github.com/xshecan/mup/config"
)

const usage = `usage:
  mup --config FILE
  mup server -p PORT[-LAST] -r TARGET_IP:PORT [--target-ingress] [--control-socket PATH]
  mup client -p LISTEN_PORT -u "SERVER_IP[%IFACE]:PORT[-LAST]/udp|icmp [via RETURN_IP]" [-u ...] -s CLIENT_IP
             [-r RETURN_IP] [--mode fallback|balancer|burst] [--control-socket PATH]
  mup client -p LISTEN_PORT --ingress "SERVER_IP[%IFACE]:PORT[-LAST]/udp|icmp" [--ingress ...]
             --egress "SERVER_IP:PORT/udp|icmp [via RETURN_IP]" [--egress ...] -s CLIENT_IP
             [--ingress-bridge "BRIDGE_IP[%IFACE]:PORT[-LAST]/udp|icmp"] [--ingress-bridge ...]
             [--egress-bridge "BRIDGE_IP:PORT/udp|icmp [via RETURN_IP]"] [--egress-bridge ...]
             [--ingress-mode MODE] [--egress-mode MODE] [--control-socket PATH]
  mup bridge -s SERVER_IP -p PORT[-LAST] [-a CIDR] [-a ...] [--control-socket PATH]
`

type applicationRunner func(context.Context, config.App) error

// fileError is a failure of the configuration file. The usage text does not
// help with it.
type fileError struct{ error }

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(value string) error {
	if value == "" {
		return errors.New("value cannot be empty")
	}
	*s = append(*s, value)
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stderr, runApplication))
}

func run(ctx context.Context, args []string, stderr io.Writer, runner applicationRunner) int {
	appConfig, err := parseArgs(args)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mup: %v\n", err)
		var file fileError
		if !errors.As(err, &file) {
			_, _ = fmt.Fprint(stderr, usage)
		}
		return 2
	}
	if err = runner(ctx, appConfig); err != nil {
		if errors.Is(err, context.Canceled) {
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "mup: %v\n", err)
		return 1
	}
	return 0
}

func runApplication(ctx context.Context, appConfig config.App) error {
	return app.Run(ctx, appConfig)
}

func parseArgs(args []string) (config.App, error) {
	if len(args) == 0 {
		return config.App{}, errors.New("expected client, server, or bridge subcommand")
	}
	switch args[0] {
	case "client":
		client, err := parseClientArgs(args[1:])
		if err != nil {
			return config.App{}, err
		}
		return config.App{Client: client}, nil
	case "server":
		server, err := parseServerArgs(args[1:])
		if err != nil {
			return config.App{}, err
		}
		return config.App{Server: server}, nil
	case "bridge":
		bridge, err := parseBridgeArgs(args[1:])
		if err != nil {
			return config.App{}, err
		}
		return config.App{Bridge: bridge}, nil
	default:
		if strings.HasPrefix(args[0], "-") {
			return parseFileArgs(args)
		}
		return config.App{}, fmt.Errorf("unknown subcommand %q: expected client, server, or bridge", args[0])
	}
}

// parseFileArgs loads the configuration file. The file selects the role.
func parseFileArgs(args []string) (config.App, error) {
	fs := flag.NewFlagSet("mup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var path string
	fs.StringVar(&path, "config", "", "YAML configuration file")
	fs.StringVar(&path, "c", "", "YAML configuration file")
	if err := fs.Parse(args); err != nil {
		return config.App{}, err
	}
	if fs.NArg() != 0 {
		return config.App{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if path == "" {
		return config.App{}, errors.New("expected client, server, or bridge subcommand, or --config")
	}
	appConfig, err := config.Load(path)
	if err != nil {
		return config.App{}, fileError{err}
	}
	return appConfig, nil
}

func parseClientArgs(args []string) (*config.Client, error) {
	fs := flag.NewFlagSet("mup client", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var rawPaths, rawIngress, rawEgress, rawIngressBridges, rawEgressBridges stringList
	var port int
	var advertisedText, returnIPText, modeName, ingressModeName, egressModeName, controlSocket string
	fs.IntVar(&port, "p", 0, "local WireGuard UDP listen port")
	fs.Var(&rawPaths, "u", "server path as IPv4:PORT/udp or /icmp, where PORT can be a range FIRST-LAST")
	fs.Var(&rawIngress, "ingress", "ingress path as IPv4:PORT/udp or /icmp, for the ingress only")
	fs.Var(&rawEgress, "egress", "egress path as IPv4:PORT/udp or /icmp, for the egress only")
	fs.Var(&rawIngressBridges, "ingress-bridge", "ingress path through a MUP bridge, as BRIDGE_IP:PORT/udp or /icmp")
	fs.Var(&rawEgressBridges, "egress-bridge", "egress path through a MUP bridge, as BRIDGE_IP:PORT/udp or /icmp")
	fs.StringVar(&ingressModeName, "ingress-mode", "fallback", "ingress mode: fallback, balancer, or burst")
	fs.StringVar(&egressModeName, "egress-mode", "fallback", "egress mode: fallback, balancer, or burst")
	// The old flag names still work.
	fs.Var(&rawIngress, "up", "old name of --ingress")
	fs.Var(&rawEgress, "down", "old name of --egress")
	fs.Var(&rawIngressBridges, "up-bridge", "old name of --ingress-bridge")
	fs.Var(&rawEgressBridges, "down-bridge", "old name of --egress-bridge")
	fs.StringVar(&ingressModeName, "up-mode", "fallback", "old name of --ingress-mode")
	fs.StringVar(&egressModeName, "down-mode", "fallback", "old name of --egress-mode")
	fs.StringVar(&advertisedText, "s", "", "advertised client IPv4")
	fs.StringVar(&returnIPText, "r", "", "return IPv4 of each -u path without its own via")
	fs.StringVar(&modeName, "mode", "fallback", "fallback, balancer, or burst")
	fs.StringVar(&controlSocket, "control-socket", api.DefaultClientSocket, "Unix socket for mupctl, or empty to disable")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("unexpected client argument %q", fs.Arg(0))
	}
	listenPort, err := portFromFlag(port, "client -p")
	if err != nil {
		return nil, err
	}
	advertised, err := parseRequiredIPv4(advertisedText, "client -s")
	if err != nil {
		return nil, err
	}
	var returnIP netip.Addr
	if returnIPText != "" {
		returnIP, err = parseRequiredIPv4(returnIPText, "client -r")
		if err != nil {
			return nil, err
		}
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	split := splitArgs{ingress: rawIngress, egress: rawEgress, ingressBridges: rawIngressBridges, egressBridges: rawEgressBridges, ingressMode: ingressModeName, egressMode: egressModeName}
	if split.any() || set["ingress-mode"] || set["egress-mode"] || set["up-mode"] || set["down-mode"] {
		if len(rawPaths) > 0 || set["mode"] || set["r"] {
			return nil, errors.New("use -u, -r, and --mode, or --ingress, --egress, the bridges, --ingress-mode, and --egress-mode, not both")
		}
		return parseSplitClientArgs(listenPort, advertised, controlSocket, split)
	}
	mode, err := config.ParseMode(modeName)
	if err != nil {
		return nil, fmt.Errorf("--mode: %w", err)
	}
	paths := make([]config.Path, 0, len(rawPaths))
	for i, raw := range rawPaths {
		path, err := config.ParsePath(raw)
		if err != nil {
			return nil, fmt.Errorf("client -u[%d]: %w", i, err)
		}
		if !path.ReturnIP.IsValid() {
			path.ReturnIP = returnIP
		}
		paths = append(paths, path)
	}
	client := &config.Client{
		AdvertisedIP:  advertised,
		ControlSocket: controlSocket,
		Groups:        []config.Group{{ListenPort: listenPort, Mode: mode, Paths: paths}},
	}
	if err := client.Validate(); err != nil {
		return nil, err
	}
	return client, nil
}

// splitArgs holds the flags of a group with separate ingress paths and egress paths.
type splitArgs struct {
	ingress, egress, ingressBridges, egressBridges []string
	ingressMode, egressMode                        string
}

func (s splitArgs) any() bool {
	return len(s.ingress)+len(s.egress)+len(s.ingressBridges)+len(s.egressBridges) > 0
}

// parseSplitClientArgs builds a group with separate ingress paths and egress paths.
// The routes of each direction come first, then its bridges.
func parseSplitClientArgs(listenPort uint16, advertised netip.Addr, controlSocket string, split splitArgs) (*config.Client, error) {
	if len(split.ingress)+len(split.ingressBridges) == 0 || len(split.egress)+len(split.egressBridges) == 0 {
		return nil, errors.New("the ingress paths and the egress paths go together: give --ingress or --ingress-bridge, and --egress or --egress-bridge")
	}
	ingressMode, err := config.ParseMode(split.ingressMode)
	if err != nil {
		return nil, fmt.Errorf("--ingress-mode: %w", err)
	}
	egressMode, err := config.ParseMode(split.egressMode)
	if err != nil {
		return nil, fmt.Errorf("--egress-mode: %w", err)
	}
	group := config.Group{ListenPort: listenPort, Mode: ingressMode, EgressMode: egressMode}
	for _, part := range []struct {
		flagName string
		raws     []string
		bridge   bool
		into     *[]config.Path
	}{
		{"ingress", split.ingress, false, &group.Paths},
		{"ingress-bridge", split.ingressBridges, true, &group.Paths},
		{"egress", split.egress, false, &group.EgressPaths},
		{"egress-bridge", split.egressBridges, true, &group.EgressPaths},
	} {
		for i, raw := range part.raws {
			path, err := config.ParsePath(raw)
			if err != nil {
				return nil, fmt.Errorf("client --%s[%d]: %w", part.flagName, i, err)
			}
			path.Bridge = part.bridge
			*part.into = append(*part.into, path)
		}
	}
	client := &config.Client{AdvertisedIP: advertised, ControlSocket: controlSocket, Groups: []config.Group{group}}
	if err := client.Validate(); err != nil {
		return nil, err
	}
	return client, nil
}

func parseServerArgs(args []string) (*config.Server, error) {
	fs := flag.NewFlagSet("mup server", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var portRaw, targetRaw, controlSocket string
	var targetIngress bool
	fs.StringVar(&portRaw, "p", "", "UDP port and ICMP identifier, as PORT or FIRST-LAST")
	fs.BoolVar(&targetIngress, "target-ingress", false, "deliver packets into the ingress hook of the target interface")
	fs.StringVar(&targetRaw, "r", "", "WireGuard UDP target as IPv4:PORT")
	fs.StringVar(&controlSocket, "control-socket", api.DefaultServerSocket, "Unix socket for mupctl, or empty to disable")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("unexpected server argument %q", fs.Arg(0))
	}
	serverPort, err := config.ParsePortRange(portRaw)
	if err != nil {
		return nil, fmt.Errorf("server -p: %w", err)
	}
	target, err := netip.ParseAddrPort(targetRaw)
	if err != nil {
		return nil, errors.New("server -r must be a nonzero IPv4:PORT")
	}
	server := &config.Server{Port: serverPort, Target: target, ControlSocket: controlSocket, TargetIngress: targetIngress}
	if err := server.Validate(); err != nil {
		return nil, err
	}
	return server, nil
}

func parseBridgeArgs(args []string) (*config.Bridge, error) {
	fs := flag.NewFlagSet("mup bridge", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var serverRaw, portRaw, controlSocket string
	var allowRaw stringList
	fs.StringVar(&serverRaw, "s", "", "IPv4 address of the MUP server")
	fs.StringVar(&portRaw, "p", "", "UDP ports and ICMP identifiers, as PORT or FIRST-LAST")
	fs.Var(&allowRaw, "a", "more source ranges of the server, as IPv4 CIDR")
	fs.StringVar(&controlSocket, "control-socket", api.DefaultBridgeSocket, "Unix socket for mupctl, or empty to disable")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("unexpected bridge argument %q", fs.Arg(0))
	}
	server, err := parseRequiredIPv4(serverRaw, "bridge -s")
	if err != nil {
		return nil, err
	}
	ports, err := config.ParsePortRange(portRaw)
	if err != nil {
		return nil, fmt.Errorf("bridge -p: %w", err)
	}
	bridge := &config.Bridge{Server: server, Port: ports, ControlSocket: controlSocket}
	for i, raw := range allowRaw {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("bridge -a[%d]: %w", i, err)
		}
		bridge.Allow = append(bridge.Allow, prefix)
	}
	if err := bridge.Validate(); err != nil {
		return nil, err
	}
	return bridge, nil
}

func parseRequiredIPv4(raw, flagName string) (netip.Addr, error) {
	address, err := netip.ParseAddr(raw)
	if err != nil || !address.Is4() || address.IsUnspecified() {
		return netip.Addr{}, fmt.Errorf("%s must be a nonzero IPv4 address", flagName)
	}
	return address, nil
}

func portFromFlag(value int, name string) (uint16, error) {
	if value <= 0 || value > 65535 {
		return 0, fmt.Errorf("%s must be between 1 and 65535", name)
	}
	return uint16(value), nil
}
