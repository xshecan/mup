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
  mup server -p PORT -r TARGET_IP:PORT [--control-socket PATH]
  mup client -p LISTEN_PORT -u SERVER_IP[%IFACE]:PORT/udp|icmp [-u ...] -s CLIENT_IP [-r RETURN_IP]
             [--mode fallback|balancer|burst] [--control-socket PATH]
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
		return config.App{}, errors.New("expected client or server subcommand")
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
	default:
		if strings.HasPrefix(args[0], "-") {
			return parseFileArgs(args)
		}
		return config.App{}, fmt.Errorf("unknown subcommand %q: expected client or server", args[0])
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
		return config.App{}, errors.New("expected client or server subcommand, or --config")
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
	var rawPaths stringList
	var port int
	var advertisedText, returnIPText, modeName, controlSocket string
	fs.IntVar(&port, "p", 0, "local WireGuard UDP listen port")
	fs.Var(&rawPaths, "u", "server path as IPv4:PORT/udp or /icmp")
	fs.StringVar(&advertisedText, "s", "", "advertised client IPv4")
	fs.StringVar(&returnIPText, "r", "", "spoofed UDP source or ICMP reflector IPv4")
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
		paths = append(paths, path)
	}
	client := &config.Client{
		AdvertisedIP:  advertised,
		ControlSocket: controlSocket,
		Groups:        []config.Group{{ListenPort: listenPort, Mode: mode, ReturnIP: returnIP, Paths: paths}},
	}
	if err := client.Validate(); err != nil {
		return nil, err
	}
	return client, nil
}

func parseServerArgs(args []string) (*config.Server, error) {
	fs := flag.NewFlagSet("mup server", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var port int
	var targetRaw, controlSocket string
	fs.IntVar(&port, "p", 0, "UDP port and ICMP identifier")
	fs.StringVar(&targetRaw, "r", "", "WireGuard UDP target as IPv4:PORT")
	fs.StringVar(&controlSocket, "control-socket", api.DefaultServerSocket, "Unix socket for mupctl, or empty to disable")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("unexpected server argument %q", fs.Arg(0))
	}
	serverPort, err := portFromFlag(port, "server -p")
	if err != nil {
		return nil, err
	}
	target, err := netip.ParseAddrPort(targetRaw)
	if err != nil {
		return nil, errors.New("server -r must be a nonzero IPv4:PORT")
	}
	server := &config.Server{Port: serverPort, Target: target, ControlSocket: controlSocket}
	if err := server.Validate(); err != nil {
		return nil, err
	}
	return server, nil
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
