// Command mupctl inspects and changes a running mup daemon through its
// control socket.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xshecan/mup/api"
)

const usage = `mupctl controls a running mup daemon.

Usage:
  mupctl [flags] COMMAND

Commands:
  status                                 Show an overview of the daemon
  groups                                 List the path groups of a client
  paths                                  List the paths of a client
  peers                                  List the peers of a client, or the peer routes of a server
  clients                                List the clients that are registered on a server
  reflectors                             List the return-pool reflectors of a server and their health
  drops                                  List the drop counters
  reset drops                            Set every drop counter to zero
  add path SERVER[%IFACE]:PORT[-LAST]/udp|icmp [via RETURN_IP]
                                         Add a path to a group
  delete path ID                         Remove a path from a client
  set mode fallback|balancer|burst       Change the path mode of a group
  version                                Print the version of mupctl

  Each list command also works after get, for example get paths.

  With --down, add, delete, and set work on the down paths and the
  downstream mode of a group with separate down paths. With --bridge, add
  adds a path through a MUP bridge, and the address is the bridge address.

Flags:
  --socket PATH       Control socket of the daemon. The default is $MUP_SOCKET,
                      /run/mup/client.sock, /run/mup/server.sock, or
                      /run/mup/bridge.sock.
  -o, --output FORMAT table, wide, or json. The default is table.
  -w, --watch         Show the output again every second (status and get only).
  --group LISTEN_PORT The group for add and set. A client with one group does
                      not need it.
  --down              Add, delete, or set a down path or the downstream mode.
  --bridge            Add a path through a MUP bridge.
`

const watchInterval = time.Second

type options struct {
	socket string
	output string
	group  uint16
	watch  bool
	down   bool
	bridge bool
	args   []string
}

type environment struct {
	getenv func(string) string
	exists func(string) bool
	now    func() time.Time
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	env := environment{getenv: os.Getenv, exists: socketExists, now: time.Now}
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, env, nil))
}

// run executes one mupctl command. A nil daemon makes run connect to the
// socket that the flags and the environment select.
func run(ctx context.Context, args []string, stdout, stderr io.Writer, env environment, daemon *api.DaemonClient) int {
	opts, err := parseOptions(args)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mupctl: %v\n\n%s", err, usage)
		return 2
	}
	if len(opts.args) == 0 || opts.args[0] == "help" {
		_, _ = fmt.Fprint(stdout, usage)
		if len(opts.args) == 0 {
			return 2
		}
		return 0
	}
	if opts.args[0] == "version" {
		_, _ = fmt.Fprintln(stdout, versionString())
		return 0
	}
	command, err := parseCommand(opts)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mupctl: %v\n\n%s", err, usage)
		return 2
	}
	socket := ""
	if daemon == nil {
		socket, err = resolveSocket(opts.socket, env)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "mupctl: %v\n", err)
			return 1
		}
		daemon = api.NewDaemonClient(socket)
	}
	call := invocation{daemon: daemon, output: opts.output, now: env.now}
	if opts.watch {
		err = watch(ctx, stdout, strings.Join(opts.args, " "), env.now, func(w io.Writer) error {
			return command(ctx, call, w)
		})
	} else {
		err = command(ctx, call, stdout)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mupctl: %v\n", explain(err, socket))
		return 1
	}
	return 0
}

func parseOptions(args []string) (options, error) {
	opts := options{output: "table"}
	for index := 0; index < len(args); index++ {
		arg := args[index]
		name, value, hasValue := strings.Cut(arg, "=")
		switch {
		case arg == "-w" || arg == "--watch":
			opts.watch = true
		case arg == "--down":
			opts.down = true
		case arg == "--bridge":
			opts.bridge = true
		case name == "--socket" || name == "-o" || name == "--output" || name == "--group":
			if !hasValue {
				if index+1 >= len(args) {
					return options{}, fmt.Errorf("flag %s needs a value", name)
				}
				index++
				value = args[index]
			}
			switch name {
			case "--socket":
				opts.socket = value
			case "--group":
				group, err := strconv.ParseUint(value, 10, 16)
				if err != nil || group == 0 {
					return options{}, fmt.Errorf("--group must be a listen port from 1 to 65535, got %q", value)
				}
				opts.group = uint16(group)
			default:
				opts.output = value
			}
		case strings.HasPrefix(arg, "-o") && len(arg) > 2:
			opts.output = arg[2:]
		case arg == "-h" || arg == "--help":
			opts.args = []string{"help"}
			return opts, nil
		case strings.HasPrefix(arg, "-") && arg != "-":
			return options{}, fmt.Errorf("unknown flag %s", arg)
		default:
			opts.args = append(opts.args, arg)
		}
	}
	switch opts.output {
	case "table", "wide", "json":
	default:
		return options{}, fmt.Errorf("unknown output format %q: use table, wide, or json", opts.output)
	}
	return opts, nil
}

type invocation struct {
	daemon *api.DaemonClient
	output string
	now    func() time.Time
}

func (s invocation) wide() bool { return s.output == "wide" }

type command func(ctx context.Context, s invocation, w io.Writer) error

func parseCommand(opts options) (command, error) {
	args := opts.args
	verb := args[0]
	if _, list := listCommand(verb); opts.watch && verb != "status" && verb != "get" && !list {
		return nil, fmt.Errorf("--watch works only with status and the list commands")
	}
	if opts.group != 0 && verb != "add" && verb != "set" {
		return nil, fmt.Errorf("--group works only with add and set")
	}
	if opts.down && verb != "add" && verb != "set" && verb != "delete" && verb != "del" && verb != "remove" && verb != "rm" {
		return nil, fmt.Errorf("--down works only with add, delete, and set")
	}
	if opts.bridge && verb != "add" {
		return nil, fmt.Errorf("--bridge works only with add")
	}
	switch verb {
	case "status":
		if err := expectArgs(args, 1); err != nil {
			return nil, err
		}
		return showStatus, nil
	case "get":
		if err := expectArgs(args, 2); err != nil {
			return nil, err
		}
		if show, ok := listCommand(args[1]); ok {
			return show, nil
		}
		return nil, fmt.Errorf("unknown resource %q: use groups, paths, peers, clients, reflectors, or drops", args[1])
	case "reset":
		if err := expectArgs(args, 2); err != nil {
			return nil, err
		}
		if args[1] != "drop" && args[1] != "drops" {
			return nil, fmt.Errorf("reset supports only drops")
		}
		return resetDrops, nil
	case "add":
		if len(args) != 3 && !(len(args) == 5 && args[3] == "via") &&
			!(len(args) == 7 && args[3] == "via" && args[5] == "balance") {
			return nil, fmt.Errorf("add path takes SERVER[%%IFACE]:PORT[-LAST]/udp|icmp [via RETURN_IP | via POOL_CIDR balance MODE]")
		}
		if !isPathResource(args[1]) {
			return nil, fmt.Errorf("add supports only paths")
		}
		spec := strings.Join(args[2:], " ")
		return func(ctx context.Context, s invocation, w io.Writer) error {
			return addPath(ctx, s, w, spec, opts.group, opts.down, opts.bridge)
		}, nil
	case "delete", "del", "remove", "rm":
		if err := expectArgs(args, 3); err != nil {
			return nil, err
		}
		if !isPathResource(args[1]) {
			return nil, fmt.Errorf("%s supports only paths", verb)
		}
		id, err := strconv.Atoi(args[2])
		if err != nil || id < 0 {
			return nil, fmt.Errorf("path ID %q is not a number", args[2])
		}
		return func(ctx context.Context, s invocation, w io.Writer) error {
			return deletePath(ctx, s, w, id, opts.down)
		}, nil
	case "set":
		if err := expectArgs(args, 3); err != nil {
			return nil, err
		}
		if args[1] != "mode" {
			return nil, fmt.Errorf("set supports only mode")
		}
		mode := args[2]
		return func(ctx context.Context, s invocation, w io.Writer) error {
			return setMode(ctx, s, w, mode, opts.group, opts.down)
		}, nil
	}
	if show, ok := listCommand(verb); ok {
		if err := expectArgs(args, 1); err != nil {
			return nil, err
		}
		return show, nil
	}
	return nil, fmt.Errorf("unknown command %q", verb)
}

// listCommand returns the command that lists a resource. Each resource has a
// singular and a plural name, and peers also has the name routes.
func listCommand(name string) (command, bool) {
	switch name {
	case "group", "groups":
		return showGroups, true
	case "path", "paths":
		return showPaths, true
	case "peer", "peers", "route", "routes":
		return showPeers, true
	case "client", "clients":
		return showClients, true
	case "reflector", "reflectors":
		return showReflectors, true
	case "drop", "drops":
		return showDrops, true
	}
	return nil, false
}

func resetDrops(ctx context.Context, s invocation, w io.Writer) error {
	if err := s.daemon.ResetDrops(ctx); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w, "drop counters reset")
	return err
}

func isPathResource(name string) bool {
	return name == "path" || name == "paths"
}

func expectArgs(args []string, count int) error {
	if len(args) != count {
		return fmt.Errorf("%s needs %d argument(s), got %d", args[0], count-1, len(args)-1)
	}
	return nil
}

func showStatus(ctx context.Context, s invocation, w io.Writer) error {
	status, err := s.daemon.Status(ctx)
	if err != nil {
		return err
	}
	var clients []api.RegisteredClient
	if status.Server != nil {
		if clients, err = s.daemon.Clients(ctx); err != nil {
			return err
		}
	}
	if s.output == "json" {
		return writeJSON(w, statusView{Status: status, Clients: clients})
	}
	printStatus(w, status, clients, s.wide(), s.now())
	return nil
}

// statusView is the JSON output of mupctl status.
type statusView struct {
	api.Status
	Clients []api.RegisteredClient `json:"clients,omitempty"`
}

func showGroups(ctx context.Context, s invocation, w io.Writer) error {
	status, err := s.daemon.Status(ctx)
	if err != nil {
		return err
	}
	if status.Client == nil {
		return fmt.Errorf("the daemon runs as a %s, and only a client has groups", status.Role)
	}
	if s.output == "json" {
		return writeJSON(w, status.Client.Groups)
	}
	printGroups(w, status.Client.Groups)
	return nil
}

func showPaths(ctx context.Context, s invocation, w io.Writer) error {
	paths, err := s.daemon.Paths(ctx)
	if err != nil {
		return err
	}
	if s.output == "json" {
		return writeJSON(w, paths)
	}
	printPaths(w, paths, s.wide(), s.now())
	return nil
}

func showPeers(ctx context.Context, s invocation, w io.Writer) error {
	peers, err := s.daemon.Peers(ctx)
	if err != nil {
		return err
	}
	if s.output == "json" {
		return writeJSON(w, peers)
	}
	if len(peers.Routes) > 0 {
		printRoutes(w, peers.Routes, s.wide())
		return nil
	}
	printPeers(w, peers.Peers)
	return nil
}

func showClients(ctx context.Context, s invocation, w io.Writer) error {
	clients, err := s.daemon.Clients(ctx)
	if err != nil {
		return err
	}
	if s.output == "json" {
		return writeJSON(w, clients)
	}
	printClients(w, clients, s.wide())
	return nil
}

func showReflectors(ctx context.Context, s invocation, w io.Writer) error {
	reflectors, err := s.daemon.Reflectors(ctx)
	if err != nil {
		return err
	}
	if s.output == "json" {
		return writeJSON(w, reflectors)
	}
	printReflectors(w, reflectors.Reflectors)
	return nil
}

func showDrops(ctx context.Context, s invocation, w io.Writer) error {
	status, err := s.daemon.Status(ctx)
	if err != nil {
		return err
	}
	if s.output == "json" {
		return writeJSON(w, status.Drops)
	}
	printDrops(w, status.Drops, s.wide())
	return nil
}

func addPath(ctx context.Context, s invocation, w io.Writer, spec string, group uint16, down, bridge bool) error {
	add, name, until := s.daemon.AddPath, "path", "ACK"
	if down {
		add, name, until = s.daemon.AddDownPath, "down path", "probe"
	}
	if bridge {
		add = func(ctx context.Context, spec string, group uint16) (api.Path, error) {
			return s.daemon.AddBridge(ctx, spec, group, down)
		}
		name = strings.Replace(name, "path", "bridge", 1)
	}
	path, err := add(ctx, spec, group)
	if err != nil {
		return err
	}
	if s.output == "json" {
		return writeJSON(w, path)
	}
	route := fmt.Sprintf("%s:%d/%s", path.Server, path.Port, path.Transport)
	if path.ReturnIP != "" {
		route += " via " + path.ReturnIP
	}
	_, err = fmt.Fprintf(w, "%s/%d created in group %d (%s, unhealthy until the first %s)\n", strings.ReplaceAll(name, " ", "-"), path.ID, path.ListenPort, route, until)
	return err
}

func deletePath(ctx context.Context, s invocation, w io.Writer, id int, down bool) error {
	remove, name := s.daemon.DeletePath, "path"
	if down {
		remove, name = s.daemon.DeleteDownPath, "down-path"
	}
	if err := remove(ctx, id); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "%s/%d deleted\n", name, id)
	return err
}

func setMode(ctx context.Context, s invocation, w io.Writer, mode string, group uint16, down bool) error {
	set, name := s.daemon.SetMode, "mode"
	if down {
		set, name = s.daemon.SetDownMode, "downstream mode"
	}
	if err := set(ctx, mode, group); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "%s set to %s\n", name, mode)
	return err
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

// watch clears the terminal and shows the output again every second, until
// ctx ends.
func watch(ctx context.Context, w io.Writer, title string, now func() time.Time, render func(io.Writer) error) error {
	for {
		var buffer bytes.Buffer
		err := render(&buffer)
		_, _ = fmt.Fprint(w, "\033[H\033[2J")
		_, _ = fmt.Fprintf(w, "Every %s: mupctl %s\t%s\n\n", watchInterval, title, now().Format(time.TimeOnly))
		if err != nil {
			_, _ = fmt.Fprintf(w, "error: %v\n", err)
		} else {
			_, _ = w.Write(buffer.Bytes())
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(watchInterval):
		}
	}
}

func resolveSocket(flagValue string, env environment) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if value := env.getenv("MUP_SOCKET"); value != "" {
		return value, nil
	}
	var found []string
	for _, socket := range []string{api.DefaultClientSocket, api.DefaultServerSocket, api.DefaultBridgeSocket} {
		if env.exists(socket) {
			found = append(found, socket)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return "", fmt.Errorf("no daemon socket at %s, %s, or %s. Start mup, or pass --socket", api.DefaultClientSocket, api.DefaultServerSocket, api.DefaultBridgeSocket)
	}
	return "", fmt.Errorf("%s exist, so choose one with --socket", strings.Join(found, " and "))
}

func socketExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode()&os.ModeSocket != 0
}

// explain turns socket errors into advice.
func explain(err error, socket string) error {
	var response *api.ResponseError
	if errors.As(err, &response) || socket == "" {
		return err
	}
	switch {
	case errors.Is(err, syscall.EACCES) || errors.Is(err, os.ErrPermission):
		return fmt.Errorf("permission denied on %s. Run mupctl as root, or as a member of the socket group", socket)
	case errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOENT):
		return fmt.Errorf("no daemon answers on %s. Make sure that mup runs", socket)
	}
	return err
}

func versionString() string {
	version := "(devel)"
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		version = info.Main.Version
	}
	return fmt.Sprintf("mupctl %s, control API v1", version)
}
