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
  get groups                             List the path groups of a client
  get paths                              List the paths of a client
  get peers                              List the peers of a client, or the peer routes of a server
  get clients                            List the clients that are registered on a server
  get drops                              List the drop counters
  add path SERVER[%IFACE]:PORT/udp|icmp [via RETURN_IP]
                                         Add a path to a group
  delete path ID                         Remove a path from a client
  set mode fallback|balancer|burst       Change the path mode of a group
  version                                Print the version of mupctl

Flags:
  --socket PATH       Control socket of the daemon. The default is $MUP_SOCKET,
                      /run/mup/client.sock, or /run/mup/server.sock.
  -o, --output FORMAT table, wide, or json. The default is table.
  -w, --watch         Show the output again every second (status and get only).
  --group LISTEN_PORT The group for add and set. A client with one group does
                      not need it.
`

const watchInterval = time.Second

type options struct {
	socket string
	output string
	group  uint16
	watch  bool
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
	if opts.watch && verb != "status" && verb != "get" {
		return nil, fmt.Errorf("--watch works only with status and get")
	}
	if opts.group != 0 && verb != "add" && verb != "set" {
		return nil, fmt.Errorf("--group works only with add and set")
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
		switch args[1] {
		case "group", "groups":
			return showGroups, nil
		case "path", "paths":
			return showPaths, nil
		case "peer", "peers", "route", "routes":
			return showPeers, nil
		case "client", "clients":
			return showClients, nil
		case "drop", "drops":
			return showDrops, nil
		}
		return nil, fmt.Errorf("unknown resource %q: use groups, paths, peers, clients, or drops", args[1])
	case "add":
		if len(args) != 3 && (len(args) != 5 || args[3] != "via") {
			return nil, fmt.Errorf("add path takes SERVER[%%IFACE]:PORT/udp|icmp [via RETURN_IP]")
		}
		if !isPathResource(args[1]) {
			return nil, fmt.Errorf("add supports only paths")
		}
		spec := strings.Join(args[2:], " ")
		return func(ctx context.Context, s invocation, w io.Writer) error {
			return addPath(ctx, s, w, spec, opts.group)
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
			return deletePath(ctx, s, w, id)
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
			return setMode(ctx, s, w, mode, opts.group)
		}, nil
	}
	return nil, fmt.Errorf("unknown command %q", verb)
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
		return errors.New("the daemon runs as a server, and only a client has groups")
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

func addPath(ctx context.Context, s invocation, w io.Writer, spec string, group uint16) error {
	path, err := s.daemon.AddPath(ctx, spec, group)
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
	_, err = fmt.Fprintf(w, "path/%d created in group %d (%s, unhealthy until the first ACK)\n", path.ID, path.ListenPort, route)
	return err
}

func deletePath(ctx context.Context, s invocation, w io.Writer, id int) error {
	if err := s.daemon.DeletePath(ctx, id); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "path/%d deleted\n", id)
	return err
}

func setMode(ctx context.Context, s invocation, w io.Writer, mode string, group uint16) error {
	if err := s.daemon.SetMode(ctx, mode, group); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "mode set to %s\n", mode)
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
	client := env.exists(api.DefaultClientSocket)
	server := env.exists(api.DefaultServerSocket)
	switch {
	case client && server:
		return "", fmt.Errorf("both %s and %s exist, so choose one with --socket", api.DefaultClientSocket, api.DefaultServerSocket)
	case client:
		return api.DefaultClientSocket, nil
	case server:
		return api.DefaultServerSocket, nil
	}
	return "", fmt.Errorf("no daemon socket at %s or %s. Start mup, or pass --socket", api.DefaultClientSocket, api.DefaultServerSocket)
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
