package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/xshecan/mup/api"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/protocol"
)

const maxRequestBytes = 4096

type clientAPI interface {
	Status() (api.Status, error)
	Paths() ([]api.Path, error)
	AddPath(raw string, listenPort uint16) (api.Path, error)
	RemovePath(id int) error
	SetMode(raw string, listenPort uint16) error
	Peers() (api.PeerList, error)
}

type serverAPI interface {
	Status() (api.Status, error)
	Peers() (api.PeerList, error)
	Clients() ([]api.RegisteredClient, error)
}

// apiError carries the HTTP status of a failed request. Other errors become
// 500 Internal Server Error.
type apiError struct {
	status int
	err    error
}

func (e *apiError) Error() string { return e.err.Error() }
func (e *apiError) Unwrap() error { return e.err }

func badRequest(err error) error {
	return &apiError{status: http.StatusBadRequest, err: err}
}

func notFound(format string, args ...any) error {
	return &apiError{status: http.StatusNotFound, err: fmt.Errorf(format, args...)}
}

func conflict(format string, args ...any) error {
	return &apiError{status: http.StatusConflict, err: fmt.Errorf(format, args...)}
}

func unavailable(format string, args ...any) error {
	return &apiError{status: http.StatusServiceUnavailable, err: fmt.Errorf(format, args...)}
}

type apiHandler struct {
	client clientAPI
	server serverAPI
}

// newAPIHandler serves the control API of a client or of a server. Exactly
// one of client and server is non-nil.
func newAPIHandler(client clientAPI, server serverAPI) http.Handler {
	handler := apiHandler{client: client, server: server}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", handler.status)
	mux.HandleFunc("GET /v1/paths", handler.paths)
	mux.HandleFunc("POST /v1/paths", handler.addPath)
	mux.HandleFunc("DELETE /v1/paths/{id}", handler.removePath)
	mux.HandleFunc("PUT /v1/mode", handler.setMode)
	mux.HandleFunc("GET /v1/peers", handler.peers)
	mux.HandleFunc("GET /v1/clients", handler.clients)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, notFound("unknown API path"))
	})
	return mux
}

func (h apiHandler) status(w http.ResponseWriter, _ *http.Request) {
	if h.client != nil {
		value, err := h.client.Status()
		writeResult(w, http.StatusOK, value, err)
		return
	}
	value, err := h.server.Status()
	writeResult(w, http.StatusOK, value, err)
}

func (h apiHandler) paths(w http.ResponseWriter, _ *http.Request) {
	if h.requireClient(w, "paths") {
		value, err := h.client.Paths()
		writeResult(w, http.StatusOK, value, err)
	}
}

func (h apiHandler) addPath(w http.ResponseWriter, r *http.Request) {
	if !h.requireClient(w, "paths") {
		return
	}
	var request api.AddPathRequest
	if err := decodeRequest(w, r, &request); err != nil {
		writeError(w, err)
		return
	}
	value, err := h.client.AddPath(request.Path, request.ListenPort)
	writeResult(w, http.StatusCreated, value, err)
}

func (h apiHandler) removePath(w http.ResponseWriter, r *http.Request) {
	if !h.requireClient(w, "paths") {
		return
	}
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, badRequest(fmt.Errorf("path ID %q is not a number", r.PathValue("id"))))
		return
	}
	if err := h.client.RemovePath(id); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h apiHandler) setMode(w http.ResponseWriter, r *http.Request) {
	if !h.requireClient(w, "the path mode") {
		return
	}
	var request api.ModeRequest
	if err := decodeRequest(w, r, &request); err != nil {
		writeError(w, err)
		return
	}
	if err := h.client.SetMode(request.Mode, request.ListenPort); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h apiHandler) peers(w http.ResponseWriter, _ *http.Request) {
	if h.client != nil {
		value, err := h.client.Peers()
		writeResult(w, http.StatusOK, value, err)
		return
	}
	value, err := h.server.Peers()
	writeResult(w, http.StatusOK, value, err)
}

func (h apiHandler) clients(w http.ResponseWriter, _ *http.Request) {
	if h.server == nil {
		writeError(w, conflict("the daemon runs as a client, and only a server has registered clients"))
		return
	}
	value, err := h.server.Clients()
	writeResult(w, http.StatusOK, value, err)
}

func (h apiHandler) requireClient(w http.ResponseWriter, resource string) bool {
	if h.client == nil {
		writeError(w, conflict("the daemon runs as a server, and only a client has %s", resource))
		return false
	}
	return true
}

func decodeRequest(w http.ResponseWriter, r *http.Request, request any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(request); err != nil {
		return badRequest(fmt.Errorf("decode request: %w", err))
	}
	return nil
}

// writeResult writes the result of a backend call.
func writeResult(w http.ResponseWriter, status int, value any, err error) {
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, status, value)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	var failure *apiError
	if errors.As(err, &failure) {
		status = failure.status
	}
	writeJSON(w, status, api.Error{Error: err.Error()})
}

// serveAPI serves handler on a Unix socket until ctx ends. An empty socket
// path turns the API off.
func serveAPI(ctx context.Context, socketPath string, handler http.Handler) error {
	if socketPath == "" {
		<-ctx.Done()
		return ctx.Err()
	}
	listener, err := listenUnix(socketPath)
	if err != nil {
		return fmt.Errorf("open control socket: %w", err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	served := make(chan error, 1)
	go func() {
		served <- server.Serve(listener)
	}()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		return ctx.Err()
	case err := <-served:
		return fmt.Errorf("serve control socket: %w", err)
	}
}

// listenUnix replaces a stale socket file, but refuses to take over a socket
// that another daemon still serves. Only root and the socket group can
// connect.
func listenUnix(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if connection, err := net.DialTimeout("unix", path, time.Second); err == nil {
			_ = connection.Close()
			return nil, fmt.Errorf("another daemon listens on %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func apiDrops(snapshot dataplane.StatsSnapshot) []api.Drop {
	drops := make([]api.Drop, 0, len(snapshot.Drops)-1)
	for reason := 1; reason < len(snapshot.Drops); reason++ {
		drops = append(drops, api.Drop{
			Reason: uint32(reason),
			Name:   protocol.DropReason(reason).String(),
			Count:  snapshot.Drops[reason],
		})
	}
	return drops
}
