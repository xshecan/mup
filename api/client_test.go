package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestClientTalksOverAUnixSocket(t *testing.T) {
	t.Parallel()

	directory, err := os.MkdirTemp("", "mup")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socket := filepath.Join(directory, "s.sock")
	if len(socket) > 100 {
		t.Skipf("socket path %q is too long for this platform", socket)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Status{Role: RoleServer, Server: &ServerStatus{Port: 5000}})
	})
	mux.HandleFunc("PUT /v1/mode", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(Error{Error: "the daemon runs as a server"})
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	client := NewDaemonClient(socket)
	status, err := client.Status(context.Background())
	if err != nil || status.Role != RoleServer || status.Server.Port != 5000 {
		t.Fatalf("Status = %#v, %v", status, err)
	}
	err = client.SetMode(context.Background(), "burst", 0)
	var response *ResponseError
	if !errors.As(err, &response) || response.StatusCode != http.StatusConflict || response.Message != "the daemon runs as a server" {
		t.Fatalf("SetMode error = %#v", err)
	}
}
