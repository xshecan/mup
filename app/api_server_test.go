package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xshecan/mup/api"
)

type fakeClientAPI struct {
	removed int
	mode    string
	group   uint16
}

func (f *fakeClientAPI) Status() (api.Status, error) {
	return api.Status{Role: api.RoleClient, Client: &api.ClientStatus{Groups: []api.Group{{ListenPort: 51820, Mode: "fallback"}}}}, nil
}

func (f *fakeClientAPI) Paths() ([]api.Path, error) {
	return []api.Path{{ID: 0, Server: "198.51.100.1", Healthy: true}}, nil
}

func (f *fakeClientAPI) AddPath(raw string, listenPort uint16) (api.Path, error) {
	if raw == "bad" {
		return api.Path{}, badRequest(errors.New("path must use IPv4:PORT/udp or /icmp"))
	}
	f.group = listenPort
	return api.Path{ID: 3, Server: "198.51.100.3"}, nil
}

func (f *fakeClientAPI) RemovePath(id int) error {
	if id == 9 {
		return notFound("path %d does not exist", id)
	}
	f.removed = id
	return nil
}

func (f *fakeClientAPI) SetMode(raw string, listenPort uint16) error {
	f.mode = raw
	f.group = listenPort
	return nil
}

func (f *fakeClientAPI) Peers() (api.PeerList, error) {
	return api.PeerList{Peers: []api.Peer{{Token: 1}}}, nil
}

type fakeServerAPI struct{}

func (fakeServerAPI) Status() (api.Status, error) {
	return api.Status{Role: api.RoleServer, Server: &api.ServerStatus{Port: 5000}}, nil
}

func (fakeServerAPI) Peers() (api.PeerList, error) {
	return api.PeerList{Routes: []api.Route{{Client: "192.0.2.10", Token: 4}}}, nil
}

func (fakeServerAPI) Clients() ([]api.RegisteredClient, error) {
	return []api.RegisteredClient{{AdvertisedIP: "192.0.2.10"}}, nil
}

func newTestDaemonClient(t *testing.T, handler http.Handler) *api.DaemonClient {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return api.NewHTTPDaemonClient(server.URL, server.Client())
}

func responseStatus(err error) int {
	var failure *api.ResponseError
	if errors.As(err, &failure) {
		return failure.StatusCode
	}
	return 0
}

func TestClientAPIServesPathsAndMode(t *testing.T) {
	t.Parallel()

	backend := &fakeClientAPI{}
	client := newTestDaemonClient(t, newAPIHandler(backend, nil))
	ctx := context.Background()

	status, err := client.Status(ctx)
	if err != nil || status.Role != api.RoleClient || status.Client.Groups[0].Mode != "fallback" {
		t.Fatalf("Status = %#v, %v", status, err)
	}
	added, err := client.AddPath(ctx, "198.51.100.3:5000/udp", 51821)
	if err != nil || added.ID != 3 {
		t.Fatalf("AddPath = %#v, %v", added, err)
	}
	if _, err := client.AddPath(ctx, "bad", 0); responseStatus(err) != http.StatusBadRequest {
		t.Fatalf("AddPath(bad) error = %v, want status 400", err)
	}
	if err := client.DeletePath(ctx, 2); err != nil || backend.removed != 2 {
		t.Fatalf("DeletePath = %v, removed %d", err, backend.removed)
	}
	if err := client.DeletePath(ctx, 9); responseStatus(err) != http.StatusNotFound || err.Error() != "path 9 does not exist" {
		t.Fatalf("DeletePath(9) error = %v", err)
	}
	if backend.group != 51821 {
		t.Fatalf("AddPath group = %d, want 51821", backend.group)
	}
	if err := client.SetMode(ctx, "burst", 51822); err != nil || backend.mode != "burst" || backend.group != 51822 {
		t.Fatalf("SetMode = %v, mode %q, group %d", err, backend.mode, backend.group)
	}
	if _, err := client.Clients(ctx); responseStatus(err) != http.StatusConflict {
		t.Fatalf("Clients on a client daemon error = %v, want status 409", err)
	}
}

func TestServerAPIRefusesClientCommands(t *testing.T) {
	t.Parallel()

	client := newTestDaemonClient(t, newAPIHandler(nil, fakeServerAPI{}))
	ctx := context.Background()
	if _, err := client.Paths(ctx); responseStatus(err) != http.StatusConflict {
		t.Fatalf("Paths on a server error = %v, want status 409", err)
	}
	if err := client.SetMode(ctx, "burst", 0); responseStatus(err) != http.StatusConflict {
		t.Fatalf("SetMode on a server error = %v, want status 409", err)
	}
	peers, err := client.Peers(ctx)
	if err != nil || len(peers.Routes) != 1 || peers.Routes[0].Token != 4 {
		t.Fatalf("Peers = %#v, %v", peers, err)
	}
	clients, err := client.Clients(ctx)
	if err != nil || len(clients) != 1 {
		t.Fatalf("Clients = %#v, %v", clients, err)
	}
}

func TestAPIRejectsUnknownRequestFields(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(newAPIHandler(&fakeClientAPI{}, nil))
	t.Cleanup(server.Close)
	request, err := http.NewRequest(http.MethodPut, server.URL+"/v1/mode", strings.NewReader(`{"mode":"burst","extra":1}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.StatusCode)
	}
}

func TestListenUnixReplacesAStaleSocketOnly(t *testing.T) {
	t.Parallel()

	directory, err := os.MkdirTemp("", "mup")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "c.sock")
	if len(path) > 100 {
		t.Skipf("socket path %q is too long for this platform", path)
	}

	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("create stale socket: %v", err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = stale.Close()

	listener, err := listenUnix(path)
	if err != nil {
		t.Fatalf("listenUnix over a stale socket: %v", err)
	}
	if _, err := listenUnix(path); err == nil {
		t.Fatal("listenUnix took over a live socket")
	}
	_ = listener.Close()

	regular := filepath.Join(directory, "file")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := listenUnix(regular); err == nil {
		t.Fatal("listenUnix replaced a regular file")
	}
}

func TestServeAPIStopsWithTheContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveAPI(ctx, "", http.NotFoundHandler()) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("serveAPI error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serveAPI did not stop")
	}
}
