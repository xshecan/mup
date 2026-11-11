package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// ResponseError is an error that the daemon returned.
type ResponseError struct {
	StatusCode int
	Message    string
}

func (e *ResponseError) Error() string {
	return e.Message
}

// DaemonClient calls the control API of one daemon.
type DaemonClient struct {
	baseURL string
	http    *http.Client
}

// NewDaemonClient returns a client for the daemon that listens on socketPath.
func NewDaemonClient(socketPath string) *DaemonClient {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	return NewHTTPDaemonClient("http://mup", &http.Client{Transport: transport, Timeout: 10 * time.Second})
}

// NewHTTPDaemonClient returns a client for a daemon at baseURL. Tests use it with
// an httptest server.
func NewHTTPDaemonClient(baseURL string, client *http.Client) *DaemonClient {
	return &DaemonClient{baseURL: baseURL, http: client}
}

func (c *DaemonClient) Status(ctx context.Context) (Status, error) {
	var status Status
	err := c.do(ctx, http.MethodGet, "/v1/status", nil, &status)
	return status, err
}

func (c *DaemonClient) Paths(ctx context.Context) ([]Path, error) {
	var paths []Path
	err := c.do(ctx, http.MethodGet, "/v1/paths", nil, &paths)
	return paths, err
}

func (c *DaemonClient) AddPath(ctx context.Context, path string, listenPort uint16) (Path, error) {
	var added Path
	err := c.do(ctx, http.MethodPost, "/v1/paths", AddPathRequest{Path: path, ListenPort: listenPort}, &added)
	return added, err
}

func (c *DaemonClient) DeletePath(ctx context.Context, id int) error {
	return c.do(ctx, http.MethodDelete, "/v1/paths/"+strconv.Itoa(id), nil, nil)
}

func (c *DaemonClient) SetMode(ctx context.Context, mode string, listenPort uint16) error {
	return c.do(ctx, http.MethodPut, "/v1/mode", ModeRequest{Mode: mode, ListenPort: listenPort}, nil)
}

func (c *DaemonClient) Peers(ctx context.Context) (PeerList, error) {
	var peers PeerList
	err := c.do(ctx, http.MethodGet, "/v1/peers", nil, &peers)
	return peers, err
}

func (c *DaemonClient) Clients(ctx context.Context) ([]RegisteredClient, error) {
	var clients []RegisteredClient
	err := c.do(ctx, http.MethodGet, "/v1/clients", nil, &clients)
	return clients, err
}

func (c *DaemonClient) do(ctx context.Context, method, path string, request, response any) error {
	var body io.Reader
	if request != nil {
		encoded, err := json.Marshal(request)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if request != nil {
		httpRequest.Header.Set("Content-Type", "application/json")
	}
	httpResponse, err := c.http.Do(httpRequest)
	if err != nil {
		return err
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode > 299 {
		var apiError Error
		if err := json.NewDecoder(httpResponse.Body).Decode(&apiError); err != nil || apiError.Error == "" {
			apiError.Error = fmt.Sprintf("daemon returned %s", httpResponse.Status)
		}
		return &ResponseError{StatusCode: httpResponse.StatusCode, Message: apiError.Error}
	}
	if response == nil {
		return nil
	}
	if err := json.NewDecoder(httpResponse.Body).Decode(response); err != nil {
		return fmt.Errorf("decode daemon response: %w", err)
	}
	return nil
}
