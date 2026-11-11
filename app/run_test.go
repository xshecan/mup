package app

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"go.uber.org/fx"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/protocol"
)

func TestDaemonOptionsResolveEveryDependency(t *testing.T) {
	t.Parallel()

	path := config.Path{Server: netip.MustParseAddr("198.51.100.1"), ServerPort: 5000, Transport: protocol.TransportUDP}
	roles := map[string]config.App{
		"client": {Client: &config.Client{
			AdvertisedIP: netip.MustParseAddr("192.0.2.10"),
			Groups:       []config.Group{{ListenPort: 51820, Paths: []config.Path{path}}},
		}},
		"server": {Server: &config.Server{Port: 5000, Target: netip.MustParseAddrPort("198.51.100.7:51820")}},
	}
	for name, appConfig := range roles {
		t.Run(name, func(t *testing.T) {
			var daemon *supervisor
			if err := fx.ValidateApp(fx.NopLogger, daemonOptions(appConfig), fx.Populate(&daemon)); err != nil {
				t.Fatalf("ValidateApp: %v", err)
			}
		})
	}
}

func loopOptions(loops ...loop) fx.Option {
	options := []fx.Option{fx.Provide(newSupervisor)}
	for _, current := range loops {
		options = append(options, fx.Provide(asLoop(func() loop { return current })))
	}
	return fx.Options(options...)
}

func waitForContext(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func runWithTimeout(t *testing.T, ctx context.Context, options fx.Option) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- runDaemon(ctx, options) }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("runDaemon did not return")
		return nil
	}
}

func TestRunDaemonReturnsTheFirstLoopFailure(t *testing.T) {
	t.Parallel()

	want := errors.New("sweep failed")
	stopped := make(chan struct{})
	options := loopOptions(
		func(context.Context) error { return want },
		func(ctx context.Context) error {
			defer close(stopped)
			return waitForContext(ctx)
		},
	)
	if err := runWithTimeout(t, context.Background(), options); !errors.Is(err, want) {
		t.Fatalf("runDaemon error = %v, want %v", err, want)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("runDaemon returned before the other loop stopped")
	}
}

func TestRunDaemonTreatsAReturnedLoopAsAFailure(t *testing.T) {
	t.Parallel()

	options := loopOptions(func(context.Context) error { return nil })
	if err := runWithTimeout(t, context.Background(), options); err == nil {
		t.Fatal("runDaemon returned no error after a loop stopped")
	}
}

func TestRunDaemonStopsCleanlyWhenTheContextEnds(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	options := loopOptions(func(ctx context.Context) error {
		close(started)
		return waitForContext(ctx)
	})
	go func() {
		<-started
		cancel()
	}()
	if err := runWithTimeout(t, ctx, options); err != nil {
		t.Fatalf("runDaemon error after cancel = %v, want nil", err)
	}
}

func TestRunDaemonReturnsConstructorErrors(t *testing.T) {
	t.Parallel()

	want := errors.New("load failed")
	options := fx.Options(
		loopOptions(),
		fx.Provide(func() (*netip.Addr, error) { return nil, want }),
		fx.Invoke(func(*netip.Addr) {}),
	)
	if err := runWithTimeout(t, context.Background(), options); err != want {
		t.Fatalf("runDaemon error = %v, want exactly %v", err, want)
	}
}

func TestRoleHooksStartBeforeTheLoops(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var order []string
	record := func(entry string) {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, entry)
	}
	ctx, cancel := context.WithCancel(context.Background())
	options := fx.Options(
		loopOptions(func(ctx context.Context) error {
			record("loop")
			cancel()
			return waitForContext(ctx)
		}),
		fx.Module("role", fx.Invoke(func(lifecycle fx.Lifecycle) {
			lifecycle.Append(fx.StartStopHook(func() { record("attach") }, func() { record("detach") }))
		})),
	)
	if err := runWithTimeout(t, ctx, options); err != nil {
		t.Fatalf("runDaemon: %v", err)
	}
	if !slices.Equal(order, []string{"attach", "loop", "detach"}) {
		t.Fatalf("order = %v, want [attach loop detach]", order)
	}
}
