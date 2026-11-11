package app

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"time"

	"go.uber.org/dig"
	"go.uber.org/fx"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
)

const (
	startTimeout = time.Minute
	stopTimeout  = 10 * time.Second
)

// Run runs the daemon until ctx ends or a daemon loop fails.
func Run(ctx context.Context, appConfig config.App) error {
	if runtime.GOOS != "linux" {
		return dataplane.ErrUnsupportedPlatform
	}
	return runDaemon(ctx, daemonOptions(appConfig))
}

func runDaemon(ctx context.Context, options fx.Option) error {
	var daemon *supervisor
	application := fx.New(fx.NopLogger, options, fx.Populate(&daemon))
	if err := application.Err(); err != nil {
		return dig.RootCause(err)
	}
	// A signal during the start waits for the start to finish, so that the stop
	// hooks always see a complete application.
	starting, cancelStart := context.WithTimeout(context.Background(), startTimeout)
	defer cancelStart()
	if err := application.Start(starting); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
	case <-application.Wait():
	}
	stopping, cancelStop := context.WithTimeout(context.Background(), stopTimeout)
	defer cancelStop()
	stopErr := application.Stop(stopping)
	return errors.Join(daemon.Err(), stopErr)
}

// loop is a part of the daemon that runs until its context ends.
type loop func(context.Context) error

type supervisorParams struct {
	fx.In

	Lifecycle  fx.Lifecycle
	Shutdowner fx.Shutdowner
	Loops      []loop `group:"loops"`
}

// supervisor runs the daemon loops between start and stop. The first loop that
// stops by itself shuts the application down.
type supervisor struct {
	loops      []loop
	shutdowner fx.Shutdowner
	cancel     context.CancelFunc
	running    sync.WaitGroup
	failure    chan error
}

func newSupervisor(params supervisorParams) *supervisor {
	s := &supervisor{loops: params.Loops, shutdowner: params.Shutdowner, failure: make(chan error, 1)}
	params.Lifecycle.Append(fx.StartStopHook(s.start, s.stop))
	return s
}

func (s *supervisor) start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	for _, run := range s.loops {
		s.running.Go(func() {
			err := run(ctx)
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				err = errors.New("a daemon loop stopped unexpectedly")
			}
			s.fail(err)
		})
	}
}

func (s *supervisor) fail(err error) {
	select {
	case s.failure <- err:
		_ = s.shutdowner.Shutdown()
	default:
	}
}

func (s *supervisor) stop(ctx context.Context) error {
	s.cancel()
	stopped := make(chan struct{})
	go func() {
		s.running.Wait()
		close(stopped)
	}()
	select {
	case <-stopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Err returns the failure that shut the application down, or nil.
func (s *supervisor) Err() error {
	select {
	case err := <-s.failure:
		return err
	default:
		return nil
	}
}
