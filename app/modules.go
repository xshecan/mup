package app

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"go.uber.org/fx"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/control"
	"github.com/xshecan/mup/dataplane"
	"github.com/xshecan/mup/protocol"
)

const registrationLeaseSeconds = 30

// controlSocket is the path of the Unix socket for mupctl. An empty path turns
// the API off.
type controlSocket string

type registrationSink interface {
	RegisterPath(dataplane.RegistrationSettings) error
	RevokeRegistration(dataplane.ClientKey) error
}

// daemonOptions builds the application of the configured role. Fx starts the
// hooks in the order that they are added, and stops them in reverse order. The
// role module runs first, so the program is attached before the loops start.
func daemonOptions(appConfig config.App) fx.Option {
	var role fx.Option
	if appConfig.Client != nil {
		role = clientModule(*appConfig.Client)
	} else {
		role = serverModule(*appConfig.Server)
	}
	return fx.Options(
		fx.Supply(appConfig, time.Now()),
		fx.Provide(
			func() routeResolver { return systemResolver{} },
			newRuntimePlan,
			newDataplane,
			newSupervisor,
			asLoop(newEventLoop),
			asLoop(newSweepLoop),
			asLoop(newAPILoop),
		),
		role,
	)
}

func clientModule(client config.Client) fx.Option {
	return fx.Module("client",
		fx.Supply(client),
		fx.Provide(
			func() pathOpener { return openClientPath },
			func() controlSocket { return controlSocket(client.ControlSocket) },
			func(plan runtimePlan) dataplane.ClientSettings { return *plan.client },
			func(runtime *dataplane.Runtime) clientDataplane { return runtime },
			newClientController,
			func(controller *clientController) http.Handler { return newAPIHandler(controller, nil) },
			asLoop(func(controller *clientController) loop { return controller.run }),
		),
		fx.Invoke(attachClient),
	)
}

func serverModule(server config.Server) fx.Option {
	return fx.Module("server",
		fx.Supply(server),
		fx.Provide(
			func() controlSocket { return controlSocket(server.ControlSocket) },
			func(runtime *dataplane.Runtime) serverDataplane { return runtime },
			newServerInspector,
			func(inspector *serverInspector) http.Handler { return newAPIHandler(nil, inspector) },
			func() *control.Registry {
				return control.NewRegistry(server.Port, registrationLeaseSeconds*time.Second)
			},
			asLoop(newServerControlLoop),
		),
		fx.Invoke(attachServer),
	)
}

// asLoop adds the result of a constructor to the daemon loops.
func asLoop(constructor any) any {
	return fx.Annotate(constructor, fx.ResultTags(`group:"loops"`))
}

func newRuntimePlan(appConfig config.App, resolver routeResolver) (runtimePlan, error) {
	var nonce uint64
	if appConfig.Client != nil {
		var err error
		if nonce, err = protocol.RandomInstanceNonce(); err != nil {
			return runtimePlan{}, err
		}
	}
	return buildPlan(appConfig, nonce, resolver)
}

func newDataplane(lifecycle fx.Lifecycle, plan runtimePlan) (*dataplane.Runtime, error) {
	runtime, err := dataplane.Load(dataplane.Config{PinRoot: plan.pinRoot})
	if err != nil {
		return nil, err
	}
	lifecycle.Append(fx.StopHook(runtime.Close))
	return runtime, nil
}

func attachClient(lifecycle fx.Lifecycle, runtime *dataplane.Runtime, plan runtimePlan) {
	lifecycle.Append(fx.StartHook(func() error {
		if err := runtime.ConfigureClient(*plan.client); err != nil {
			return err
		}
		return runtime.AttachClient(plan.attachIfindexes)
	}))
}

func attachServer(lifecycle fx.Lifecycle, runtime *dataplane.Runtime, plan runtimePlan) {
	lifecycle.Append(fx.StartHook(func() error {
		if err := runtime.ConfigureServer(*plan.server); err != nil {
			return err
		}
		return runtime.AttachServer(plan.attachIfindexes)
	}))
}

func newServerControlLoop(server config.Server, registry *control.Registry, runtime *dataplane.Runtime) loop {
	return func(ctx context.Context) error {
		if err := serveServerControls(ctx, server, registry, runtime); err != nil {
			return fmt.Errorf("serve control plane: %w", err)
		}
		return nil
	}
}

func newAPILoop(socket controlSocket, handler http.Handler) loop {
	return func(ctx context.Context) error {
		return serveAPI(ctx, string(socket), handler)
	}
}

func newEventLoop(runtime *dataplane.Runtime) loop {
	return func(ctx context.Context) error {
		return runtime.ConsumeEvents(ctx, func(event dataplane.Event) {
			log.Printf(
				"mup dataplane event: reason=%d ifindex=%d monotonic_ns=%d",
				event.Reason,
				event.Ifindex,
				event.TimestampNS,
			)
		})
	}
}

func newSweepLoop(runtime *dataplane.Runtime) loop {
	return func(ctx context.Context) error {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				now, err := monotonicNowNS()
				if err == nil {
					err = runtime.Sweep(now)
				}
				if err != nil {
					return err
				}
			}
		}
	}
}
