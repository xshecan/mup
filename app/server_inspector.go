package app

import (
	"fmt"
	"time"

	"github.com/xshecan/mup/api"
	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
)

type serverDataplane interface {
	Snapshot() (dataplane.StatsSnapshot, error)
	ServerRoutes() ([]dataplane.ServerRoute, error)
	Registrations() ([]dataplane.Registration, error)
	RegisteredPaths() ([]dataplane.RegisteredPath, error)
}

// serverInspector answers the read-only API calls of a server.
type serverInspector struct {
	server        config.Server
	dataplane     serverDataplane
	startedAt     time.Time
	interfaceName func(int) string
}

func newServerInspector(server config.Server, plane serverDataplane, startedAt time.Time) *serverInspector {
	return &serverInspector{server: server, dataplane: plane, startedAt: startedAt, interfaceName: interfaceName}
}

func (s *serverInspector) Status() (api.Status, error) {
	snapshot, err := s.dataplane.Snapshot()
	if err != nil {
		return api.Status{}, err
	}
	return api.Status{
		Role:      api.RoleServer,
		StartedAt: s.startedAt,
		Server: &api.ServerStatus{
			Port:             s.server.Port,
			Target:           s.server.Target.String(),
			Clients:          snapshot.Registrations,
			Paths:            snapshot.RegisteredPaths,
			Peers:            snapshot.ServerRoutes,
			PortsFree:        snapshot.TargetPortsAvailable,
			PortsQuarantined: snapshot.PortsQuarantined,
			Duplicates:       snapshot.DuplicateEntries,
		},
		Drops: apiDrops(snapshot),
	}, nil
}

func (s *serverInspector) Peers() (api.PeerList, error) {
	routes, err := s.dataplane.ServerRoutes()
	if err != nil {
		return api.PeerList{}, err
	}
	list := make([]api.Route, 0, len(routes))
	for _, route := range routes {
		converted := api.Route{
			Client:      route.Client.AdvertisedIP.String(),
			Nonce:       formatNonce(route.Client.InstanceNonce),
			Token:       route.Token,
			TargetPort:  route.TargetPort,
			Transport:   route.Transport.String(),
			PathID:      route.PathID,
			Source:      route.ClientSource.String(),
			Local:       route.ServerLocal.String(),
			Interface:   s.interfaceName(route.Ifindex),
			IdleSeconds: route.Idle.Seconds(),
		}
		if route.ReturnIP.IsValid() {
			converted.ReturnIP = route.ReturnIP.String()
		}
		list = append(list, converted)
	}
	return api.PeerList{Routes: list}, nil
}

func (s *serverInspector) Clients() ([]api.RegisteredClient, error) {
	registrations, err := s.dataplane.Registrations()
	if err != nil {
		return nil, err
	}
	paths, err := s.dataplane.RegisteredPaths()
	if err != nil {
		return nil, err
	}
	routes, err := s.dataplane.ServerRoutes()
	if err != nil {
		return nil, err
	}
	clients := make([]api.RegisteredClient, 0, len(registrations))
	index := make(map[dataplane.ClientKey]int, len(registrations))
	for _, registration := range registrations {
		client := api.RegisteredClient{
			AdvertisedIP: registration.Client.AdvertisedIP.String(),
			Nonce:        formatNonce(registration.Client.InstanceNonce),
			ListenPort:   registration.ListenPort,
			LeaseSeconds: registration.ExpiresIn.Seconds(),
			Paths:        []api.RegisteredPath{},
		}
		if registration.ReturnIP.IsValid() {
			client.ReturnIP = registration.ReturnIP.String()
		}
		index[registration.Client] = len(clients)
		clients = append(clients, client)
	}
	for _, path := range paths {
		position, exists := index[path.Client]
		if !exists {
			continue
		}
		clients[position].Paths = append(clients[position].Paths, api.RegisteredPath{
			ID:           path.PathID,
			Source:       path.Source.String(),
			Local:        path.Local.String(),
			Transport:    path.Transport.String(),
			LeaseSeconds: path.ExpiresIn.Seconds(),
		})
	}
	for _, route := range routes {
		if position, exists := index[route.Client]; exists {
			clients[position].Peers++
		}
	}
	return clients, nil
}

func formatNonce(nonce uint64) string {
	return fmt.Sprintf("%016x", nonce)
}
