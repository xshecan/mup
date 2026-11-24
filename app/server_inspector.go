package app

import (
	"fmt"
	"net/netip"
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
	Reflectors() ([]dataplane.Reflector, error)
}

// serverInspector answers the read-only API calls of a server.
type serverInspector struct {
	server        config.Server
	dataplane     serverDataplane
	startedAt     time.Time
	interfaceName func(int) string
	// egresses holds the egress paths of the clients with separate egress paths.
	egresses *egressService
}

func newServerInspector(server config.Server, plane serverDataplane, startedAt time.Time, egresses *egressService) *serverInspector {
	return &serverInspector{server: server, dataplane: plane, startedAt: startedAt, interfaceName: interfaceName, egresses: egresses}
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
			Port:             s.server.Port.First,
			PortLast:         s.server.Port.Last,
			Target:           s.server.Target.String(),
			TargetIngress:    s.server.TargetIngress,
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
	paths, err := s.dataplane.RegisteredPaths()
	if err != nil {
		return api.PeerList{}, err
	}
	prefixes := poolPrefixes(paths)
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
		converted.ReturnIP = returnText(route.Client, route.ReturnIP, route.ReturnPool, prefixes)
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
	prefixes := poolPrefixes(paths)
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
		client.ReturnIP = returnText(registration.Client, registration.ReturnIP, registration.ReturnPool, prefixes)
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
			ListenPort:   path.ListenPort,
			Source:       path.Source.String(),
			Local:        path.Local.String(),
			Transport:    path.Transport.String(),
			ReturnIP:     returnText(path.Client, path.ReturnIP, path.ReturnPrefix != 0, prefixes),
			LeaseSeconds: path.ExpiresIn.Seconds(),
		})
	}
	if s.egresses != nil {
		for client, groups := range s.egresses.registry.clients(time.Now()) {
			if position, exists := index[client]; exists && len(groups) > 0 {
				clients[position].Egresses = groups
				clients[position].Egress = &groups[0]
			}
		}
	}
	for _, route := range routes {
		if position, exists := index[route.Client]; exists {
			clients[position].Peers++
		}
	}
	return clients, nil
}

func (s *serverInspector) Reflectors() (api.ReflectorList, error) {
	reflectors, err := s.dataplane.Reflectors()
	if err != nil {
		return api.ReflectorList{}, err
	}
	list := make([]api.Reflector, 0, len(reflectors))
	for _, reflector := range reflectors {
		list = append(list, api.Reflector{
			Pool:      fmt.Sprintf("%s/%d", reflector.Base, reflector.Prefix),
			Address:   reflector.Address.String(),
			Transport: reflector.Transport.String(),
			Healthy:   reflector.Healthy,
		})
	}
	return api.ReflectorList{Reflectors: list}, nil
}

type poolPrefixKey struct {
	client dataplane.ClientKey
	base   netip.Addr
}

// poolPrefixes maps each client and pool base to its prefix length. Only a
// registered path keeps the prefix, so a route or a registration finds it here.
func poolPrefixes(paths []dataplane.RegisteredPath) map[poolPrefixKey]uint8 {
	prefixes := make(map[poolPrefixKey]uint8)
	for _, path := range paths {
		if path.ReturnPrefix != 0 {
			prefixes[poolPrefixKey{client: path.Client, base: path.ReturnIP}] = path.ReturnPrefix
		}
	}
	return prefixes
}

// returnText formats a return IP, or a return pool as a CIDR. A pool without a
// known prefix shows its base and the word pool.
func returnText(client dataplane.ClientKey, address netip.Addr, pool bool, prefixes map[poolPrefixKey]uint8) string {
	if !address.IsValid() {
		return ""
	}
	if !pool {
		return address.String()
	}
	if prefix, ok := prefixes[poolPrefixKey{client: client, base: address}]; ok {
		return netip.PrefixFrom(address, int(prefix)).String()
	}
	return address.String() + " pool"
}

func formatNonce(nonce uint64) string {
	return fmt.Sprintf("%016x", nonce)
}
