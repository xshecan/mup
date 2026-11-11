package app

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
)

const defaultPinRoot = "/sys/fs/bpf/mup"

type routeResolver interface {
	Resolve(destination netip.Addr, interfaceName string) (source netip.Addr, ifindex int, err error)
	UpInterfaceIndexes() ([]int, error)
}

type runtimePlan struct {
	pinRoot         string
	attachIfindexes []int
	client          *dataplane.ClientSettings
	server          *dataplane.ServerSettings
}

func buildPlan(appConfig config.App, nonce uint64, resolver routeResolver) (runtimePlan, error) {
	if (appConfig.Client == nil) == (appConfig.Server == nil) {
		return runtimePlan{}, errors.New("exactly one client or server configuration is required")
	}
	attachIfindexes, err := resolver.UpInterfaceIndexes()
	if err != nil {
		return runtimePlan{}, fmt.Errorf("enumerate interfaces: %w", err)
	}

	if appConfig.Client != nil {
		client := appConfig.Client
		settings := dataplane.ClientSettings{
			InstanceNonce: nonce,
			AdvertisedIP:  client.AdvertisedIP,
			Generation:    1,
			Groups:        make([]dataplane.GroupSettings, 0, len(client.Groups)),
			Paths:         make([]dataplane.PathSettings, 0, config.MaxPaths),
		}
		for _, group := range client.Groups {
			var pathMask uint8
			for _, path := range group.Paths {
				slot := len(settings.Paths)
				_, ifindex, err := resolver.Resolve(path.Server, path.Interface)
				if err != nil {
					return runtimePlan{}, fmt.Errorf("resolve client path %d: %w", slot, err)
				}
				if ifindex <= 0 {
					return runtimePlan{}, fmt.Errorf("resolve client path %d: invalid interface index %d", slot, ifindex)
				}
				attachIfindexes = append(attachIfindexes, ifindex)
				settings.Paths = append(settings.Paths, dataplane.PathSettings{
					DestinationIP: path.Server,
					SourceIP:      client.AdvertisedIP,
					Ifindex:       ifindex,
					ServerPort:    path.ServerPort,
					Transport:     path.Transport,
					Priority:      uint8(slot),
					ReturnIP:      path.ReturnIP,
				})
				pathMask |= 1 << slot
			}
			settings.Groups = append(settings.Groups, dataplane.GroupSettings{
				ListenPort: group.ListenPort,
				Mode:       group.Mode,
				PathMask:   pathMask,
			})
		}
		settings.HealthyMask = uint32(1)<<len(settings.Paths) - 1
		return runtimePlan{
			pinRoot:         defaultPinRoot + "/client",
			attachIfindexes: uniqueSortedPositive(attachIfindexes),
			client:          &settings,
		}, nil
	}

	server := appConfig.Server
	sourceIP, ifindex, err := resolver.Resolve(server.Target.Addr(), "")
	if err != nil {
		return runtimePlan{}, fmt.Errorf("resolve server target route: %w", err)
	}
	if ifindex <= 0 {
		return runtimePlan{}, fmt.Errorf("resolve server target route: invalid interface index %d", ifindex)
	}
	attachIfindexes = append(attachIfindexes, ifindex)
	settings := dataplane.ServerSettings{
		Target:      server.Target,
		SourceIP:    sourceIP,
		Ifindex:     ifindex,
		ServerPorts: server.Port,
	}
	return runtimePlan{
		pinRoot:         defaultPinRoot + "/server",
		attachIfindexes: uniqueSortedPositive(attachIfindexes),
		server:          &settings,
	}, nil
}

func uniqueSortedPositive(values []int) []int {
	set := make(map[int]struct{}, len(values))
	for _, value := range values {
		if value > 0 {
			set[value] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(set))
}
