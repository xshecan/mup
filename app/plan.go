package app

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
)

const defaultPinRoot = "/sys/fs/bpf/mup"

type routeResolver interface {
	Resolve(destination netip.Addr, interfaceName string) (source netip.Addr, ifindex int, err error)
	UpInterfaceIndexes() ([]int, error)
	LoopbackIndex() (int, error)
	HardwareAddr(ifindex int) (net.HardwareAddr, error)
}

type runtimePlan struct {
	pinRoot         string
	attachIfindexes []int
	client          *dataplane.ClientSettings
	server          *dataplane.ServerSettings
}

func buildPlan(appConfig config.App, nonce uint64, resolver routeResolver) (runtimePlan, error) {
	roles := 0
	for _, set := range []bool{appConfig.Client != nil, appConfig.Server != nil, appConfig.Bridge != nil} {
		if set {
			roles++
		}
	}
	if roles != 1 {
		return runtimePlan{}, errors.New("exactly one client, server, or bridge configuration is required")
	}
	attachIfindexes, err := resolver.UpInterfaceIndexes()
	if err != nil {
		return runtimePlan{}, fmt.Errorf("enumerate interfaces: %w", err)
	}
	// A bridge takes packets on every interface, and the start writes its
	// settings with the addresses of that moment.
	if appConfig.Bridge != nil {
		return runtimePlan{
			pinRoot:         defaultPinRoot + "/bridge",
			attachIfindexes: uniqueSortedPositive(attachIfindexes),
		}, nil
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
		var upReflectMask uint32
		for _, group := range client.Groups {
			var pathMask uint8
			for _, path := range group.Paths {
				slot := len(settings.Paths)
				// An up reflect path sends to the via host, so the interface
				// comes from the route to the via, not to the server. The path
				// starts unhealthy, because the control plane finds the healthy
				// members before it carries the upstream.
				destination := path.Server
				if path.UpReflect(group.Split()) {
					destination = path.ReturnIP
					upReflectMask |= 1 << slot
				}
				_, ifindex, err := resolver.Resolve(destination, path.Interface)
				if err != nil {
					return runtimePlan{}, fmt.Errorf("resolve client path %d: %w", slot, err)
				}
				if ifindex <= 0 {
					return runtimePlan{}, fmt.Errorf("resolve client path %d: invalid interface index %d", slot, ifindex)
				}
				attachIfindexes = append(attachIfindexes, ifindex)
				settings.Paths = append(settings.Paths, clientPathSettings(path, client.AdvertisedIP, ifindex, uint8(slot)))
				pathMask |= 1 << slot
			}
			var downMask uint8
			for _, down := range group.DownPaths {
				downSettings := dataplane.DownPathFromConfig(down)
				downMask |= 1 << len(settings.DownPaths)
				settings.DownPaths = append(settings.DownPaths, &downSettings)
			}
			settings.Groups = append(settings.Groups, dataplane.GroupSettings{
				ListenPort: group.ListenPort,
				Mode:       group.Mode,
				PathMask:   pathMask,
				DownMode:   group.DownMode,
				DownMask:   downMask,
			})
		}
		settings.HealthyMask = (uint32(1)<<len(settings.Paths) - 1) &^ upReflectMask
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
	var ingressMAC net.HardwareAddr
	ingressIfindex := 0
	if server.TargetIngress {
		// The target must be an address of this host, so that the packets
		// injected into the ingress hook of its interface reach it.
		if sourceIP != server.Target.Addr() {
			return runtimePlan{}, fmt.Errorf("server target_ingress needs a target address on this host, but %s routes from %s", server.Target.Addr(), sourceIP)
		}
		ingressMAC, err = resolver.HardwareAddr(ifindex)
		if err != nil {
			return runtimePlan{}, fmt.Errorf("resolve target ingress interface: %w", err)
		}
		if len(ingressMAC) != 6 {
			return runtimePlan{}, fmt.Errorf("server target_ingress needs an Ethernet interface, and interface %d has no Ethernet address", ifindex)
		}
		ingressIfindex = ifindex
	} else if sourceIP == server.Target.Addr() {
		ifindex, err = resolver.LoopbackIndex()
		if err != nil {
			return runtimePlan{}, fmt.Errorf("resolve local server target: %w", err)
		}
		if ifindex <= 0 {
			return runtimePlan{}, fmt.Errorf("resolve local server target: invalid loopback index %d", ifindex)
		}
	}
	attachIfindexes = append(attachIfindexes, ifindex)
	settings := dataplane.ServerSettings{
		Target:         server.Target,
		SourceIP:       sourceIP,
		Ifindex:        ifindex,
		ServerPorts:    server.Port,
		IngressIfindex: ingressIfindex,
		IngressMAC:     ingressMAC,
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

// clientPathSettings is the dataplane form of a client path.
func clientPathSettings(path config.Path, advertisedIP netip.Addr, ifindex int, priority uint8) dataplane.PathSettings {
	return dataplane.PathSettings{
		DestinationIP: path.Server,
		SourceIP:      advertisedIP,
		Ifindex:       ifindex,
		ServerPort:    path.ServerPort,
		Transport:     path.Transport,
		Priority:      priority,
		ReturnIP:      path.ReturnIP,
		ReturnPrefix:  path.ReturnPrefix,
		Balance:       path.Balance,
	}
}
