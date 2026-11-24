package dataplane

import (
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"

	"github.com/xshecan/mup/config"
)

type configurationMap interface {
	Update(key, value interface{}, flags ebpf.MapUpdateFlags) error
}

type configurationMaps struct {
	client         configurationMap
	server         configurationMap
	ports          configurationMap
	ingress        configurationMap
	groups         configurationMap
	paths          configurationMap
	returns        configurationMap
	ingressReflect configurationMap
	state          configurationMap
	downs          configurationMap
	// pathSrc and downSrc hold the source range of each path slot and each
	// egress path slot.
	pathSrc configurationMap
	downSrc configurationMap
}

func applyClientSettings(maps configurationMaps, settings ClientSettings) error {
	client, groups, paths, state, err := encodeClientSettings(settings)
	if err != nil {
		return err
	}
	var pathSrc [config.MaxPaths]mupPathSrcV1
	for index, path := range settings.Paths {
		if pathSrc[index], err = encodePathSrc(fmt.Sprintf("path %d", index), path.SrcFirst, path.SrcLast); err != nil {
			return err
		}
	}
	var downSrc [MaxEgressPaths]mupPathSrcV1
	for slot, egress := range settings.EgressPaths {
		if egress == nil {
			continue
		}
		if downSrc[slot], err = encodePathSrc(fmt.Sprintf("egress path %d", slot), egress.SrcFirst, egress.SrcLast); err != nil {
			return err
		}
	}
	key := uint32(0)
	disabled := state
	disabled.HealthyMask = 0
	if err := maps.state.Update(key, disabled, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("disable client paths: %w", err)
	}
	for index, path := range paths {
		var pathReturn mupPathReturnV1
		if index < len(settings.Paths) {
			if pathReturn, err = encodePathReturn(index, settings.Paths[index]); err != nil {
				return err
			}
		}
		if err := maps.returns.Update(uint32(index), pathReturn, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update return IP of client path %d: %w", index, err)
		}
		// Every slot gets its range, so an unused slot drops the range of an
		// old path.
		if maps.pathSrc != nil {
			if err := maps.pathSrc.Update(uint32(index), pathSrc[index], ebpf.UpdateAny); err != nil {
				return fmt.Errorf("update source range of client path %d: %w", index, err)
			}
		}
		if err := maps.paths.Update(uint32(index), path, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update client path %d: %w", index, err)
		}
		// The control plane owns the reflect members of an ingress reflect slot, and
		// writes the healthy members as the registrations come up. A full apply
		// clears them, so a reused slot does not keep the members of an old path.
		if maps.ingressReflect != nil {
			if err := maps.ingressReflect.Update(uint32(index), mupUpReflectV1{}, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("clear ingress reflect members of client path %d: %w", index, err)
			}
		}
	}
	if maps.downs != nil {
		for slot := range MaxEgressPaths {
			var egress mupClientDownPathV1
			if slot < len(settings.EgressPaths) && settings.EgressPaths[slot] != nil {
				if egress, err = encodeClientEgressPath(slot, *settings.EgressPaths[slot]); err != nil {
					return err
				}
			}
			if maps.downSrc != nil {
				if err := maps.downSrc.Update(uint32(slot), downSrc[slot], ebpf.UpdateAny); err != nil {
					return fmt.Errorf("update source range of client egress path %d: %w", slot, err)
				}
			}
			if err := maps.downs.Update(uint32(slot), egress, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("update client egress path %d: %w", slot, err)
			}
		}
	}
	for listenPort, group := range groups {
		if err := maps.groups.Update(listenPort, group, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update path group of listen port %d: %w", listenPort, err)
		}
	}
	if err := maps.client.Update(key, client, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update client configuration: %w", err)
	}
	if err := maps.state.Update(key, state, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("publish client path state: %w", err)
	}
	return nil
}

func applyServerSettings(maps configurationMaps, settings ServerSettings) error {
	server, ports, err := encodeServerSettings(settings)
	if err != nil {
		return err
	}
	ingress, err := encodeTargetIngress(settings)
	if err != nil {
		return err
	}
	if err := maps.ports.Update(uint32(0), ports, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update server ports: %w", err)
	}
	if err := maps.server.Update(uint32(0), server, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update server configuration: %w", err)
	}
	if maps.ingress != nil {
		if err := maps.ingress.Update(uint32(0), ingress, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update target ingress: %w", err)
		}
	}
	return nil
}

func applyPathState(stateMap configurationMap, healthyMask uint8, generation uint32) error {
	state := mupPathStateV1{
		Generation:  generation,
		HealthyMask: uint32(healthyMask),
	}
	if err := stateMap.Update(uint32(0), state, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update client path state: %w", err)
	}
	return nil
}

func applyGroup(groups configurationMap, group GroupSettings) error {
	encoded, err := encodeGroupSettings(group)
	if err != nil {
		return err
	}
	if err := groups.Update(group.ListenPort, encoded, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update path group of listen port %d: %w", group.ListenPort, err)
	}
	return nil
}

// applyPath writes one client path slot with its return IP, its source range,
// and empty reflect members. A path without a source range resets the range of
// an old path of the slot.
func applyPath(paths, returns, ingressReflect, pathSrc configurationMap, slot int, path PathSettings) error {
	encoded, err := encodePathSettings(slot, path)
	if err != nil {
		return err
	}
	pathReturn, err := encodePathReturn(slot, path)
	if err != nil {
		return err
	}
	src, err := encodePathSrc(fmt.Sprintf("path %d", slot), path.SrcFirst, path.SrcLast)
	if err != nil {
		return err
	}
	if err := returns.Update(uint32(slot), pathReturn, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update return IP of client path %d: %w", slot, err)
	}
	if pathSrc != nil {
		if err := pathSrc.Update(uint32(slot), src, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update source range of client path %d: %w", slot, err)
		}
	}
	// A new path has no healthy reflect members yet. The control plane fills
	// them for an ingress reflect path, so clear any members of an old path.
	if ingressReflect != nil {
		if err := ingressReflect.Update(uint32(slot), mupUpReflectV1{}, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("clear ingress reflect members of client path %d: %w", slot, err)
		}
	}
	if err := paths.Update(uint32(slot), encoded, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update client path %d: %w", slot, err)
	}
	return nil
}

// applyIngressReflectMembers writes the reflect members of an ingress reflect path slot.
// An empty list clears the slot, so the egress leaves it a direct path.
func applyIngressReflectMembers(ingressReflect configurationMap, slot int, members []netip.Addr, perPacket bool) error {
	if slot < 0 || slot >= config.MaxPaths {
		return fmt.Errorf("path slot %d is outside 0 to %d", slot, config.MaxPaths-1)
	}
	encoded, err := encodeIngressReflect(members, perPacket)
	if err != nil {
		return err
	}
	if err := ingressReflect.Update(uint32(slot), encoded, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update ingress reflect members of client path %d: %w", slot, err)
	}
	return nil
}

// applyEgressPath writes one client egress path slot and its source range. A
// nil path clears both.
func applyEgressPath(downs, downSrc configurationMap, slot int, path *EgressPathSettings) error {
	var encoded mupClientDownPathV1
	var src mupPathSrcV1
	if slot < 0 || slot >= MaxEgressPaths {
		return fmt.Errorf("egress path slot %d is outside 0 to %d", slot, MaxEgressPaths-1)
	}
	if path != nil {
		var err error
		if encoded, err = encodeClientEgressPath(slot, *path); err != nil {
			return err
		}
		if src, err = encodePathSrc(fmt.Sprintf("egress path %d", slot), path.SrcFirst, path.SrcLast); err != nil {
			return err
		}
	}
	// A cleared slot loses its path before its range, and a new path gets its
	// range first, so the program never checks a path against a stale range.
	if path == nil {
		if err := downs.Update(uint32(slot), encoded, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update client egress path %d: %w", slot, err)
		}
	}
	if downSrc != nil {
		if err := downSrc.Update(uint32(slot), src, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update source range of client egress path %d: %w", slot, err)
		}
	}
	if path != nil {
		if err := downs.Update(uint32(slot), encoded, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update client egress path %d: %w", slot, err)
		}
	}
	return nil
}

// clearPath writes an empty entry. The client program skips a slot without a
// destination address.
func clearPath(paths, returns, ingressReflect, pathSrc configurationMap, slot int) error {
	if slot < 0 || slot >= config.MaxPaths {
		return fmt.Errorf("path slot %d is outside 0 to %d", slot, config.MaxPaths-1)
	}
	if err := paths.Update(uint32(slot), mupPathConfigV1{}, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("clear client path %d: %w", slot, err)
	}
	if pathSrc != nil {
		if err := pathSrc.Update(uint32(slot), mupPathSrcV1{}, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("clear source range of client path %d: %w", slot, err)
		}
	}
	if err := returns.Update(uint32(slot), mupPathReturnV1{}, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("clear return IP of client path %d: %w", slot, err)
	}
	if ingressReflect != nil {
		if err := ingressReflect.Update(uint32(slot), mupUpReflectV1{}, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("clear ingress reflect members of client path %d: %w", slot, err)
		}
	}
	return nil
}
