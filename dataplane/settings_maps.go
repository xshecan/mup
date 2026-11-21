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
	client    configurationMap
	server    configurationMap
	ports     configurationMap
	ingress   configurationMap
	groups    configurationMap
	paths     configurationMap
	returns   configurationMap
	upReflect configurationMap
	state     configurationMap
	downs     configurationMap
}

func applyClientSettings(maps configurationMaps, settings ClientSettings) error {
	client, groups, paths, state, err := encodeClientSettings(settings)
	if err != nil {
		return err
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
		if err := maps.paths.Update(uint32(index), path, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update client path %d: %w", index, err)
		}
		// The control plane owns the reflect members of an up reflect slot, and
		// writes the healthy members as the registrations come up. A full apply
		// clears them, so a reused slot does not keep the members of an old path.
		if maps.upReflect != nil {
			if err := maps.upReflect.Update(uint32(index), mupUpReflectV1{}, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("clear up reflect members of client path %d: %w", index, err)
			}
		}
	}
	if maps.downs != nil {
		for slot := range MaxDownPaths {
			var down mupClientDownPathV1
			if slot < len(settings.DownPaths) && settings.DownPaths[slot] != nil {
				if down, err = encodeClientDownPath(slot, *settings.DownPaths[slot]); err != nil {
					return err
				}
			}
			if err := maps.downs.Update(uint32(slot), down, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("update client down path %d: %w", slot, err)
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

func applyPath(paths, returns, upReflect configurationMap, slot int, path PathSettings) error {
	encoded, err := encodePathSettings(slot, path)
	if err != nil {
		return err
	}
	pathReturn, err := encodePathReturn(slot, path)
	if err != nil {
		return err
	}
	if err := returns.Update(uint32(slot), pathReturn, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update return IP of client path %d: %w", slot, err)
	}
	// A new path has no healthy reflect members yet. The control plane fills
	// them for an up reflect path, so clear any members of an old path.
	if upReflect != nil {
		if err := upReflect.Update(uint32(slot), mupUpReflectV1{}, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("clear up reflect members of client path %d: %w", slot, err)
		}
	}
	if err := paths.Update(uint32(slot), encoded, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update client path %d: %w", slot, err)
	}
	return nil
}

// applyUpReflectMembers writes the reflect members of an up reflect path slot.
// An empty list clears the slot, so the egress leaves it a direct path.
func applyUpReflectMembers(upReflect configurationMap, slot int, members []netip.Addr, perPacket bool) error {
	if slot < 0 || slot >= config.MaxPaths {
		return fmt.Errorf("path slot %d is outside 0 to %d", slot, config.MaxPaths-1)
	}
	encoded, err := encodeUpReflect(members, perPacket)
	if err != nil {
		return err
	}
	if err := upReflect.Update(uint32(slot), encoded, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update up reflect members of client path %d: %w", slot, err)
	}
	return nil
}

// applyDownPath writes one client down path slot. A nil path clears it.
func applyDownPath(downs configurationMap, slot int, path *DownPathSettings) error {
	var encoded mupClientDownPathV1
	if slot < 0 || slot >= MaxDownPaths {
		return fmt.Errorf("down path slot %d is outside 0 to %d", slot, MaxDownPaths-1)
	}
	if path != nil {
		var err error
		if encoded, err = encodeClientDownPath(slot, *path); err != nil {
			return err
		}
	}
	if err := downs.Update(uint32(slot), encoded, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update client down path %d: %w", slot, err)
	}
	return nil
}

// clearPath writes an empty entry. The client program skips a slot without a
// destination address.
func clearPath(paths, returns, upReflect configurationMap, slot int) error {
	if slot < 0 || slot >= config.MaxPaths {
		return fmt.Errorf("path slot %d is outside 0 to %d", slot, config.MaxPaths-1)
	}
	if err := paths.Update(uint32(slot), mupPathConfigV1{}, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("clear client path %d: %w", slot, err)
	}
	if err := returns.Update(uint32(slot), mupPathReturnV1{}, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("clear return IP of client path %d: %w", slot, err)
	}
	if upReflect != nil {
		if err := upReflect.Update(uint32(slot), mupUpReflectV1{}, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("clear up reflect members of client path %d: %w", slot, err)
		}
	}
	return nil
}
