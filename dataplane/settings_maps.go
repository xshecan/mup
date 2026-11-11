package dataplane

import (
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/xshecan/mup/config"
)

type configurationMap interface {
	Update(key, value interface{}, flags ebpf.MapUpdateFlags) error
}

type configurationMaps struct {
	client configurationMap
	server configurationMap
	groups configurationMap
	paths  configurationMap
	state  configurationMap
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
		if err := maps.paths.Update(uint32(index), path, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update client path %d: %w", index, err)
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
	server, err := encodeServerSettings(settings)
	if err != nil {
		return err
	}
	if err := maps.server.Update(uint32(0), server, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update server configuration: %w", err)
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

func applyPath(paths configurationMap, slot int, path PathSettings) error {
	encoded, err := encodePathSettings(slot, path)
	if err != nil {
		return err
	}
	if err := paths.Update(uint32(slot), encoded, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update client path %d: %w", slot, err)
	}
	return nil
}

// clearPath writes an empty entry. The client program skips a slot without a
// destination address.
func clearPath(paths configurationMap, slot int) error {
	if slot < 0 || slot >= config.MaxPaths {
		return fmt.Errorf("path slot %d is outside 0 to %d", slot, config.MaxPaths-1)
	}
	if err := paths.Update(uint32(slot), mupPathConfigV1{}, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("clear client path %d: %w", slot, err)
	}
	return nil
}
