package control

import "github.com/xshecan/mup/config"

// SelectPaths mirrors the path choice of the client program for one group.
// healthyMask holds only the healthy paths of the group.
func SelectPaths(mode config.Mode, peerToken uint32, priorities []uint8, healthyMask uint8) []int {
	if len(priorities) == 0 || healthyMask == 0 {
		return nil
	}
	switch mode {
	case config.ModeFallback:
		selected := -1
		var selectedPriority uint8
		for path, priority := range priorities {
			if path >= 8 || healthyMask&(1<<path) == 0 {
				continue
			}
			if selected == -1 || priority < selectedPriority {
				selected = path
				selectedPriority = priority
			}
		}
		if selected == -1 {
			return nil
		}
		return []int{selected}
	case config.ModeBalancer:
		healthy := make([]int, 0, len(priorities))
		for path := range priorities {
			if path < 8 && healthyMask&(1<<path) != 0 {
				healthy = append(healthy, path)
			}
		}
		if len(healthy) == 0 {
			return nil
		}
		hash := peerToken*0x9e3779b1 ^ uint32(healthyMask)*0x85ebca6b
		hash ^= hash >> 16
		return []int{healthy[int(hash%uint32(len(healthy)))]}
	case config.ModeBurst:
		selected := make([]int, 0, len(priorities))
		for path := range priorities {
			if path < 8 && healthyMask&(1<<path) != 0 {
				selected = append(selected, path)
			}
		}
		return selected
	default:
		return nil
	}
}
