//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func (r *Runtime) AttachClient(ifindexes []int) error {
	return r.attachIngress("client", r.objects.MupClientIngress, ifindexes)
}

func (r *Runtime) AttachServer(ifindexes []int) error {
	return r.attachIngress("server", r.objects.MupServerIngress, ifindexes)
}

type attachedLink struct {
	ifindex int
	link    link.Link
}

// attachIngress attaches the program to each interface that this runtime did
// not attach yet.
func (r *Runtime) attachIngress(role string, program *ebpf.Program, ifindexes []int) error {
	validated, err := validateIfindexes(ifindexes)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("MUP dataplane is closed")
	}
	start := len(r.links)
	for _, ifindex := range validated {
		if r.attachedLocked(ifindex) {
			continue
		}
		var pin string
		if r.pinRoot != "" {
			pin = filepath.Join(r.pinRoot, role, strconv.Itoa(ifindex), "ingress")
			if _, err := os.Stat(pin); err == nil {
				attached, err := link.LoadPinnedLink(pin, nil)
				if err != nil {
					r.rollbackLinks(start)
					return fmt.Errorf("load pinned %s TCX ingress link for ifindex %d: %w", role, ifindex, err)
				}
				if err := attached.Update(program); err != nil {
					_ = attached.Close()
					r.rollbackLinks(start)
					return fmt.Errorf("update pinned %s TCX ingress link for ifindex %d: %w", role, ifindex, err)
				}
				r.links = append(r.links, attachedLink{ifindex: ifindex, link: attached})
				continue
			} else if !os.IsNotExist(err) {
				r.rollbackLinks(start)
				return fmt.Errorf("inspect pinned %s TCX ingress link for ifindex %d: %w", role, ifindex, err)
			}
		}

		attached, err := link.AttachTCX(link.TCXOptions{
			Interface: ifindex,
			Program:   program,
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			r.rollbackLinks(start)
			return fmt.Errorf("attach %s TCX ingress to ifindex %d: %w", role, ifindex, err)
		}
		if pin != "" {
			if err := os.MkdirAll(filepath.Dir(pin), 0o755); err != nil {
				_ = attached.Close()
				r.rollbackLinks(start)
				return fmt.Errorf("create %s TCX link pin directory: %w", role, err)
			}
			if err := attached.Pin(pin); err != nil {
				_ = attached.Close()
				r.rollbackLinks(start)
				return fmt.Errorf("pin %s TCX ingress link for ifindex %d: %w", role, ifindex, err)
			}
		}
		r.links = append(r.links, attachedLink{ifindex: ifindex, link: attached})
	}
	return nil
}

func (r *Runtime) attachedLocked(ifindex int) bool {
	for _, attached := range r.links {
		if attached.ifindex == ifindex {
			return true
		}
	}
	return false
}

func (r *Runtime) rollbackLinks(start int) {
	for i := len(r.links) - 1; i >= start; i-- {
		_ = r.links[i].link.Close()
	}
	r.links = r.links[:start]
}

func validateIfindexes(ifindexes []int) ([]int, error) {
	if len(ifindexes) == 0 {
		return nil, errors.New("at least one network interface is required")
	}
	seen := make(map[int]struct{}, len(ifindexes))
	result := append([]int(nil), ifindexes...)
	for _, ifindex := range result {
		if ifindex <= 0 {
			return nil, fmt.Errorf("invalid interface index %d", ifindex)
		}
		if _, exists := seen[ifindex]; exists {
			return nil, fmt.Errorf("duplicate interface index %d", ifindex)
		}
		seen[ifindex] = struct{}{}
	}
	return result, nil
}
