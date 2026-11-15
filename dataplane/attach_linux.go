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
	egress  bool
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
		if attached.ifindex == ifindex && !attached.egress {
			return true
		}
	}
	return false
}

// AttachServerEgress attaches the server egress program to the egress hook of
// one interface and removes it from every other interface. An ifindex of zero
// removes it everywhere. The program catches the replies of a target with
// ingress delivery. It goes after the programs that are on the hook, because
// a program before it, such as a WireGuard router, can rewrite those replies.
func (r *Runtime) AttachServerEgress(ifindex int) error {
	if ifindex < 0 {
		return fmt.Errorf("invalid interface index %d", ifindex)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("MUP dataplane is closed")
	}
	keep := ""
	if ifindex > 0 && r.pinRoot != "" {
		keep = filepath.Join(r.pinRoot, "server", strconv.Itoa(ifindex), "egress")
	}
	if r.pinRoot != "" {
		pins, err := filepath.Glob(filepath.Join(r.pinRoot, "server", "*", "egress"))
		if err != nil {
			return fmt.Errorf("list pinned server TCX egress links: %w", err)
		}
		for _, pin := range pins {
			if pin == keep {
				continue
			}
			if err := detachPinnedLink(pin); err != nil {
				return err
			}
		}
	}
	links := r.links[:0]
	for _, attached := range r.links {
		if attached.egress && attached.ifindex != ifindex {
			_ = attached.link.Unpin()
			_ = attached.link.Close()
			continue
		}
		links = append(links, attached)
	}
	r.links = links
	if ifindex == 0 {
		return nil
	}
	for _, attached := range r.links {
		if attached.egress && attached.ifindex == ifindex {
			return nil
		}
	}
	program := r.objects.MupServerEgress
	if keep != "" {
		if _, err := os.Stat(keep); err == nil {
			attached, err := link.LoadPinnedLink(keep, nil)
			if err != nil {
				return fmt.Errorf("load pinned server TCX egress link for ifindex %d: %w", ifindex, err)
			}
			if err := attached.Update(program); err != nil {
				_ = attached.Close()
				return fmt.Errorf("update pinned server TCX egress link for ifindex %d: %w", ifindex, err)
			}
			r.links = append(r.links, attachedLink{ifindex: ifindex, egress: true, link: attached})
			return nil
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect pinned server TCX egress link for ifindex %d: %w", ifindex, err)
		}
	}
	attached, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   program,
		Attach:    ebpf.AttachTCXEgress,
		Anchor:    link.Tail(),
	})
	if err != nil {
		return fmt.Errorf("attach server TCX egress to ifindex %d: %w", ifindex, err)
	}
	if keep != "" {
		if err := os.MkdirAll(filepath.Dir(keep), 0o755); err != nil {
			_ = attached.Close()
			return fmt.Errorf("create server TCX link pin directory: %w", err)
		}
		if err := attached.Pin(keep); err != nil {
			_ = attached.Close()
			return fmt.Errorf("pin server TCX egress link for ifindex %d: %w", ifindex, err)
		}
	}
	r.links = append(r.links, attachedLink{ifindex: ifindex, egress: true, link: attached})
	return nil
}

// detachPinnedLink removes a pinned link from its hook.
func detachPinnedLink(pin string) error {
	attached, err := link.LoadPinnedLink(pin, nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("load pinned link %s: %w", pin, err)
	}
	defer attached.Close()
	if err := attached.Unpin(); err != nil {
		return fmt.Errorf("unpin link %s: %w", pin, err)
	}
	return nil
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
