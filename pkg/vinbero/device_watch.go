package vinbero

import (
	"errors"
	"fmt"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// WatchDevices subscribes to link deletions and forgets an attachment as
// soon as its interface is deleted, removing it from the state file, so a
// pod veth deleted without a detach does not linger. It watches the network
// namespace of the calling thread. A subscription that fails (e.g. a
// receive buffer overflow) is opened again, and every (re)subscription
// starts with a sweep over the current interfaces, so a deletion missed in
// between is still caught. Close stops it.
func (v *Vinbero) WatchDevices() error {
	ns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("watch devices: %w", err)
	}
	h, err := netlink.NewHandleAt(ns)
	if err != nil {
		_ = ns.Close()
		return fmt.Errorf("watch devices: %w", err)
	}
	done := make(chan struct{})
	stopped := make(chan struct{})
	v.devMu.Lock()
	v.stopWatch = func() { close(done); <-stopped }
	v.devMu.Unlock()
	go func() {
		defer close(stopped)
		defer func() { h.Close(); _ = ns.Close() }()
		for {
			v.watchOnce(ns, h, done)
			select {
			case <-done:
				return
			case <-time.After(time.Second):
			}
		}
	}()
	return nil
}

// watchOnce runs one subscription until it fails or done is closed.
func (v *Vinbero) watchOnce(ns netns.NsHandle, h *netlink.Handle, done <-chan struct{}) {
	updates := make(chan netlink.LinkUpdate, 256)
	sub := make(chan struct{})
	defer close(sub)
	err := netlink.LinkSubscribeWithOptions(updates, sub, netlink.LinkSubscribeOptions{
		Namespace:         &ns,
		ReceiveBufferSize: 1 << 20,
		ErrorCallback: func(err error) {
			v.logger.Warn("device watch: link subscription error", zap.Error(err))
		},
	})
	if err != nil {
		v.logger.Warn("device watch: subscribe to link events", zap.Error(err))
		return
	}
	present, err := linkIndexes(h.LinkList())
	if err != nil {
		v.logger.Warn("device watch: sweep", zap.Error(err))
	} else {
		v.pruneDevices(present)
	}
	for {
		select {
		case <-done:
			return
		case u, ok := <-updates:
			if !ok {
				return // the subscription failed; resubscribe
			}
			// A port leaving a bridge also sends RTM_DELLINK (family
			// AF_BRIDGE) while the interface lives on, so the deletion is
			// confirmed with a lookup before the attachment goes.
			if u.Header.Type != unix.RTM_DELLINK || u.Family == unix.AF_BRIDGE {
				continue
			}
			name, ifindex := u.Attrs().Name, u.Attrs().Index
			if l, err := h.LinkByName(name); err == nil && l.Attrs().Index == ifindex {
				continue
			} else if err != nil && !errors.As(err, &netlink.LinkNotFoundError{}) {
				v.logger.Warn("device watch: confirm deletion", zap.String("device", name), zap.Error(err))
				continue
			}
			v.linkDeleted(name, ifindex)
		}
	}
}

// linkDeleted forgets the attachment on a deleted interface. An attachment
// with the same name but another ifindex belongs to a newer interface and
// stays.
func (v *Vinbero) linkDeleted(name string, ifindex int) {
	v.devMu.Lock()
	defer v.devMu.Unlock()
	if a, ok := v.attached[name]; ok && a.Ifindex == ifindex {
		v.forgetLocked([]*deviceAttachment{a}, "interface was deleted")
	}
}

// pruneDevices forgets every attachment whose interface is not in present
// (name to ifindex) any more.
func (v *Vinbero) pruneDevices(present map[string]int) {
	v.devMu.Lock()
	defer v.devMu.Unlock()
	var gone []*deviceAttachment
	for _, a := range v.attached {
		if idx, ok := present[a.Name]; !ok || idx != a.Ifindex {
			gone = append(gone, a)
		}
	}
	v.forgetLocked(gone, "interface is gone")
}

// forgetLocked drops stale attachments and removes the runtime ones from
// the state file. Caller holds v.devMu.
func (v *Vinbero) forgetLocked(as []*deviceAttachment, why string) {
	var names []string
	for _, a := range as {
		if !a.Config {
			names = append(names, a.Name)
		}
		v.dropLocked(a, why)
	}
	if len(names) > 0 && v.resMgr != nil {
		if err := v.resMgr.RemoveDevices(names...); err != nil {
			v.logger.Warn("persist state after dropping vanished devices", zap.Error(err))
		}
	}
}
