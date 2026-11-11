package vinbero

import (
	"errors"
	"fmt"
	"time"

	"github.com/takehaya/vinbero/pkg/netlinksub"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// linkSweepInterval is how often the link watcher re-checks its state against
// the interfaces that exist. Tests shorten it.
var linkSweepInterval = time.Minute

// WatchDevices subscribes to link deletions and forgets an attachment as
// soon as its interface is deleted, removing it from the state file, so a
// pod veth deleted without a detach does not linger. The headend_l2 entries
// of a deleted interface go with it: they are keyed by an ifindex nothing
// can name any more, so no RPC could remove them, and their saved circuits
// with them. A rename or a new hardware address of an interface with saved
// circuits is recorded, so the next start still restores them. It watches the network
// namespace of the calling thread. A subscription that ends (e.g. a
// receive buffer overflow) is opened again after a wait that grows with each
// failed attempt (netlinksub), and every (re)subscription starts with a
// sweep over the current interfaces, so a deletion missed in between is
// still caught; the same sweep runs periodically and retries a removal that
// failed. Close stops it.
func (v *Vinbero) WatchDevices() error {
	ns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("watch devices: %w", err)
	}
	// Only the route family: a handle opened with no family list opens a
	// socket of every family the library knows, and opening an XFRM socket
	// makes the kernel load xfrm_user.
	h, err := netlink.NewHandleAt(ns, unix.NETLINK_ROUTE)
	if err != nil {
		_ = ns.Close()
		return fmt.Errorf("watch devices: %w", err)
	}
	st := netlinksub.New(v.logger, "device watch: links")
	done := make(chan struct{})
	stopped := make(chan struct{})
	v.devMu.Lock()
	v.stopWatch = func() { close(done); <-stopped }
	v.devMu.Unlock()
	go func() {
		defer close(stopped)
		defer func() { h.Close(); _ = ns.Close() }()
		updates, sub, err := subscribeLinks(ns, st)
		for {
			var d time.Duration
			if err == nil {
				if !v.watchOnce(h, updates, sub, done) {
					return
				}
				d = st.Ended()
			} else {
				d = st.Failed(err)
			}
			if !netlinksub.Wait(done, d) {
				return
			}
			if updates, sub, err = subscribeLinks(ns, st); err == nil {
				st.Restored()
			}
		}
	}()
	return nil
}

// subscribeLinks subscribes to link events in ns. Closing sub ends the
// subscription.
func subscribeLinks(ns netns.NsHandle, st *netlinksub.State) (<-chan netlink.LinkUpdate, chan struct{}, error) {
	updates := make(chan netlink.LinkUpdate, 256)
	sub := make(chan struct{})
	err := netlink.LinkSubscribeWithOptions(updates, sub, netlink.LinkSubscribeOptions{
		Namespace:         &ns,
		ReceiveBufferSize: 1 << 20,
		ErrorCallback:     st.OnError,
	})
	if err != nil {
		close(sub)
		return nil, nil, fmt.Errorf("subscribe to link events: %w", err)
	}
	return updates, sub, nil
}

// watchOnce runs one subscription until it ends (true) or done is closed
// (false), and closes it.
func (v *Vinbero) watchOnce(h *netlink.Handle, updates <-chan netlink.LinkUpdate, sub chan struct{}, done <-chan struct{}) bool {
	defer func() {
		close(sub)
		// The subscription's reader may block on a full channel; drained,
		// it sees the closed socket and ends.
		go func() {
			for range updates {
			}
		}()
	}()
	v.sweepLinks(h)
	sweep := time.NewTicker(linkSweepInterval)
	defer sweep.Stop()
	for {
		select {
		case <-done:
			return false
		case <-sweep.C:
			v.sweepLinks(h)
		case u, ok := <-updates:
			if !ok {
				return true // the subscription ended; subscribe again
			}
			if u.Family == unix.AF_BRIDGE {
				// A port leaving a bridge also sends RTM_DELLINK (family
				// AF_BRIDGE) while the interface lives on.
				continue
			}
			if u.Header.Type == unix.RTM_NEWLINK {
				// A rename or a new hardware address of an interface
				// with L2 headend circuits.
				if v.l2 != nil {
					a := u.Attrs()
					v.l2.follow(LinkID{Name: a.Name, Ifindex: uint32(a.Index), MAC: a.HardwareAddr})
				}
				continue
			}
			// The deletion is confirmed with a lookup before the
			// attachment goes.
			if u.Header.Type != unix.RTM_DELLINK {
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
			// The name is confirmed gone, but a new interface can already
			// hold the ifindex; check it before touching its entries.
			if _, err := h.LinkByIndex(ifindex); errors.As(err, &netlink.LinkNotFoundError{}) {
				v.deleteHeadendL2(func(i uint32) bool { return i == uint32(ifindex) })
			}
		}
	}
}

// sweepLinks compares the attachments and headend_l2 entries with the
// interfaces that exist, which catches a deletion the subscription missed and
// retries a removal that failed.
func (v *Vinbero) sweepLinks(h *netlink.Handle) {
	present, err := linkIndexes(h.LinkList())
	if err != nil {
		v.logger.Warn("device watch: sweep", zap.Error(err))
		return
	}
	v.pruneDevices(present)
	v.pruneHeadendL2(h, present)
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

// pruneHeadendL2 removes the headend_l2 entries of interfaces that are not
// in present (name to ifindex), which covers a deletion the subscription
// missed and, with pinned maps, one that happened while the daemon was down.
// present may predate an interface created since, so an ifindex missing from
// it is confirmed gone before its entries are removed.
func (v *Vinbero) pruneHeadendL2(h *netlink.Handle, present map[string]int) {
	live := make(map[uint32]struct{}, len(present))
	for _, ifindex := range present {
		live[uint32(ifindex)] = struct{}{}
	}
	v.deleteHeadendL2(func(i uint32) bool {
		if _, ok := live[i]; ok || i == 0 {
			return false
		}
		_, err := h.LinkByIndex(int(i))
		return errors.As(err, &netlink.LinkNotFoundError{})
	})
}

func (v *Vinbero) deleteHeadendL2(match func(ifindex uint32) bool) {
	var n int
	var err error
	switch {
	case v.l2 != nil:
		// The saved circuits of the interface go with its entries.
		n, err = v.l2.deleteWhere(match)
	case v.mapOps != nil:
		n, err = v.mapOps.DeleteHeadendL2Where(match)
	default:
		return
	}
	if err != nil {
		v.logger.Warn("device watch: remove headend_l2 entries of a deleted interface", zap.Error(err))
	}
	if n > 0 {
		v.logger.Info("Removed headend_l2 entries of a deleted interface", zap.Int("count", n))
	}
}

// pruneDevices forgets every attachment whose interface is not in present
// (name to ifindex) any more. present is older than the lock, so an attachment
// missing from it is confirmed gone under the lock first: it may have been
// made after the dump.
func (v *Vinbero) pruneDevices(present map[string]int) {
	v.devMu.Lock()
	defer v.devMu.Unlock()
	var gone []*deviceAttachment
	for _, a := range v.attached {
		if idx, ok := present[a.Name]; (!ok || idx != a.Ifindex) && !v.alive(a) {
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
