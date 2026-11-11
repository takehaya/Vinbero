package fibmode

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/takehaya/vinbero/pkg/netlinksub"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// Maps is where the decision goes: the data plane's fib_global_mode_map and
// fib_local_v4/v6_map.
type Maps interface {
	// SetFibGlobalMode sets which families run their vrf 0 lookups as
	// direct lookups.
	SetFibGlobalMode(v4, v6 bool) error
	// SyncFibLocal makes each family's local-address map hold exactly the
	// given addresses.
	SyncFibLocal(v4, v6 []netip.Addr) error
}

// Settle is how long the watcher waits after the last relevant change
// before it reads the namespace again and may return to the direct mode.
// The direct mode is off from the moment the change is seen until then.
var Settle = 200 * time.Millisecond

// Watcher keeps the data plane's lookup mode in step with the network
// namespace it runs in (see the package comment). It follows the
// namespace's rule, route and link events on one NETLINK_ROUTE socket. A
// relevant event turns the direct mode of the family off at once and
// schedules a fresh read of the whole state; only a complete read taken
// while the subscription is up turns it back on. While the subscription is
// down, or a read failed, both families use the full lookup.
type Watcher struct {
	maps   Maps
	logger *zap.Logger

	// read lists the namespace's state and subscribe opens the event
	// stream; tests replace them.
	read      func() (*Snapshot, error)
	subscribe func(st *netlinksub.State) (*subscription, error)

	st  *netlinksub.State
	sub *subscription // the open event stream, nil while there is none

	// What the maps hold (written: once at least), and what was logged
	// last.
	written    bool
	v4, v6     bool
	local4     []netip.Addr
	local6     []netip.Addr
	logged     Decision
	loggedOnce bool

	// From the last snapshot: the VRF devices' tables and ifindexes, whose
	// changes are relevant.
	vrfTables map[uint32]bool
	vrfLinks  map[int32]bool
}

// New returns a Watcher that writes to maps.
func New(maps Maps, logger *zap.Logger) *Watcher {
	w := &Watcher{maps: maps, logger: logger, read: Read}
	w.subscribe = subscribeEvents
	w.st = netlinksub.New(logger, "global FIB lookup mode: rules, routes and links")
	return w
}

// Start writes the full lookup for both families, then follows the
// namespace of the calling thread in the background until ctx ends, when
// it writes the full lookup again.
func (w *Watcher) Start(ctx context.Context) error {
	ns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("global FIB lookup mode: %w", err)
	}
	if err := w.setMode(false, false); err != nil {
		_ = ns.Close()
		return fmt.Errorf("global FIB lookup mode: %w", err)
	}
	go func() {
		defer func() { _ = ns.Close() }()
		runtime.LockOSThread()
		if err := netns.Set(ns); err != nil {
			w.logger.Warn("global FIB lookup mode: cannot enter the network namespace it watches; the global VRF keeps the full lookup", zap.Error(err))
			return
		}
		w.run(ctx.Done())
	}()
	return nil
}

// subscription is an open event stream.
type subscription struct {
	events <-chan []syscall.NetlinkMessage
	stop   func()
	// down reports that the stream failed; its channel may still hold the
	// batches read before the failure, and is closed after them.
	down func() bool
}

func (w *Watcher) run(quit <-chan struct{}) {
	defer func() {
		if w.sub != nil {
			w.sub.stop()
		}
		if err := w.setMode(false, false); err != nil {
			w.logger.Warn("global FIB lookup mode: cannot write the full lookup on stop", zap.Error(err))
		}
	}()
	sub, err := w.subscribe(w.st)
	for err != nil {
		if !netlinksub.Wait(quit, w.st.Failed(err)) {
			return
		}
		if sub, err = w.subscribe(w.st); err == nil {
			w.st.Restored()
		}
	}
	w.sub = sub
	listing := netlinksub.NewListing(w.logger, "global FIB lookup mode")
	retry := listing.Result(w.resync())
	settle := time.NewTimer(Settle)
	settle.Stop()
	for {
		select {
		case <-quit:
			return
		case <-retry:
			retry = listing.Result(w.resync())
		case <-settle.C:
			retry = listing.Result(w.resync())
		case msgs, ok := <-w.sub.events:
			if ok {
				if w.handle(msgs) {
					settle.Reset(Settle)
				}
				continue
			}
			w.sub.stop()
			w.sub = nil
			w.fallBack("the event subscription ended")
			settle.Stop()
			if !w.st.Again(quit, func() error {
				sub, err := w.subscribe(w.st)
				if err == nil {
					w.sub = sub
				}
				return err
			}) {
				return
			}
			retry = listing.Result(w.resync())
		}
	}
}

// resync reads the namespace and applies the decision. On a failed read or
// write both families stay on the full lookup and the error is returned for
// a retry.
func (w *Watcher) resync() error {
	s, err := w.read()
	if err != nil {
		w.fallBack("the namespace could not be read")
		return err
	}
	w.vrfTables = map[uint32]bool{}
	w.vrfLinks = map[int32]bool{}
	for _, v := range s.VRFs {
		w.vrfTables[v.Table] = true
		w.vrfLinks[int32(v.Index)] = true
	}
	// The read is only good if no event was lost while it ran: a stream
	// that failed meanwhile is resubscribed and read again by the loop.
	if w.sub == nil || w.sub.down() {
		w.fallBack("the event subscription failed")
		return nil
	}
	d := Decide(s)
	if err := w.apply(d); err != nil {
		w.fallBack("the data-plane maps could not be written")
		return err
	}
	if w.sub.down() {
		w.fallBack("the event subscription failed")
		return nil
	}
	w.log(d)
	return nil
}

// apply writes d: a family whose local addresses change leaves the direct
// mode before its map changes, and a family enters it only after.
func (w *Watcher) apply(d Decision) error {
	keep4 := d.V4.Direct && w.v4 && slices.Equal(d.V4.Local, w.local4)
	keep6 := d.V6.Direct && w.v6 && slices.Equal(d.V6.Local, w.local6)
	if err := w.setMode(keep4, keep6); err != nil {
		return err
	}
	if err := w.maps.SyncFibLocal(d.V4.Local, d.V6.Local); err != nil {
		return err
	}
	w.local4, w.local6 = d.V4.Local, d.V6.Local
	return w.setMode(d.V4.Direct, d.V6.Direct)
}

// setMode writes the mode when it differs from what the map holds. A
// direct family is first written off, so a failed write leaves the full
// lookup.
func (w *Watcher) setMode(v4, v6 bool) error {
	if v4 == w.v4 && v6 == w.v6 && w.written {
		return nil
	}
	if err := w.maps.SetFibGlobalMode(v4, v6); err != nil {
		// Try for the full lookup at least.
		if v4 || v6 {
			if w.maps.SetFibGlobalMode(false, false) == nil {
				w.v4, w.v6 = false, false
			}
		}
		return err
	}
	w.v4, w.v6, w.written = v4, v6, true
	return nil
}

// fallBack turns the direct mode off for both families.
func (w *Watcher) fallBack(why string) {
	if !w.v4 && !w.v6 {
		return
	}
	if err := w.setMode(false, false); err != nil {
		w.logger.Warn("global FIB lookup mode: cannot write the full lookup", zap.Error(err))
		return
	}
	w.logger.Info("global VRF FIB lookups: full lookup for both families until the namespace is read again", zap.String("reason", why))
}

func (w *Watcher) log(d Decision) {
	for _, f := range []struct {
		name     string
		new, old Family
	}{{"IPv4", d.V4, w.logged.V4}, {"IPv6", d.V6, w.logged.V6}} {
		if w.loggedOnce && f.new.Direct == f.old.Direct && f.new.Why == f.old.Why {
			continue
		}
		if f.new.Direct {
			w.logger.Info("global VRF FIB lookups: direct lookup", zap.String("family", f.name), zap.Int("local_addresses", len(f.new.Local)))
		} else {
			w.logger.Info("global VRF FIB lookups: full lookup", zap.String("family", f.name), zap.String("reason", f.new.Why))
		}
	}
	w.logged, w.loggedOnce = d, true
}

// handle turns the direct mode off for each family an event may affect and
// reports whether any did, so the caller schedules a read.
func (w *Watcher) handle(msgs []syscall.NetlinkMessage) bool {
	var off4, off6 bool
	for _, m := range msgs {
		f4, f6 := w.affects(m)
		off4, off6 = off4 || f4, off6 || f6
	}
	if !off4 && !off6 {
		return false
	}
	v4, v6 := w.v4 && !off4, w.v6 && !off6
	if v4 != w.v4 || v6 != w.v6 {
		if err := w.setMode(v4, v6); err != nil {
			w.logger.Warn("global FIB lookup mode: cannot write the full lookup", zap.Error(err))
		}
	}
	return true
}

// affects says which families' decision an event may change.
func (w *Watcher) affects(m syscall.NetlinkMessage) (v4, v6 bool) {
	family := func(f int) (bool, bool) { return f == unix.AF_INET, f == unix.AF_INET6 }
	switch m.Header.Type {
	case unix.RTM_NEWRULE, unix.RTM_DELRULE:
		if len(m.Data) < 1 {
			return true, true
		}
		return family(int(m.Data[0]))
	case unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
		r, ok, err := parseRoute(m.Data)
		if err != nil {
			return true, true
		}
		if !ok {
			return false, false
		}
		switch {
		case r.Table == tableLocal,
			r.Table == tableDefault && r.Family == unix.AF_INET,
			w.vrfTables[r.Table] && (r.Dst.Bits() == 0 || r.Type == unix.RTN_THROW || r.NH && r.Type == unix.RTN_BLACKHOLE):
			return family(r.Family)
		}
		return false, false
	case unix.RTM_NEWLINK, unix.RTM_DELLINK:
		if len(m.Data) < unix.SizeofIfInfomsg {
			return true, true
		}
		index := int32(binary.NativeEndian.Uint32(m.Data[4:8]))
		if w.vrfLinks[index] {
			return true, true
		}
		kind, err := linkKind(m.Data[unix.SizeofIfInfomsg:])
		if err != nil || kind == "vrf" {
			return true, true
		}
	}
	return false, false
}

// linkKind returns the IFLA_INFO_KIND of a link message's attributes.
func linkKind(b []byte) (string, error) {
	attrs, err := nl.ParseRouteAttr(b)
	if err != nil {
		return "", err
	}
	for _, a := range attrs {
		if a.Attr.Type != unix.IFLA_LINKINFO {
			continue
		}
		info, err := nl.ParseRouteAttr(a.Value)
		if err != nil {
			return "", err
		}
		for _, i := range info {
			if i.Attr.Type == unix.IFLA_INFO_KIND {
				return unix.ByteSliceToString(i.Value), nil
			}
		}
	}
	return "", nil
}

// subscribeEvents subscribes one NETLINK_ROUTE socket of the calling
// thread's namespace to the rule, route and link groups. The returned
// channel carries each batch the socket reads and is closed when a read
// fails (an overrun, ENOBUFS, among others), which ends the subscription;
// the error goes to st. The returned func closes the socket.
func subscribeEvents(st *netlinksub.State) (*subscription, error) {
	s, err := nl.Subscribe(unix.NETLINK_ROUTE,
		unix.RTNLGRP_IPV4_RULE, unix.RTNLGRP_IPV6_RULE,
		unix.RTNLGRP_IPV4_ROUTE, unix.RTNLGRP_IPV6_ROUTE,
		unix.RTNLGRP_LINK)
	if err != nil {
		return nil, fmt.Errorf("subscribe to rule, route and link events: %w", err)
	}
	// Route groups carry every route change of the namespace; a larger
	// buffer makes an overrun during a burst less likely.
	_ = s.SetReceiveBufferSize(1<<22, false)
	ch := make(chan []syscall.NetlinkMessage, 256)
	done := make(chan struct{})
	var down atomic.Bool
	go func() {
		defer close(ch)
		for {
			msgs, _, err := s.Receive()
			if err != nil {
				down.Store(true)
				select {
				case <-done:
				default:
					st.OnError(err)
				}
				return
			}
			select {
			case ch <- msgs:
			case <-done:
				return
			}
		}
	}()
	closed := false
	return &subscription{events: ch, down: down.Load, stop: func() {
		if closed {
			return
		}
		closed = true
		close(done)
		s.Close()
		go func() {
			for range ch {
			}
		}()
	}}, nil
}
