package netlinkwatch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/takehaya/vinbero/pkg/fib"
	"github.com/takehaya/vinbero/pkg/netlinksub"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// RouteSink consumes VRF-local route changes the RouteWatcher observes. The
// auto-advertise exporter (pkg/bgp/export) satisfies it; keeping it an
// interface lets the watcher be tested without a BGP session.
type RouteSink interface {
	OnRoute(table uint32, prefix netip.Prefix, added bool)
}

// protocolNames maps the operator-facing redistribute keywords to the kernel
// route protocols they cover. The set is an allowlist: only the listed
// protocols are redistributed, so routes Vinbero installs itself (RTPROT_BGP)
// can never match and a received route is never advertised back out. "static"
// covers RTPROT_STATIC only (controller-authored static routes); RTPROT_BOOT,
// the default protocol for an unqualified `ip route add`, is intentionally
// excluded so a casually-added route does not leak into the VPN.
var protocolNames = map[string][]int{
	"connected": {unix.RTPROT_KERNEL},
	"static":    {unix.RTPROT_STATIC},
}

// RouteWatcher watches Linux route updates via Netlink and forwards the ones
// belonging to a registered VRF table (and a redistributed protocol) to a
// RouteSink. It mirrors FDBWatcher's lifecycle: subscribe in Start, drain on a
// goroutine, stop by closing done.
type RouteWatcher struct {
	logger  *zap.Logger
	mu      sync.RWMutex
	watched map[uint32]map[int]struct{} // table id -> allowed RTPROT_* set
	// sinks receives every matching route change, in registration order. The
	// first entry is the sink NewRouteWatcher was built with.
	sinks      []routeSinkEntry
	nextSinkID uint64
	// added holds, per table, the prefixes delivered as added and not
	// removed since, so a resync can remove the ones whose route went away
	// while the subscription was down. Guarded by mu.
	added map[uint32]map[netip.Prefix]struct{}
	// regGen numbers each table's registration, so a resync that read a
	// table under one registration delivers nothing once it is replaced.
	// Guarded by mu.
	regGen  map[uint32]uint64
	nextGen uint64
	// subscribe opens the route event stream and routeList lists a table;
	// tests replace them.
	subscribe func(ch chan<- netlink.RouteUpdate, done <-chan struct{}, options netlink.RouteSubscribeOptions) error
	routeList func(table uint32) ([]netlink.Route, error)
	// subSt follows the subscription and logs its state changes.
	subSt *netlinksub.State
	done  chan struct{}
	wg    sync.WaitGroup
}

// routeSinkEntry is one registered sink and the id its removal is keyed by.
type routeSinkEntry struct {
	id   uint64
	sink RouteSink
}

// NewRouteWatcher creates a RouteWatcher that delivers matching route changes
// to sink. Further consumers attach with AddSink.
func NewRouteWatcher(sink RouteSink, logger *zap.Logger) *RouteWatcher {
	w := &RouteWatcher{
		logger:    logger.Named("route.watch"),
		watched:   make(map[uint32]map[int]struct{}),
		added:     make(map[uint32]map[netip.Prefix]struct{}),
		regGen:    make(map[uint32]uint64),
		subscribe: netlink.RouteSubscribeWithOptions,
		routeList: listTable,
		done:      make(chan struct{}),
	}
	w.subSt = netlinksub.New(w.logger, "routes")
	if sink != nil {
		w.nextSinkID++
		w.sinks = append(w.sinks, routeSinkEntry{id: w.nextSinkID, sink: sink})
	}
	return w
}

// AddSink registers an additional consumer and returns a remove func that is
// safe to call more than once. Sinks are notified in registration order.
func (w *RouteWatcher) AddSink(sink RouteSink) func() {
	if sink == nil {
		return func() {}
	}
	w.mu.Lock()
	w.nextSinkID++
	id := w.nextSinkID
	w.sinks = append(w.sinks, routeSinkEntry{id: id, sink: sink})
	w.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			w.mu.Lock()
			defer w.mu.Unlock()
			for i, e := range w.sinks {
				if e.id == id {
					w.sinks = append(w.sinks[:i], w.sinks[i+1:]...)
					return
				}
			}
		})
	}
}

// RegisterTable registers the given routing table for redistribution: once
// Start is running, routes in that table whose protocol is covered by protocols
// (the redistribute keywords "connected" / "static") are forwarded to the sink.
// An unknown keyword is rejected so a config typo surfaces instead of silently
// redistributing nothing.
func (w *RouteWatcher) RegisterTable(table uint32, protocols []string) error {
	set := make(map[int]struct{})
	for _, name := range protocols {
		protos, ok := protocolNames[name]
		if !ok {
			return fmt.Errorf("unknown redistribute protocol %q (want connected|static)", name)
		}
		for _, p := range protos {
			set[p] = struct{}{}
		}
	}
	if len(set) == 0 {
		return fmt.Errorf("table %d: redistribute list is empty", table)
	}
	w.mu.Lock()
	w.watched[table] = set
	w.nextGen++
	w.regGen[table] = w.nextGen
	w.mu.Unlock()
	w.logger.Info("registered VRF table for route redistribution",
		zap.Uint32("table", table), zap.Strings("protocols", protocols))
	return nil
}

// UnregisterTable stops forwarding routes for a table.
func (w *RouteWatcher) UnregisterTable(table uint32) {
	w.mu.Lock()
	delete(w.watched, table)
	delete(w.added, table)
	delete(w.regGen, table)
	w.mu.Unlock()
}

// Start subscribes to route updates in the calling thread's network
// namespace and begins forwarding. Before the first update it replays the
// registered tables' existing routes, so prefixes present before startup are
// advertised too, matching FDBWatcher; the updates that arrived meanwhile
// follow, so the latest state wins. A subscription that ends (e.g. an ENOBUFS
// overflow) is subscribed again (netlinksub) and the tables are resynced:
// their routes are delivered as adds again, and a prefix delivered before
// whose route is gone now is delivered as removed.
func (w *RouteWatcher) Start(ctx context.Context) error {
	ns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("route watcher: %w", err)
	}
	updates, stop, err := w.subscribeRoutes()
	if err != nil {
		_ = ns.Close()
		return err
	}
	w.wg.Go(func() {
		defer func() { _ = ns.Close() }()
		w.follow(ctx, ns, updates, stop)
	})
	return nil
}

// subscribeRoutes subscribes to route updates in the calling thread's
// network namespace. Closing stop ends the subscription. The tables are listed with requests of their own: the
// library's ListExisting would send its request to every other subscriber of
// the route group (netlinksub).
func (w *RouteWatcher) subscribeRoutes() (<-chan netlink.RouteUpdate, chan struct{}, error) {
	updates := make(chan netlink.RouteUpdate, 256)
	stop := make(chan struct{})
	if err := w.subscribe(updates, stop, netlink.RouteSubscribeOptions{
		// A larger socket buffer reduces the chance of an ENOBUFS overflow
		// during a route-churn burst.
		ReceiveBufferSize: 1 << 20,
		ErrorCallback:     w.subSt.OnError,
	}); err != nil {
		close(stop)
		return nil, nil, fmt.Errorf("subscribe to route updates: %w", err)
	}
	return updates, stop, nil
}

// follow resyncs the tables, then forwards the subscription's updates until
// the watcher stops. It subscribes again in ns each time the subscription
// ends and resyncs then, and repeats a resync that failed when its retry
// fires.
func (w *RouteWatcher) follow(ctx context.Context, ns netns.NsHandle, updates <-chan netlink.RouteUpdate, stop chan struct{}) {
	if err := enterNetns(ns); err != nil {
		w.logger.Warn("route watcher: cannot enter the network namespace it watches; a resync may list another", zap.Error(err))
	}
	quit := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-w.done:
		}
		close(quit)
	}()
	listing := netlinksub.NewListing(w.logger, "routes")
	again := listing.Result(w.resync())
	for {
		select {
		case <-quit:
			close(stop)
			go drain(updates)
			return
		case <-again:
			again = listing.Result(w.resync())
		case update, ok := <-updates:
			if ok {
				w.handleRouteUpdate(update)
				continue
			}
			close(stop)
			if !w.subSt.Again(quit, func() error {
				var err error
				updates, stop, err = w.subscribeRoutes()
				return err
			}) {
				return
			}
			again = listing.Result(w.resync())
		}
	}
}

// resync delivers as removed each prefix of a watched table delivered as
// added whose route is gone, then every redistributed route of the table as
// added: removals first, so a prefix cap (max_prefixes) frees its room
// before the adds. A table whose listing fails is left as it is, and the
// error is returned for a retry.
func (w *RouteWatcher) resync() error {
	type reg struct {
		protos map[int]struct{}
		gen    uint64
	}
	w.mu.RLock()
	tables := make(map[uint32]reg, len(w.watched))
	for t, p := range w.watched {
		tables[t] = reg{protos: p, gen: w.regGen[t]}
	}
	w.mu.RUnlock()
	var errs []error
	for table, r := range tables {
		routes, err := w.routeList(table)
		if err != nil {
			errs = append(errs, fmt.Errorf("table %d: %w", table, err))
			continue
		}
		present := map[netip.Prefix]struct{}{}
		for i := range routes {
			if p, ok := redistributed(r.protos, int(routes[i].Protocol), routes[i].Dst); ok {
				present[p] = struct{}{}
			}
		}
		w.mu.RLock()
		var gone []netip.Prefix
		for p := range w.added[table] {
			if _, ok := present[p]; !ok {
				gone = append(gone, p)
			}
		}
		w.mu.RUnlock()
		for _, p := range gone {
			w.sendAs(table, r.gen, p, false)
		}
		for p := range present {
			w.sendAs(table, r.gen, p, true)
		}
	}
	return errors.Join(errs...)
}

func (w *RouteWatcher) handleRouteUpdate(u netlink.RouteUpdate) {
	table := uint32(u.Table)
	w.mu.RLock()
	protos, watched := w.watched[table]
	w.mu.RUnlock()
	if !watched {
		return
	}
	switch u.Type {
	case unix.RTM_NEWROUTE:
		w.deliver(table, protos, int(u.Protocol), u.Dst, true)
	case unix.RTM_DELROUTE:
		w.deliver(table, protos, int(u.Protocol), u.Dst, false)
	}
}

// deliver applies the redistribute protocol allowlist to one route and forwards
// it to every registered sink. Shared by the live update path
// (handleRouteUpdate) and the replay path (DumpTable) so the filter contract
// lives in one place.
func (w *RouteWatcher) deliver(table uint32, protos map[int]struct{}, proto int, dst *net.IPNet, added bool) {
	prefix, ok := redistributed(protos, proto, dst)
	if !ok {
		return
	}
	w.send(table, prefix, added)
}

// redistributed returns the prefix of a route the protocol allowlist
// passes.
func redistributed(protos map[int]struct{}, proto int, dst *net.IPNet) (netip.Prefix, bool) {
	if _, allow := protos[proto]; !allow {
		return netip.Prefix{}, false
	}
	// A nil destination is the default route / a route with no prefix; nothing
	// specific to advertise.
	if dst == nil {
		return netip.Prefix{}, false
	}
	return fib.IPNetToPrefix(dst)
}

// send records the change in added and forwards it to every registered sink.
func (w *RouteWatcher) send(table uint32, prefix netip.Prefix, added bool) {
	w.sendAs(table, 0, prefix, added)
}

// sendAs is send for a change read under the table's registration gen (0:
// any). A change for a table that is not watched, or whose registration is
// not gen any more, is dropped.
func (w *RouteWatcher) sendAs(table uint32, gen uint64, prefix netip.Prefix, added bool) {
	// Copy the sink list so delivery runs without holding w.mu: a sink may
	// call back into the watcher (RegisterTable / DumpTable).
	w.mu.Lock()
	cur, watched := w.regGen[table]
	if !watched || (gen != 0 && cur != gen) {
		w.mu.Unlock()
		return
	}
	if added {
		if w.added[table] == nil {
			w.added[table] = map[netip.Prefix]struct{}{}
		}
		w.added[table][prefix] = struct{}{}
	} else {
		delete(w.added[table], prefix)
	}
	sinks := make([]RouteSink, 0, len(w.sinks))
	for _, e := range w.sinks {
		sinks = append(sinks, e.sink)
	}
	w.mu.Unlock()
	for _, sink := range sinks {
		sink.OnRoute(table, prefix, added)
	}
}

// Stop ends the watch and waits for the drain goroutine to exit.
func (w *RouteWatcher) Stop() {
	select {
	case <-w.done:
	default:
		close(w.done)
	}
	w.wg.Wait()
}

// DumpTable replays a registered table's existing routes through the sink as
// adds. The replay of the existing routes in Start only covers tables registered
// before Start; a table registered later (e.g. a VRF bound at runtime over RPC)
// needs this to pick up routes already present. Routes are filtered by the same
// protocol allowlist RegisterTable recorded for the table.
func (w *RouteWatcher) DumpTable(table uint32) error {
	w.mu.RLock()
	protos, watched := w.watched[table]
	w.mu.RUnlock()
	if !watched {
		return fmt.Errorf("table %d is not registered", table)
	}
	routes, err := w.routeList(table)
	if err != nil {
		return fmt.Errorf("list routes in table %d: %w", table, err)
	}
	for i := range routes {
		r := &routes[i]
		w.deliver(table, protos, int(r.Protocol), r.Dst, true)
	}
	return nil
}

// listTable lists the routes of a table, both families.
func listTable(table uint32) ([]netlink.Route, error) {
	return netlink.RouteListFiltered(unix.AF_UNSPEC, &netlink.Route{Table: int(table)}, netlink.RT_FILTER_TABLE)
}
