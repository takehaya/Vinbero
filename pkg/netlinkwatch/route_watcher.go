package netlinkwatch

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/takehaya/vinbero/pkg/fib"
	"github.com/vishvananda/netlink"
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
	done       chan struct{}
	wg         sync.WaitGroup
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
		logger:  logger.Named("route.watch"),
		watched: make(map[uint32]map[int]struct{}),
		done:    make(chan struct{}),
	}
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
	w.mu.Unlock()
	w.logger.Info("registered VRF table for route redistribution",
		zap.Uint32("table", table), zap.Strings("protocols", protocols))
	return nil
}

// UnregisterTable stops forwarding routes for a table.
func (w *RouteWatcher) UnregisterTable(table uint32) {
	w.mu.Lock()
	delete(w.watched, table)
	w.mu.Unlock()
}

// Start subscribes to route updates and begins forwarding. ListExisting
// replays the current routing tables so prefixes present before startup are
// advertised too, matching FDBWatcher.
func (w *RouteWatcher) Start(ctx context.Context) error {
	updates := make(chan netlink.RouteUpdate, 256)
	if err := netlink.RouteSubscribeWithOptions(updates, w.done, netlink.RouteSubscribeOptions{
		ListExisting: true,
		// A larger socket buffer reduces the chance of an ENOBUFS overflow
		// during the ListExisting dump or a route-churn burst; ErrorCallback
		// surfaces any subscription error (including a dump interruption)
		// instead of letting it pass silently.
		ReceiveBufferSize: 1 << 20,
		ErrorCallback: func(err error) {
			w.logger.Error("netlink route subscription error", zap.Error(err))
		},
	}); err != nil {
		return err
	}
	w.wg.Go(func() {
		w.processUpdates(ctx, updates)
	})
	return nil
}

func (w *RouteWatcher) processUpdates(ctx context.Context, updates <-chan netlink.RouteUpdate) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case update, ok := <-updates:
			if !ok {
				// A clean Stop() closes w.done first, so reaching here with
				// w.done still open means the netlink socket closed the channel
				// on its own (e.g. an ENOBUFS overflow). Log loudly: route
				// changes are no longer observed, so advertised routes can
				// silently go stale until the daemon restarts.
				select {
				case <-w.done:
				default:
					w.logger.Error("netlink route update channel closed unexpectedly; " +
						"auto-advertise is no longer tracking route changes")
				}
				return
			}
			w.handleRouteUpdate(update)
		}
	}
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
	if _, allow := protos[proto]; !allow {
		return
	}
	// A nil destination is the default route / a route with no prefix; nothing
	// specific to advertise.
	if dst == nil {
		return
	}
	prefix, ok := fib.IPNetToPrefix(dst)
	if !ok {
		return
	}
	// Copy the sink list so delivery runs without holding w.mu: a sink may
	// call back into the watcher (RegisterTable / DumpTable).
	w.mu.RLock()
	sinks := make([]RouteSink, 0, len(w.sinks))
	for _, e := range w.sinks {
		sinks = append(sinks, e.sink)
	}
	w.mu.RUnlock()
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
// adds. The initial ListExisting replay in Start only covers tables registered
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
	routes, err := netlink.RouteListFiltered(unix.AF_UNSPEC,
		&netlink.Route{Table: int(table)}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list routes in table %d: %w", table, err)
	}
	for i := range routes {
		r := &routes[i]
		w.deliver(table, protos, int(r.Protocol), r.Dst, true)
	}
	return nil
}
