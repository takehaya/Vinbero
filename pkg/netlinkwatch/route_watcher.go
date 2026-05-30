package netlinkwatch

import (
	"context"
	"fmt"
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
	sink    RouteSink
	logger  *zap.Logger
	mu      sync.RWMutex
	watched map[uint32]map[int]struct{} // table id -> allowed RTPROT_* set
	done    chan struct{}
	wg      sync.WaitGroup
}

// NewRouteWatcher creates a RouteWatcher that delivers matching route changes
// to sink.
func NewRouteWatcher(sink RouteSink, logger *zap.Logger) *RouteWatcher {
	return &RouteWatcher{
		sink:    sink,
		logger:  logger.Named("route.watch"),
		watched: make(map[uint32]map[int]struct{}),
		done:    make(chan struct{}),
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
	if _, allow := protos[int(u.Protocol)]; !allow {
		return
	}
	// A nil destination is the default route / a route with no prefix; there
	// is nothing specific to advertise, so skip it.
	if u.Dst == nil {
		return
	}
	prefix, ok := fib.IPNetToPrefix(u.Dst)
	if !ok {
		return
	}
	switch u.Type {
	case unix.RTM_NEWROUTE:
		w.sink.OnRoute(table, prefix, true)
	case unix.RTM_DELROUTE:
		w.sink.OnRoute(table, prefix, false)
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
