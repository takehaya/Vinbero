package gobgp

import (
	"context"
	"fmt"
	"time"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	gobgpsrv "github.com/osrg/gobgp/v4/pkg/server"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// compile-time assertion that *Session also satisfies RouteSubscriber.
var _ bgp.RouteSubscriber = (*Session)(nil)

// Subscribe registers handler for post-policy route updates. The cancel
// func tears down the underlying gobgp watcher; callers must invoke it
// to avoid leaking the watch goroutine.
//
// handler is called from a gobgp-internal goroutine and must not block
// (see bgp.RouteHandler). filter restricts delivery to one family; an
// empty filter delivers every supported family.
func (s *Session) Subscribe(filter bgp.Family, handler bgp.RouteHandler) (func(), error) {
	srv := s.bgpServer()
	if srv == nil {
		return nil, bgp.ErrSessionNotStarted
	}
	ctx, cancel := context.WithCancel(context.Background())
	cbs := gobgpsrv.WatchEventMessageCallbacks{
		OnPathUpdate: func(paths []*apiutil.Path, _ time.Time) {
			for _, p := range paths {
				ev, ok := pathToRouteEvent(p)
				if !ok {
					continue // family Vinbero does not consume
				}
				if filter != "" && ev.Family != filter {
					continue
				}
				handler(ev)
			}
		},
	}
	// WatchPostUpdate: post-import-policy routes, which is what the data
	// plane should mirror. current=true replays the existing RIB so a
	// subscriber that attaches after peers are up still sees them.
	//
	// INVARIANT: Subscribe is called exactly once, at daemon start, before
	// any local route/SR Policy is advertised (see cmd/vinberod/main.go).
	// The current=true replay therefore only ever delivers peer-learned
	// routes, never this node's own advertisements. If that ordering is ever
	// broken -- a second Subscribe, or advertising before subscribing -- the
	// replay would feed the node's own advertised routes back into the
	// applier. A node that both advertises and steers would then act on its
	// own SR Policy / VPN routes. Preserve the single-boot-subscribe ordering,
	// or filter local-origin paths here, before relaxing this.
	if err := srv.WatchEvent(ctx, cbs, gobgpsrv.WatchPostUpdate(true, "", "")); err != nil {
		cancel()
		return nil, fmt.Errorf("watch event: %w", err)
	}
	return cancel, nil
}

// pathToRouteEvent converts a gobgp received Path into a Vinbero
// RouteEvent. VPN families are fully decoded (RD / prefix / SRv6 SID /
// route targets / next hop); IPv6 unicast carries prefix and next hop.
func pathToRouteEvent(p *apiutil.Path) (bgp.RouteEvent, bool) {
	fam, ok := apiFamilyToVinbero(p.Family)
	if !ok {
		return bgp.RouteEvent{}, false
	}
	ev := bgp.RouteEvent{Family: fam, IsWithdraw: p.Withdrawal}
	switch fam {
	case bgp.FamilyVPNv4, bgp.FamilyVPNv6:
		ev.VPN = decodeVPNRoute(p, fam)
	case bgp.FamilyIPv6Unicast:
		ev.Unicast = &bgp.UnicastRoute{
			Prefix:  nlriString(p.Nlri),
			NextHop: decodeNextHop(p.Attrs),
		}
	case bgp.FamilySRPolicyIPv6:
		ev.SRPolicy = decodeSRPolicy(p)
	}
	return ev, true
}

// apiFamilyToVinbero maps a gobgp route family to a Vinbero Family.
// Unsupported families return ok=false so the caller skips them.
func apiFamilyToVinbero(f gobgppkt.Family) (bgp.Family, bool) {
	switch f {
	case gobgppkt.RF_IPv4_VPN:
		return bgp.FamilyVPNv4, true
	case gobgppkt.RF_IPv6_VPN:
		return bgp.FamilyVPNv6, true
	case gobgppkt.RF_IPv6_UC:
		return bgp.FamilyIPv6Unicast, true
	case gobgppkt.RF_SR_POLICY_IPv6:
		return bgp.FamilySRPolicyIPv6, true
	default:
		return "", false
	}
}
