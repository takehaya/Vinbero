package gobgp

import (
	"fmt"

	gobgpapi "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// compile-time assertion that *Session also satisfies RouteLister.
var _ bgp.RouteLister = (*Session)(nil)

// ListRoutes snapshots the loc-rib for family and hands each peer-learned
// route to handler on the calling goroutine. Unlike the Subscribe stream
// (post-policy peer updates only), the rib also holds this node's own
// advertisements, so locally originated paths are skipped here -- gobgp
// marks them with an invalid source address, which toPathApiUtil copies
// into Path.PeerAddress. Re-applying an own EVPN RT3 would otherwise
// install a self-pointing BUM peer. The decode is the same pathToRouteEvent
// the live watch uses (ListPath builds paths with the same converter), and
// rib-resident paths always carry Withdrawal=false.
func (s *Session) ListRoutes(family bgp.Family, handler bgp.RouteHandler) error {
	srv := s.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	rf, err := vinberoFamilyToAPI(family)
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}
	return srv.ListPath(apiutil.ListPathRequest{
		TableType: gobgpapi.TableType_TABLE_TYPE_GLOBAL,
		Family:    rf,
	}, func(_ gobgppkt.NLRI, paths []*apiutil.Path) {
		for _, p := range paths {
			if !p.PeerAddress.IsValid() {
				continue // locally originated (this node's own advertisement)
			}
			ev, ok := pathToRouteEvent(p)
			if !ok || ev.Family != family {
				continue
			}
			handler(ev)
		}
	})
}
