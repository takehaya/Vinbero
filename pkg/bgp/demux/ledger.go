package demux

import (
	"fmt"
	"strings"
	"sync"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// A withdrawal carries no path attributes: gobgp builds the withdraw path
// with an empty attribute list, because BGP itself only sends the NLRI
// being removed. So the endpoint behavior a route was advertised with is
// simply not on the wire when it goes away.
//
// That breaks the claim rule in the one direction that matters most. The
// advertise is withheld from the built-in applier, which therefore tracks
// nothing for that prefix; the withdraw then arrives with behavior 0,
// looks unclaimed, and reaches the applier as a delete for state it never
// installed. Best case that is a permanent error log per withdraw; for the
// paths that are not owner-guarded it is a delete of a plugin's entry.
//
// The ledger closes that by remembering the decision instead of re-deriving
// it: an advertise whose behavior is claimed records its NLRI, and a
// withdraw for a recorded NLRI is treated as claimed and consumes the
// record. Keying on NLRI works because that is the one thing a withdraw
// does carry.
// The record is per path, not per NLRI. Behind a pair of route reflectors,
// or with ADD-PATH, one NLRI arrives as several paths and is withdrawn
// several times; a single record consumed by the first withdraw would let
// the second escape to the built-in appliers with behavior 0, which is the
// very failure this exists to prevent. So each path is tracked separately
// and the NLRI stays claimed until the last one is gone.
type claimLedger struct {
	mu sync.Mutex
	// paths holds, per NLRI key, the paths currently advertised under a
	// claimed behavior. An NLRI with no paths left is removed, so the
	// ledger tracks live routes rather than growing without bound.
	paths map[string]map[bgp.PathSource]struct{}
}

func newClaimLedger() *claimLedger {
	return &claimLedger{paths: make(map[string]map[bgp.PathSource]struct{})}
}

// recordAdvertise marks one path of an NLRI as claimed.
func (l *claimLedger) recordAdvertise(key string, src bgp.PathSource) {
	if key == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	byPath, ok := l.paths[key]
	if !ok {
		byPath = make(map[bgp.PathSource]struct{})
		l.paths[key] = byPath
	}
	byPath[src] = struct{}{}
}

// forget drops one path. The NLRI stops being claimed only once no path
// under it remains.
func (l *claimLedger) forget(key string, src bgp.PathSource) {
	if key == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	byPath, ok := l.paths[key]
	if !ok {
		return
	}
	delete(byPath, src)
	if len(byPath) == 0 {
		delete(l.paths, key)
	}
}

// isClaimed reports whether any path of an NLRI is advertised under a
// claimed behavior.
func (l *claimLedger) isClaimed(key string) bool {
	if key == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.paths[key]) > 0
}

// size is the number of live claimed NLRIs, for tests and diagnostics.
func (l *claimLedger) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.paths)
}

// nlriKey identifies the route an event is about, stably across the
// advertise and the withdraw of the same NLRI.
//
// It deliberately excludes the path source: a route withdrawn by one peer
// may still be advertised by another, and the claim decision belongs to
// the NLRI rather than to any one path. It also excludes everything an
// attribute carries, since a withdraw has none.
//
// Returns "" when the family carries nothing usable, in which case the
// caller falls back to the behavior on the event itself.
func nlriKey(ev bgp.RouteEvent) string {
	switch {
	case ev.VPN != nil:
		return join("vpn", string(ev.Family), ev.VPN.RD, ev.VPN.Prefix)
	case ev.Unicast != nil:
		return join("unicast", string(ev.Family), ev.Unicast.Prefix)
	case ev.EVPN != nil:
		e := ev.EVPN
		return join("evpn", string(ev.Family), fmt.Sprint(int(e.Type)), e.RD,
			fmt.Sprintf("%x", e.ESI), fmt.Sprint(e.EthernetTag), e.MAC, e.IPAddr, e.ESImportRT)
	case ev.MUP != nil:
		m := ev.MUP
		return join("mup", string(ev.Family), fmt.Sprint(int(m.Type)), m.RD, m.Prefix,
			m.Address, fmt.Sprint(m.TEID), fmt.Sprint(m.TEIDLen))
	case ev.SRPolicy != nil:
		p := ev.SRPolicy
		return join("srpolicy", string(ev.Family), fmt.Sprint(p.Color), p.Endpoint.String())
	default:
		return ""
	}
}

// join builds a key from parts, separated so two different field splits
// cannot render the same string.
func join(parts ...string) string {
	return strings.Join(parts, "\x1f")
}
