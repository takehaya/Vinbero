package apply

import (
	"fmt"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// TrackedWriteError reports writes or removals of state the applier tracks
// that ReconcileTracked could not make. The state is kept, so another
// ReconcileTracked pass retries them; no loc-rib replay is needed.
type TrackedWriteError struct {
	VPN, MUP, EVPN int // VPN prefixes, MUP sessions, EVPN peers and segments
}

// Failed is how many entries are still failing.
func (e *TrackedWriteError) Failed() int { return e.VPN + e.MUP + e.EVPN }

func (e *TrackedWriteError) Error() string {
	return fmt.Sprintf("data-plane writes failed for %d VPN prefixes, %d MUP sessions and %d EVPN entries",
		e.VPN, e.MUP, e.EVPN)
}

// UnwrittenRoutesError reports routes a replay delivered but could not
// write, and that the applier does not track until they are written (EVPN
// routes). Only another replay of Family delivers them again.
type UnwrittenRoutesError struct {
	Family bgp.Family
	Routes int
}

func (e *UnwrittenRoutesError) Error() string {
	return fmt.Sprintf("data-plane writes failed for %d %s routes during the replay", e.Routes, e.Family)
}
