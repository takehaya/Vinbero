package demux

import (
	"sync"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// builtinView serializes delivery-state transitions with their resulting
// callbacks. Its lock also orders on-demand replay against live events.
type builtinView struct {
	mu      sync.Mutex
	state   builtinDeliveryState
	claimed func(uint16) bool
	handler bgp.RouteHandler
}

type builtinScan struct {
	view  *builtinView
	state *builtinScanState
}

func (v *builtinView) beginScan() *builtinScan {
	v.mu.Lock()
	defer v.mu.Unlock()
	return &builtinScan{view: v, state: v.state.beginScan()}
}

func (s *builtinScan) close() {
	s.view.mu.Lock()
	defer s.view.mu.Unlock()
	s.view.state.endScan(s.state)
}

func (s *builtinScan) retract(ev bgp.RouteEvent) {
	v := s.view
	v.mu.Lock()
	defer v.mu.Unlock()
	v.dispatchLocked(v.state.retract(s.state, ev, v.claimed))
}

func (d *Demux) newBuiltinView(h bgp.RouteHandler) *builtinView {
	return &builtinView{
		state: newBuiltinDeliveryState(forwardingKey), handler: h,
		claimed: func(behavior uint16) bool {
			d.mu.RLock()
			claims := d.claims
			d.mu.RUnlock()
			return claims.IsClaimed(behavior)
		},
	}
}

func forwardingKey(ev bgp.RouteEvent) string {
	if ev.VPN != nil {
		return join("vpn-prefix", string(ev.Family), ev.VPN.Prefix)
	}
	return nlriKey(ev)
}

// refresh uses current paths after a claim rollback, never an older snapshot
// that could reintroduce a path withdrawn during registration.
func (v *builtinView) refresh() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, key := range v.state.keys() {
		v.dispatchLocked(v.state.refresh(key, v.claimed))
	}
}

func (v *builtinView) handle(ev bgp.RouteEvent) {
	v.handleWithClaim(ev, false)
}

func (v *builtinView) handleWithClaim(ev bgp.RouteEvent, claimedWithdraw bool) {
	// The built-in handler must not recursively invoke this same view.
	v.mu.Lock()
	defer v.mu.Unlock()
	v.handleLocked(ev, claimedWithdraw)
}

func (v *builtinView) handleLocked(ev bgp.RouteEvent, claimedWithdraw bool) {
	v.dispatchLocked(v.state.handle(ev, claimedWithdraw, v.claimed))
}

func (v *builtinView) dispatchLocked(actions []bgp.RouteEvent) {
	for _, ev := range actions {
		v.handler(ev)
	}
}
