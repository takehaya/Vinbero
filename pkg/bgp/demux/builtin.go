package demux

import (
	"sort"
	"sync"

	"github.com/takehaya/vinbero/pkg/bgp"
)

type routePath struct {
	nlri   string
	source bgp.PathSource
}

type builtinGroup struct {
	routes    map[routePath]bgp.RouteEvent
	delivered map[routePath]bgp.RouteEvent
}

// builtinView tracks both the paths a built-in was given and those a claim
// withholds. An UPDATE can change its consumer without a wire withdrawal;
// that transition needs a synthetic withdrawal of the previous delivery.
// VPN paths share a headend key across RDs, so one claimed path withholds
// the whole forwarding prefix. Retained ordinary paths can be replayed
// when the last claimed path disappears.
type builtinView struct {
	mu      sync.Mutex
	groups  map[string]*builtinGroup
	claimed func(uint16) bool
	handler bgp.RouteHandler
	// Registered appliers accept idempotent withdrawals for state installed
	// outside this view. Snapshot callbacks may accept advertisements only.
	withdrawUnseen bool
	scans          map[*builtinScan]struct{}
}

// A scan only remembers prefixes changed during its own lifetime. This also
// covers removed groups without keeping tombstones for every past route.
type builtinScan struct {
	view    *builtinView
	changed map[string]struct{}
}

func (v *builtinView) beginScan() *builtinScan {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.scans == nil {
		v.scans = make(map[*builtinScan]struct{})
	}
	s := &builtinScan{view: v, changed: make(map[string]struct{})}
	v.scans[s] = struct{}{}
	return s
}

func (s *builtinScan) close() {
	s.view.mu.Lock()
	defer s.view.mu.Unlock()
	delete(s.view.scans, s)
}

func (s *builtinScan) retract(ev bgp.RouteEvent) {
	v := s.view
	v.mu.Lock()
	defer v.mu.Unlock()
	key := forwardingKey(ev)
	if _, changed := s.changed[key]; changed {
		return
	}
	if key == "" {
		if v.claimed(ev.EndpointBehavior) {
			ev.IsWithdraw = true
			v.handler(ev)
		}
		return
	}
	v.updateLocked(ev, true, key)
}

func (v *builtinView) changedLocked(key string) {
	for s := range v.scans {
		s.changed[key] = struct{}{}
	}
}

func (d *Demux) newBuiltinView(h bgp.RouteHandler) *builtinView {
	return &builtinView{
		groups: make(map[string]*builtinGroup), handler: h,
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

// refresh re-evaluates current paths after a claim rollback without replaying
// an older RIB snapshot over live updates that have already reached this view.
func (v *builtinView) refresh() {
	v.mu.Lock()
	defer v.mu.Unlock()
	keys := make([]string, 0, len(v.groups))
	for key := range v.groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		v.changedLocked(key)
		g := v.groups[key]
		paths := sortedPaths(g.routes)
		if len(paths) > 0 {
			v.updateLocked(g.routes[paths[0]], false, key)
		}
	}
}

func (v *builtinView) handle(ev bgp.RouteEvent) {
	if ev.Source.IsLocal() {
		return
	}
	key := forwardingKey(ev)
	if key == "" {
		if !v.claimed(ev.EndpointBehavior) {
			v.handler(ev)
		}
		return
	}
	// Keep mutation and delivery ordered against live and snapshot callers.
	// The built-in handler must not recursively invoke this same view.
	v.mu.Lock()
	defer v.mu.Unlock()
	v.changedLocked(key)
	v.updateLocked(ev, false, key)
}

func (v *builtinView) updateLocked(ev bgp.RouteEvent, retract bool, key string) {
	if retract && !v.claimed(ev.EndpointBehavior) {
		return
	}
	g := v.groups[key]
	if g == nil {
		g = &builtinGroup{routes: make(map[routePath]bgp.RouteEvent), delivered: make(map[routePath]bgp.RouteEvent)}
		v.groups[key] = g
	}
	path := routePath{nlriKey(ev), ev.Source}
	_, known := g.routes[path]
	if ev.IsWithdraw {
		delete(g.routes, path)
	} else {
		g.routes[path] = ev
	}
	claimed := false
	for _, route := range g.routes {
		if v.claimed(route.EndpointBehavior) {
			claimed = true
			break
		}
	}
	retracted := false
	for _, previous := range sortedPaths(g.delivered) {
		if _, still := g.routes[previous]; still && !claimed {
			continue
		}
		gone := g.delivered[previous]
		gone.IsWithdraw = true
		v.handler(gone)
		if previous == path {
			retracted = true
		}
		delete(g.delivered, previous)
	}
	if (retract || v.withdrawUnseen && claimed && !ev.IsWithdraw) && !retracted {
		// The applier may have installed this path through an independent
		// replay. Cleanup cannot depend solely on this view's history.
		gone := ev
		gone.IsWithdraw = true
		v.handler(gone)
	}
	if !claimed {
		if ev.IsWithdraw && !known {
			// The applier can own state from an earlier daemon run or an
			// independent replay. Preserve ordinary withdrawals even when
			// this view never observed their advertisements.
			v.handler(ev)
		}
		for _, current := range sortedPaths(g.routes) {
			if _, sent := g.delivered[current]; sent && (ev.IsWithdraw || current != path) {
				continue
			}
			route := g.routes[current]
			v.handler(route)
			g.delivered[current] = route
		}
	}
	if len(g.routes) == 0 {
		delete(v.groups, key)
	}
}

func sortedPaths(routes map[routePath]bgp.RouteEvent) []routePath {
	paths := make([]routePath, 0, len(routes))
	for path := range routes {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].nlri != paths[j].nlri {
			return paths[i].nlri < paths[j].nlri
		}
		return paths[i].source.String() < paths[j].source.String()
	})
	return paths
}
