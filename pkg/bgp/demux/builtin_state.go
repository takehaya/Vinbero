package demux

import (
	"sort"

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

// builtinDeliveryState retains paths and the delivery decisions made for them.
// Its transitions return ordered route actions; they never invoke an applier.
// The view serializes transitions and action dispatch under its existing lock.
// A delivery record is not an acknowledgement of a successful kernel write.
// The key adapter groups VPN paths by forwarding prefix and other families by NLRI.
type builtinDeliveryState struct {
	groups map[string]*builtinGroup
	key    func(bgp.RouteEvent) string
	scans  map[*builtinScanState]struct{}
}

// Scan-local changes protect retraction from old RIB data without permanent
// tombstones. The view closes the scan after the RIB walk, including on failure.
type builtinScanState struct {
	changed map[routePath]struct{}
}

func newBuiltinDeliveryState(key func(bgp.RouteEvent) string) builtinDeliveryState {
	return builtinDeliveryState{groups: make(map[string]*builtinGroup), key: key}
}

func (s *builtinDeliveryState) beginScan() *builtinScanState {
	if s.scans == nil {
		s.scans = make(map[*builtinScanState]struct{})
	}
	scan := &builtinScanState{changed: make(map[routePath]struct{})}
	s.scans[scan] = struct{}{}
	return scan
}

func (s *builtinDeliveryState) endScan(scan *builtinScanState) {
	delete(s.scans, scan)
}

func (s *builtinDeliveryState) changed(ev bgp.RouteEvent) {
	for scan := range s.scans {
		scan.changed[routePath{nlriKey(ev), ev.Source}] = struct{}{}
	}
}

func (s *builtinDeliveryState) retract(scan *builtinScanState, ev bgp.RouteEvent, isClaimed func(uint16) bool) []bgp.RouteEvent {
	key := s.key(ev)
	if _, changed := scan.changed[routePath{nlriKey(ev), ev.Source}]; changed {
		return nil
	}
	if key == "" {
		if isClaimed(ev.EndpointBehavior) {
			ev.IsWithdraw = true
			return []bgp.RouteEvent{ev}
		}
		return nil
	}
	return s.update(ev, true, key, false, isClaimed)
}

func (s *builtinDeliveryState) keys() []string {
	keys := make([]string, 0, len(s.groups))
	for key := range s.groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// refresh re-evaluates one group from current retained paths after a claim
// rollback. The view dispatches each group's actions before evaluating the next.
func (s *builtinDeliveryState) refresh(key string, isClaimed func(uint16) bool) []bgp.RouteEvent {
	g := s.groups[key]
	paths := sortedPaths(g.routes)
	for _, path := range paths {
		s.changed(g.routes[path])
	}
	if len(paths) == 0 {
		return nil
	}
	return s.update(g.routes[paths[0]], false, key, false, isClaimed)
}

func (s *builtinDeliveryState) handle(ev bgp.RouteEvent, claimedWithdraw bool, isClaimed func(uint16) bool) []bgp.RouteEvent {
	if ev.Source.IsLocal() {
		return nil
	}
	key := s.key(ev)
	if key == "" {
		if !claimedWithdraw && !isClaimed(ev.EndpointBehavior) {
			return []bgp.RouteEvent{ev}
		}
		return nil
	}
	s.changed(ev)
	return s.update(ev, false, key, claimedWithdraw, isClaimed)
}

func (s *builtinDeliveryState) update(ev bgp.RouteEvent, retract bool, key string, claimedWithdraw bool, isClaimed func(uint16) bool) []bgp.RouteEvent {
	if retract && !isClaimed(ev.EndpointBehavior) {
		return nil
	}
	var actions []bgp.RouteEvent
	g := s.groups[key]
	if g == nil {
		g = &builtinGroup{routes: make(map[routePath]bgp.RouteEvent), delivered: make(map[routePath]bgp.RouteEvent)}
		s.groups[key] = g
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
		if isClaimed(route.EndpointBehavior) {
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
		actions = append(actions, gone)
		if previous == path {
			retracted = true
		}
		delete(g.delivered, previous)
	}
	if (retract || claimed && !ev.IsWithdraw) && !retracted {
		// The applier may have installed this path through an independent
		// replay. Cleanup cannot depend solely on this view's history.
		gone := ev
		gone.IsWithdraw = true
		actions = append(actions, gone)
	}
	if !claimed {
		if ev.IsWithdraw && !known && !claimedWithdraw {
			// The applier can own state from an earlier daemon run or an
			// independent replay. Preserve ordinary withdrawals even when
			// this view never observed their advertisements.
			actions = append(actions, ev)
		}
		for _, current := range sortedPaths(g.routes) {
			if _, sent := g.delivered[current]; sent && (ev.IsWithdraw || current != path) {
				continue
			}
			route := g.routes[current]
			actions = append(actions, route)
			g.delivered[current] = route
		}
	}
	if len(g.routes) == 0 {
		delete(s.groups, key)
	}
	return actions
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
