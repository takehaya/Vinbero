package demux

import (
	"slices"
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
//
// A claimed path takes its group away from the built-in applier only where
// the applier would put it. vrfs names those VRFs for a VPN path; the other
// paths of the prefix are then kept out of those VRFs alone (see
// bgp.RouteEvent.ExcludedVRFs) and still reach the applier for the rest. A
// path vrfs cannot place (any other family, or no vrfs at all) withholds its
// whole group when it is claimed.
type builtinDeliveryState struct {
	groups map[string]*builtinGroup
	key    func(bgp.RouteEvent) string
	scans  map[*builtinScanState]struct{}
	vrfs   func(bgp.RouteEvent) ([]uint32, bool)
}

// builtinDelivery is what one retained path should be to the applier: not
// delivered, or delivered and kept out of excluded.
type builtinDelivery struct {
	deliver  bool
	excluded []uint32
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

func (s *builtinDeliveryState) retract(scan *builtinScanState, ev bgp.RouteEvent, isClaimed func(bgp.RouteEvent) bool) []bgp.RouteEvent {
	key := s.key(ev)
	if _, changed := scan.changed[routePath{nlriKey(ev), ev.Source}]; changed {
		return nil
	}
	if key == "" {
		if isClaimed(ev) {
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
func (s *builtinDeliveryState) refresh(key string, isClaimed func(bgp.RouteEvent) bool) []bgp.RouteEvent {
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

func (s *builtinDeliveryState) handle(ev bgp.RouteEvent, claimedWithdraw bool, isClaimed func(bgp.RouteEvent) bool) []bgp.RouteEvent {
	if ev.Source.IsLocal() {
		return nil
	}
	key := s.key(ev)
	if key == "" {
		if !claimedWithdraw && !isClaimed(ev) {
			return []bgp.RouteEvent{ev}
		}
		return nil
	}
	s.changed(ev)
	return s.update(ev, false, key, claimedWithdraw, isClaimed)
}

func (s *builtinDeliveryState) update(ev bgp.RouteEvent, retract bool, key string, claimedWithdraw bool, isClaimed func(bgp.RouteEvent) bool) []bgp.RouteEvent {
	if retract && !isClaimed(ev) {
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
	plan, whole := s.plan(g, isClaimed)
	retracted := false
	for _, previous := range sortedPaths(g.delivered) {
		if plan[previous].deliver {
			continue
		}
		gone := g.delivered[previous]
		gone.IsWithdraw, gone.ExcludedVRFs = true, nil
		actions = append(actions, gone)
		if previous == path {
			retracted = true
		}
		delete(g.delivered, previous)
	}
	if (retract || !ev.IsWithdraw && !plan[path].deliver) && !retracted {
		// The applier may have installed this path through an independent
		// replay. Cleanup cannot depend solely on this view's history.
		gone := ev
		gone.IsWithdraw, gone.ExcludedVRFs = true, nil
		actions = append(actions, gone)
	}
	if ev.IsWithdraw && !known && !claimedWithdraw && !whole {
		// The applier can own state from an earlier daemon run or an
		// independent replay. Preserve ordinary withdrawals even when
		// this view never observed their advertisements.
		actions = append(actions, ev)
	}
	for _, current := range sortedPaths(g.routes) {
		want := plan[current]
		if !want.deliver {
			continue
		}
		if sent, ok := g.delivered[current]; ok && (ev.IsWithdraw || current != path) && slices.Equal(sent.ExcludedVRFs, want.excluded) {
			continue
		}
		route := g.routes[current]
		route.ExcludedVRFs = want.excluded
		actions = append(actions, route)
		g.delivered[current] = route
	}
	if len(g.routes) == 0 {
		delete(s.groups, key)
	}
	return actions
}

// plan decides every retained path of g. A claimed path is never delivered.
// An unclaimed one is kept out of the VRFs the claimed paths are placed in,
// and is not delivered when that leaves it none. whole reports a claimed
// path whose VRFs are unknown, which withholds the whole group.
func (s *builtinDeliveryState) plan(g *builtinGroup, isClaimed func(bgp.RouteEvent) bool) (map[routePath]builtinDelivery, bool) {
	plan := make(map[routePath]builtinDelivery, len(g.routes))
	taken := make(map[uint32]struct{})
	whole := false
	for path, route := range g.routes {
		if !isClaimed(route) {
			continue
		}
		plan[path] = builtinDelivery{}
		vrfs, ok := s.placement(route)
		if !ok {
			whole = true
		}
		for _, v := range vrfs {
			taken[v] = struct{}{}
		}
	}
	for path, route := range g.routes {
		if _, claimed := plan[path]; claimed {
			continue
		}
		if whole {
			plan[path] = builtinDelivery{}
			continue
		}
		if len(taken) == 0 {
			plan[path] = builtinDelivery{deliver: true}
			continue
		}
		vrfs, ok := s.placement(route)
		if !ok {
			plan[path] = builtinDelivery{}
			continue
		}
		var excluded []uint32
		for _, v := range vrfs {
			if _, ok := taken[v]; ok {
				excluded = append(excluded, v)
			}
		}
		if len(excluded) > 0 && len(excluded) == len(vrfs) {
			plan[path] = builtinDelivery{}
			continue
		}
		slices.Sort(excluded)
		plan[path] = builtinDelivery{deliver: true, excluded: excluded}
	}
	return plan, whole
}

// placement is the VRFs the applier places route in, deduplicated, and
// whether they are known.
func (s *builtinDeliveryState) placement(route bgp.RouteEvent) ([]uint32, bool) {
	if s.vrfs == nil {
		return nil, false
	}
	vrfs, ok := s.vrfs(route)
	if !ok {
		return nil, false
	}
	vrfs = slices.Clone(vrfs)
	slices.Sort(vrfs)
	return slices.Compact(vrfs), true
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
