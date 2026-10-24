package cplane

import "net/netip"

// PathKey identifies an input path. It is not a forwarding key: paths with
// different RDs, peers or ADD-PATH IDs can still compete for the same headend.
type PathKey struct {
	Family string
	RD     string
	Prefix string
	Peer   string
	PathID uint32
}

// Key supports IPv4/IPv6 unicast and VPN prefix routes. EVPN and MUP need their
// own NLRI identities and are deliberately not represented by this view.
func (r Route) Key() (PathKey, bool) {
	v4 := r.Family == "vpnv4" || r.Family == "ipv4_unicast"
	v6 := r.Family == "vpnv6" || r.Family == "ipv6_unicast"
	if !v4 && !v6 {
		return PathKey{}, false
	}
	prefix, err := netip.ParsePrefix(r.Prefix)
	if err != nil || prefix.Addr().Is4In6() || prefix.Addr().Is4() != v4 {
		return PathKey{}, false
	}
	return PathKey{r.Family, r.RD, prefix.Masked().String(), r.Peer, r.PathID}, true
}

// RouteView maintains accepted BGP prefix routes and a pending-apply flag.
// It does not select a winning path. Use one view for the BGP source, update it
// with every delivered event (including rejected routes), and call Applied only
// after a successful synchronous declaration. A failed declaration stays pending
// so a later tick can retry, without needing another route update.
//
// The zero value is ready for live events. A BGP replay suspends Pending across
// batches and ticks until its end marker; other sources do not reset this view.
// Methods are for the guest's serialized callbacks, not concurrent goroutines.
type RouteView struct {
	// Accept filters advertisements, never withdrawals. Rejected updates remove
	// the previous version of that path, if any. Nil accepts all prefix routes.
	Accept    func(Route) bool
	paths     map[PathKey]Route
	replaying bool
	dirty     bool
}

func (v *RouteView) Update(events []Event) {
	for _, ev := range events {
		switch ev.Kind {
		case EventStartOfReplay:
			if ev.ReplaySource == BGPSource {
				v.paths = nil
				v.replaying, v.dirty = true, true
			}
		case EventEndOfReplay:
			if ev.ReplaySource == BGPSource {
				v.replaying, v.dirty = false, true
			}
		case EventRoute:
			route := ev.Route
			key, ok := route.Key()
			if !ok {
				continue
			}
			if route.Withdraw || (v.Accept != nil && !v.Accept(route)) {
				if _, held := v.paths[key]; held {
					delete(v.paths, key)
					v.dirty = true
				}
				continue
			}
			if v.paths == nil {
				v.paths = make(map[PathKey]Route)
			}
			route.Prefix = key.Prefix
			v.paths[key] = route
			v.dirty = true
		}
	}
}

func (v *RouteView) Pending() bool   { return v.dirty && !v.replaying }
func (v *RouteView) Replaying() bool { return v.replaying }
func (v *RouteView) Applied() {
	if !v.replaying {
		v.dirty = false
	}
}

// Range visits the current view in unspecified order. Do not mutate the view or
// the slices within a Route during iteration. Selection must be independent of
// map iteration order. During replay this view is incomplete.
func (v *RouteView) Range(visit func(PathKey, Route)) {
	for key, route := range v.paths {
		visit(key, route)
	}
}
