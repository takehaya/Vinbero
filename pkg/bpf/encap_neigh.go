package bpf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// ===== Write notification =====

// SetEncapChangeHook installs fn to receive the outer destinations of every
// map write that can add an encapsulation (headend, MUP session, ECMP path,
// SR policy, L2 headend, BD peer, End.B6 SID, service-return circuit); nil
// removes it. fn must not block. The EncapNeighKeeper uses it to resolve a
// new destination at once. TestEncapMapWritersNotify fails when a writer of
// one of those maps does not call encapWrote.
func (m *MapOperations) SetEncapChangeHook(fn func(dsts []netip.Addr)) {
	if fn == nil {
		m.encapHook.Store(nil)
		return
	}
	m.encapHook.Store(&fn)
}

// encapWrote hands the destinations of a write to the hook. A failed write
// may notify too: a destination the maps do not hold is dropped by the
// keeper's next resweep.
func (m *MapOperations) encapWrote(dsts ...netip.Addr) {
	if len(dsts) == 0 {
		return
	}
	if fn := m.encapHook.Load(); fn != nil {
		(*fn)(dsts)
	}
}

// segmentDst is the outer destination a segment becomes, or false for one
// that is never routed (unset, an IPv4-mapped placeholder, multicast).
func segmentDst(seg [IPv6AddrLen]byte) (netip.Addr, bool) {
	a := netip.AddrFrom16(seg)
	if a.IsUnspecified() || a.Is4In6() || a.IsMulticast() {
		return netip.Addr{}, false
	}
	return a, true
}

// headendDst is the outer destination of a headend entry: its first segment.
// A MUP gate (no segments of its own) has none. A policy-steered entry's
// transport SID is the SR policy's own write.
func headendDst(e *HeadendEntry) []netip.Addr {
	if e == nil || e.NumSegments == 0 || e.NumSegments > MaxSegments {
		return nil
	}
	if a, ok := segmentDst(e.Segments[0]); ok {
		return []netip.Addr{a}
	}
	return nil
}

func firstAddr(addrs []netip.Addr) []netip.Addr {
	if len(addrs) == 0 || !addrs[0].Is6() {
		return nil
	}
	return addrs[:1]
}

func ecmpPathDsts(paths []EcmpPath) []netip.Addr {
	var out []netip.Addr
	for _, p := range paths {
		out = append(out, headendDst(p.Entry)...)
	}
	return out
}

func serviceIngressDst(e *ServiceIngressEntry) []netip.Addr {
	if e == nil {
		return nil
	}
	return headendDst(&e.Encap)
}

func isB6Action(action uint8) bool {
	switch vinberov1.Srv6LocalAction(action) {
	case vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_B6,
		vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_B6_ENCAPS:
		return true
	}
	return false
}

// sidPolicyDst is the outer destination of an End.B6 / End.B6.Encaps
// policy; other behaviours encapsulate nothing.
func sidPolicyDst(entry *SidFunctionEntry, aux *SidAuxEntry) []netip.Addr {
	if entry == nil || aux == nil || !isB6Action(entry.Action) {
		return nil
	}
	return headendDst(SidAuxB6PolicyData(aux))
}

// ===== Full walk =====

// EncapDestinations returns every outer IPv6 destination an encapsulation
// can be sent to: the first segment of each headend entry (IPv4 and IPv6
// headends, the MUP sessions, the ECMP paths, the L2 headend circuits and the
// BD peers), the first transport SID of each SR policy, the first segment of
// each End.B6 / End.B6.Encaps policy, the encapsulation of each service-return
// circuit, and the destination of each End.AD cached header. End.AM's next
// destination is not here: it comes from each packet's SRH and is in no map.
// The result is sorted and has no duplicates.
func (m *MapOperations) EncapDestinations() ([]netip.Addr, error) {
	set := map[netip.Addr]struct{}{}
	add := func(dsts []netip.Addr) {
		for _, d := range dsts {
			set[d] = struct{}{}
		}
	}
	var errs []error
	for _, mp := range []*ebpf.Map{
		m.objs.HeadendV4Map, m.objs.HeadendV6Map, m.objs.MupUplinkV4Map, m.objs.MupUplinkV6Map,
		m.objs.EcmpPathMap, m.objs.HeadendL2Map, m.objs.BdPeerMap,
	} {
		var e HeadendEntry
		if err := iterateValues(mp, &e, func() { add(headendDst(&e)) }); err != nil {
			errs = append(errs, err)
		}
	}
	var pol BpfSrPolicyValue
	if err := iterateValues(m.objs.SrPolicyMap, &pol, func() {
		if pol.Len > 0 {
			if a, ok := segmentDst(pol.Segs[0]); ok {
				set[a] = struct{}{}
			}
		}
	}); err != nil {
		errs = append(errs, err)
	}
	var svc ServiceIngressEntry
	if err := iterateValues(m.objs.ServiceIngressMap, &svc, func() { add(serviceIngressDst(&svc)) }); err != nil {
		errs = append(errs, err)
	}
	var ad AdCacheVal
	if err := iterateValues(m.objs.AdCacheMap, &ad, func() {
		// The cached outer IPv6 header, ready to prepend: DA at offset 24.
		if ad.Valid != 0 && ad.HdrLen >= 40 {
			var da [IPv6AddrLen]byte
			copy(da[:], ad.Hdr[24:40])
			if a, ok := segmentDst(da); ok {
				set[a] = struct{}{}
			}
		}
	}); err != nil {
		errs = append(errs, err)
	}
	var sid SidFunctionEntry
	var b6 []uint16
	if err := iterateValues(m.objs.SidFunctionMap, &sid, func() {
		if isB6Action(sid.Action) && sid.AuxIndex != 0 {
			b6 = append(b6, sid.AuxIndex)
		}
	}); err != nil {
		errs = append(errs, err)
	}
	for _, idx := range b6 {
		var aux SidAuxEntry
		if err := m.objs.SidAuxMap.Lookup(uint32(idx), &aux); err != nil {
			errs = append(errs, fmt.Errorf("lookup sid_aux_map[%d]: %w", idx, err))
			continue
		}
		add(headendDst(SidAuxB6PolicyData(&aux)))
	}
	out := make([]netip.Addr, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out, errors.Join(errs...)
}

// iterateValues runs each for every value of mp, decoded into val. Keys are
// read as raw bytes, so one helper serves maps of any key type.
func iterateValues[V any](mp *ebpf.Map, val *V, each func()) error {
	if mp == nil {
		return nil
	}
	key := make([]byte, mp.KeySize())
	it := mp.Iterate()
	for it.Next(key, val) {
		each()
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate %s: %w", mp.String(), err)
	}
	return nil
}

// ===== Resolution =====

// NeighTarget is one underlay next hop: the device and the address whose
// neighbour entry an encapsulation needs.
type NeighTarget struct {
	Ifindex uint32
	IP      net.IP
}

func (t NeighTarget) key() string { return neighKey(t.Ifindex, t.IP) }

func neighKey(ifindex uint32, ip net.IP) string { return fmt.Sprintf("%d/%s", ifindex, ip) }

const mainTableID = 254 // RT_TABLE_MAIN

// mainTable is an LPM index over the main table's IPv6 routes, built from
// one dump per pass.
type mainTable struct {
	byLen map[int]map[netip.Prefix]netlink.Route // the lowest-metric route per prefix
}

func newMainTable(routes []netlink.Route) *mainTable {
	t := &mainTable{byLen: map[int]map[netip.Prefix]netlink.Route{}}
	for _, r := range routes {
		var p netip.Prefix
		if r.Dst == nil {
			p = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
		} else {
			a, ok := netip.AddrFromSlice(r.Dst.IP)
			if !ok {
				continue
			}
			ones, _ := r.Dst.Mask.Size()
			p = netip.PrefixFrom(a.Unmap(), ones).Masked()
		}
		if !p.Addr().Is6() {
			continue
		}
		bucket := t.byLen[p.Bits()]
		if bucket == nil {
			bucket = map[netip.Prefix]netlink.Route{}
			t.byLen[p.Bits()] = bucket
		}
		if cur, ok := bucket[p]; !ok || r.Priority < cur.Priority {
			bucket[p] = r
		}
	}
	return t
}

// lookup returns the main-table route the direct (BPF_FIB_LOOKUP_TBID)
// lookup selects for dst: the longest prefix, the lowest metric.
func (t *mainTable) lookup(dst netip.Addr) (netlink.Route, bool) {
	for bits := 128; bits >= 0; bits-- {
		bucket := t.byLen[bits]
		if bucket == nil {
			continue
		}
		p, _ := dst.Prefix(bits)
		if r, ok := bucket[p]; ok {
			return r, true
		}
	}
	return netlink.Route{}, false
}

// routeTargets are the next hops of a route: every member of a multipath
// route, the gateway of a gatewayed one, dst itself for an on-link one. A
// blackhole, prohibit or unreachable route has none, and that is not an
// error. nhObject reports a unicast route whose next hops the netlink
// library cannot read (a nexthop object, RTA_NH_ID, with
// net.ipv4.nexthop_compat_mode=0).
func routeTargets(r netlink.Route, dst net.IP) (targets []NeighTarget, nhObject bool) {
	if r.Type != unix.RTN_UNICAST {
		return nil, false
	}
	add := func(ifindex int, gw net.IP) {
		if ifindex <= 1 {
			return
		}
		ip := gw
		if ip == nil {
			ip = dst
		}
		targets = append(targets, NeighTarget{Ifindex: uint32(ifindex), IP: ip})
	}
	if len(r.MultiPath) > 0 {
		for _, nh := range r.MultiPath {
			add(nh.LinkIndex, nh.Gw)
		}
		return targets, false
	}
	if r.LinkIndex == 0 && r.Gw == nil {
		return nil, true
	}
	add(r.LinkIndex, r.Gw)
	return targets, false
}

// isRejectRouteErr reports the errors a route lookup returns for a
// destination with no route or a reject route (blackhole EINVAL, prohibit
// EACCES, unreachable EHOSTUNREACH / ENETUNREACH): none is a failure.
func isRejectRouteErr(err error) bool {
	for _, e := range []error{unix.EINVAL, unix.EACCES, unix.EHOSTUNREACH, unix.ENETUNREACH, unix.ESRCH} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// resolver resolves destinations the two ways the data plane looks the outer
// header up: a tenant AC's encapsulation in the main table directly (the
// mainTable index, from one dump per pass), the global VRF's through the ip
// rules (a rule-based route lookup, as a host-originated packet meets them).
// Both results' next hops are kept.
type resolver struct {
	dumpMain func() ([]netlink.Route, error)
	ruleGet  func(dst net.IP) ([]netlink.Route, error)
}

func defaultResolver() resolver {
	return resolver{
		dumpMain: func() ([]netlink.Route, error) {
			return netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{Table: mainTableID}, netlink.RT_FILTER_TABLE)
		},
		ruleGet: func(dst net.IP) ([]netlink.Route, error) {
			return netlink.RouteGetWithOptions(dst, &netlink.RouteGetOptions{FIBMatch: true})
		},
	}
}

// resolve returns the next hops of each destination. nhObject reports a
// route whose next hops could not be read (see routeTargets).
func (r resolver) resolve(dsts []netip.Addr) (map[netip.Addr][]NeighTarget, bool, error) {
	out := make(map[netip.Addr][]NeighTarget, len(dsts))
	if len(dsts) == 0 {
		return out, false, nil
	}
	routes, err := r.dumpMain()
	if err != nil {
		return nil, false, fmt.Errorf("dump the main table: %w", err)
	}
	main := newMainTable(routes)
	nhObject := false
	var errs []error
	for _, d := range dsts {
		ip := net.IP(d.AsSlice())
		seen := map[string]struct{}{}
		var targets []NeighTarget
		addAll := func(ts []NeighTarget, nh bool) {
			nhObject = nhObject || nh
			for _, t := range ts {
				if _, dup := seen[t.key()]; !dup {
					seen[t.key()] = struct{}{}
					targets = append(targets, t)
				}
			}
		}
		if rt, ok := main.lookup(d); ok {
			addAll(routeTargets(rt, ip))
		}
		rs, err := r.ruleGet(ip)
		switch {
		case err == nil:
			for _, rt := range rs {
				addAll(routeTargets(rt, ip))
			}
		case isRejectRouteErr(err):
		default:
			errs = append(errs, fmt.Errorf("route lookup for %s: %w", d, err))
		}
		out[d] = targets
	}
	return out, nhObject, errors.Join(errs...)
}

// ===== Neighbour entries =====

// neighOps is the neighbour-table surface of the keeper; tests replace it.
type neighOps struct {
	list       func(ifindex, family int) ([]netlink.Neigh, error)
	setManaged func(ifindex uint32, ip net.IP) error
	del        func(n netlink.Neigh) error
}

func kernelNeighOps() neighOps {
	return neighOps{
		list: netlink.NeighList,
		setManaged: func(ifindex uint32, ip net.IP) error {
			return netlink.NeighSet(&netlink.Neigh{
				LinkIndex: int(ifindex), Family: ipFamily(ip), IP: ip,
				State: netlink.NUD_NONE, Flags: netlink.NTF_EXT_LEARNED, FlagsExt: netlink.NTF_EXT_MANAGED,
			})
		},
		del: func(n netlink.Neigh) error {
			// Only the key: the kernel deletes the entry whatever flags it
			// carries.
			return netlink.NeighDel(&netlink.Neigh{LinkIndex: n.LinkIndex, Family: ipFamily(n.IP), IP: n.IP})
		},
	}
}

func ipFamily(ip net.IP) int {
	if ip.To4() != nil {
		return netlink.FAMILY_V4
	}
	return netlink.FAMILY_V6
}

// bumNeighClaims holds the next hops KeepNeighResolved made managed for the
// BUM flood slots. The keeper never gives those back.
var bumNeighClaims sync.Map

func neighStatic(n netlink.Neigh) bool {
	return n.State&(netlink.NUD_PERMANENT|netlink.NUD_NOARP) != 0
}

func neighManaged(n netlink.Neigh) bool { return n.FlagsExt&netlink.NTF_EXT_MANAGED != 0 }

// ===== Keeper =====

// EncapNeighKeeper keeps the underlay next hop of every encapsulation
// resolved, so no encapsulation depends on other traffic to resolve it.
//
// An encapsulation whose next hop has no neighbour entry is handed to the
// kernel (XDP_PASS) to resolve it. From a port enslaved to a VRF device the
// kernel looks that packet up in the VRF table, where the unreachable default
// drops it, so the neighbour would never be solicited; the L2 and
// service-return paths drop such a packet outright. The keeper makes each
// next hop a managed neighbour (NTF_EXT_MANAGED with extern_learn): the
// kernel resolves it and keeps it resolved whether or not traffic uses it.
//
// The keeper holds the set of destinations and their next hops:
//
//   - a map write hands it the destinations it wrote (SetEncapChangeHook),
//     and only a destination not yet in the set is resolved;
//   - a route, nexthop-object or ip-rule change re-resolves the set;
//   - a deleted neighbour entry the keeper holds is made managed again;
//   - at start and every resweep, a full walk of the maps (EncapDestinations)
//     replaces the set: it picks up writers that do not notify (a plugin
//     writing a map directly, the data plane's End.AD cache) and drops
//     destinations no entry uses any more.
//
// A next hop no destination uses any more is given back: the managed entry
// the keeper made is deleted. Entries that were static (permanent, noarp),
// already managed when the keeper first saw them, or kept for the BUM flood
// slots are left alone. Each pass reads the neighbour table once per
// device and family.
type EncapNeighKeeper struct {
	walk    func() ([]netip.Addr, error)
	res     resolver
	neigh   neighOps
	logger  *zap.Logger
	resweep time.Duration

	wake chan struct{}
	// subRoutes subscribes to route, nexthop-object and ip-rule changes
	// (shared with the BUM devmap sync); tests replace it.
	subRoutes func() (*routeSub, error)

	// pmu guards what the events ask for; Notify takes only it, so a map
	// writer never waits for a pass.
	pmu     sync.Mutex
	pending map[netip.Addr]struct{} // written, not yet resolved
	reroute bool                    // routes changed: re-resolve the set
	rekeep  bool                    // a kept entry was deleted

	// mu guards the set and the owned entries, and is held by a pass.
	mu sync.Mutex
	// dests is the destination set with each one's next hops.
	dests map[netip.Addr][]NeighTarget
	// owned are the next hops whose managed entry this keeper made.
	owned map[string]NeighTarget
	// warned holds what was logged, so a lasting condition logs once.
	warned map[string]string
}

// encapNeighResweep is the interval of the full walk.
const encapNeighResweep = 30 * time.Second

// encapNeighDebounce coalesces a burst of writes or route changes into one
// pass.
const encapNeighDebounce = 200 * time.Millisecond

// NewEncapNeighKeeper builds a keeper over mapOps.
func NewEncapNeighKeeper(mapOps *MapOperations, logger *zap.Logger) *EncapNeighKeeper {
	if logger == nil {
		logger = zap.NewNop()
	}
	k := &EncapNeighKeeper{
		walk:    mapOps.EncapDestinations,
		res:     defaultResolver(),
		neigh:   kernelNeighOps(),
		logger:  logger.Named("encap.neigh"),
		resweep: encapNeighResweep,
		wake:    make(chan struct{}, 1),
		pending: map[netip.Addr]struct{}{},
		dests:   map[netip.Addr][]NeighTarget{},
		owned:   map[string]NeighTarget{},
		warned:  map[string]string{},
	}
	k.subRoutes = func() (*routeSub, error) { return subscribeRouteEvents(k.logger, "encap next hops") }
	return k
}

// Notify queues written destinations. It never blocks.
func (k *EncapNeighKeeper) Notify(dsts []netip.Addr) {
	k.pmu.Lock()
	for _, d := range dsts {
		k.pending[d] = struct{}{}
	}
	k.pmu.Unlock()
	k.poke()
}

// takeEvents returns and clears what the events since the last pass asked
// for.
func (k *EncapNeighKeeper) takeEvents() (pending map[netip.Addr]struct{}, reroute, rekeep bool) {
	k.pmu.Lock()
	defer k.pmu.Unlock()
	pending, reroute, rekeep = k.pending, k.reroute, k.rekeep
	k.pending = map[netip.Addr]struct{}{}
	k.reroute, k.rekeep = false, false
	return pending, reroute, rekeep
}

func (k *EncapNeighKeeper) setFlag(reroute, rekeep bool) {
	k.pmu.Lock()
	k.reroute = k.reroute || reroute
	k.rekeep = k.rekeep || rekeep
	k.pmu.Unlock()
}

func (k *EncapNeighKeeper) poke() {
	select {
	case k.wake <- struct{}{}:
	default:
	}
}

func (k *EncapNeighKeeper) warnOnce(key, msg string, err error, fields ...zap.Field) {
	text := ""
	if err != nil {
		text = err.Error()
	}
	if v, ok := k.warned[key]; ok && v == text {
		return
	}
	k.warned[key] = text
	if err != nil {
		fields = append(fields, zap.Error(err))
	}
	k.logger.Warn(msg, fields...)
}

// Sweep walks the maps, replaces the destination set with what they hold,
// resolves all of it and brings the neighbour entries in line. It returns
// the next hops kept.
func (k *EncapNeighKeeper) Sweep() ([]NeighTarget, error) {
	// Events from before the walk are covered by it.
	_, _, _ = k.takeEvents()
	dsts, werr := k.walk()
	k.mu.Lock()
	defer k.mu.Unlock()
	if werr != nil && len(dsts) == 0 {
		// A walk that read nothing must not release every next hop.
		return k.targetsLocked(), werr
	}
	err := k.resolveLocked(dsts, true)
	return k.targetsLocked(), errors.Join(werr, err)
}

// pass runs what the events since the last pass asked for.
func (k *EncapNeighKeeper) pass() error {
	pending, reroute, rekeep := k.takeEvents()
	k.mu.Lock()
	defer k.mu.Unlock()
	var dsts []netip.Addr
	if reroute {
		for d := range k.dests {
			dsts = append(dsts, d)
		}
	}
	for d := range pending {
		if _, known := k.dests[d]; !known {
			dsts = append(dsts, d)
		}
	}
	if len(dsts) == 0 && !rekeep {
		return nil
	}
	if len(dsts) == 0 {
		return k.applyLocked()
	}
	return k.resolveLocked(dsts, false)
}

// resolveLocked resolves dsts and merges them into the set: replace makes
// dsts the whole set (a destination not in it is dropped), otherwise they
// are added. Then the neighbour entries are brought in line.
func (k *EncapNeighKeeper) resolveLocked(dsts []netip.Addr, replace bool) error {
	resolved, nhObject, rerr := k.res.resolve(dsts)
	if resolved == nil {
		k.warnOnce("resolve", "cannot resolve the next hops of encapsulation destinations", rerr)
		return rerr
	}
	if rerr != nil {
		k.warnOnce("resolve", "cannot resolve the next hop of some encapsulation destinations", rerr)
	} else {
		delete(k.warned, "resolve")
	}
	if nhObject {
		k.warnOnce("nhobject", "an encapsulation destination is routed through a nexthop object whose next hops "+
			"vinberod cannot read; set net.ipv4.nexthop_compat_mode=1 (it covers IPv6 too) so its neighbour is kept resolved", nil)
	}
	if replace {
		k.dests = resolved
	} else {
		for d, ts := range resolved {
			k.dests[d] = ts
		}
	}
	return errors.Join(rerr, k.applyLocked())
}

// applyLocked makes every next hop of the set managed and gives back the
// owned ones no destination uses, reading each device's neighbours once.
func (k *EncapNeighKeeper) applyLocked() error {
	wanted := map[string]NeighTarget{}
	for _, ts := range k.dests {
		for _, t := range ts {
			wanted[t.key()] = t
		}
	}
	type group struct{ ifindex, family int }
	byDev := map[group][]NeighTarget{}
	for _, t := range wanted {
		g := group{int(t.Ifindex), ipFamily(t.IP)}
		byDev[g] = append(byDev[g], t)
	}
	var release []NeighTarget
	for key, t := range k.owned {
		if _, ok := wanted[key]; !ok {
			release = append(release, t)
			g := group{int(t.Ifindex), ipFamily(t.IP)}
			if _, ok := byDev[g]; !ok {
				byDev[g] = nil
			}
		}
	}
	dumps := map[group]map[string]netlink.Neigh{}
	var errs []error
	for g := range byDev {
		neighs, err := k.neigh.list(g.ifindex, g.family)
		if err != nil {
			errs = append(errs, fmt.Errorf("list the neighbours of %d: %w", g.ifindex, err))
			continue
		}
		m := make(map[string]netlink.Neigh, len(neighs))
		for _, n := range neighs {
			m[n.IP.String()] = n
		}
		dumps[g] = m
	}
	for g, ts := range byDev {
		dump, ok := dumps[g]
		if !ok {
			continue
		}
		for _, t := range ts {
			key := t.key()
			if n, exists := dump[t.IP.String()]; exists && (neighStatic(n) || neighManaged(n)) {
				continue // static, or already managed (by this keeper or someone else)
			}
			if err := k.neigh.setManaged(t.Ifindex, t.IP); err != nil {
				k.warnOnce("keep "+key, "cannot keep an encapsulation next hop resolved", err,
					zap.Uint32("ifindex", t.Ifindex), zap.Stringer("nexthop", t.IP))
				errs = append(errs, err)
				continue
			}
			delete(k.warned, "keep "+key)
			if _, mine := k.owned[key]; !mine {
				k.logger.Info("keeping an encapsulation next hop resolved",
					zap.Uint32("ifindex", t.Ifindex), zap.Stringer("nexthop", t.IP))
			}
			k.owned[key] = t
		}
	}
	for _, t := range release {
		key := t.key()
		delete(k.owned, key)
		if _, bum := bumNeighClaims.Load(key); bum {
			continue
		}
		dump, ok := dumps[group{int(t.Ifindex), ipFamily(t.IP)}]
		if !ok {
			continue
		}
		n, exists := dump[t.IP.String()]
		if !exists || neighStatic(n) || !neighManaged(n) {
			continue // gone, or someone changed it since
		}
		if err := k.neigh.del(n); err != nil && !errors.Is(err, unix.ENOENT) {
			k.warnOnce("release "+key, "cannot give back an encapsulation next hop", err,
				zap.Uint32("ifindex", t.Ifindex), zap.Stringer("nexthop", t.IP))
			errs = append(errs, err)
			continue
		}
		k.logger.Info("encapsulation next hop no longer used; managed neighbour removed",
			zap.Uint32("ifindex", t.Ifindex), zap.Stringer("nexthop", t.IP))
	}
	return errors.Join(errs...)
}

func (k *EncapNeighKeeper) targetsLocked() []NeighTarget {
	seen := map[string]NeighTarget{}
	for _, ts := range k.dests {
		for _, t := range ts {
			seen[t.key()] = t
		}
	}
	out := make([]NeighTarget, 0, len(seen))
	for _, t := range seen {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

func (k *EncapNeighKeeper) isOwned(ifindex int, ip net.IP) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	_, ok := k.owned[neighKey(uint32(ifindex), ip)]
	return ok
}

// Run sweeps once and then follows writes, route changes, deleted entries
// and the resweep until ctx ends. It returns after the first sweep; the
// watch runs in the background.
func (k *EncapNeighKeeper) Run(ctx context.Context) error {
	if _, err := k.Sweep(); err != nil {
		k.logger.Warn("initial encapsulation next-hop sweep incomplete", zap.Error(err))
	}
	routes, err := k.subRoutes()
	if err != nil {
		return fmt.Errorf("subscribe to route updates: %w", err)
	}
	neighs, err := k.subscribeNeighs()
	if err != nil {
		close(routes.done)
		return err
	}
	go k.watch(ctx, routes, neighs)
	return nil
}

type neighSub struct {
	updates chan netlink.NeighUpdate
	done    chan struct{}
}

func (k *EncapNeighKeeper) subscribeNeighs() (*neighSub, error) {
	s := &neighSub{updates: make(chan netlink.NeighUpdate, 256), done: make(chan struct{})}
	if err := netlink.NeighSubscribeWithOptions(s.updates, s.done, netlink.NeighSubscribeOptions{
		ErrorCallback: func(err error) { k.logger.Warn("neighbour subscription failed", zap.Error(err)) },
	}); err != nil {
		close(s.done)
		return nil, fmt.Errorf("subscribe to neighbour updates: %w", err)
	}
	return s, nil
}

func (k *EncapNeighKeeper) watch(ctx context.Context, routes *routeSub, neighs *neighSub) {
	defer func() {
		if routes != nil {
			close(routes.done)
		}
		if neighs != nil {
			close(neighs.done)
		}
	}()
	resweep := time.NewTicker(k.resweep)
	defer resweep.Stop()
	timer := time.NewTimer(encapNeighDebounce)
	timer.Stop()
	var fire <-chan time.Time
	pending := func() {
		if fire == nil {
			timer.Reset(encapNeighDebounce)
			fire = timer.C
		}
	}
	reroute := func() {
		k.setFlag(true, false)
		pending()
	}
	for {
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case _, ok := <-routes.routes:
			if !ok {
				if routes = resubscribeRouteEvents(ctx, routes, k.subRoutes, k.logger, "encap next hops"); routes == nil {
					return
				}
			}
			reroute()
		case _, ok := <-routes.nexthops:
			if !ok {
				if routes = resubscribeRouteEvents(ctx, routes, k.subRoutes, k.logger, "encap next hops"); routes == nil {
					return
				}
			}
			reroute()
		case u, ok := <-neighs.updates:
			if !ok {
				close(neighs.done)
				neighs = nil
				for neighs == nil {
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Second):
					}
					var err error
					if neighs, err = k.subscribeNeighs(); err != nil {
						k.logger.Warn("neighbour resubscribe failed; retrying", zap.Error(err))
					}
				}
				k.setFlag(false, true)
				pending()
				continue
			}
			if u.Type == unix.RTM_DELNEIGH && k.isOwned(u.LinkIndex, u.IP) {
				k.setFlag(false, true)
				pending()
			}
		case <-k.wake:
			pending()
		case <-resweep.C:
			if _, err := k.Sweep(); err != nil {
				k.logger.Debug("encapsulation next-hop sweep incomplete", zap.Error(err))
			}
		case <-fire:
			fire = nil
			if err := k.pass(); err != nil {
				k.logger.Debug("encapsulation next-hop pass incomplete", zap.Error(err))
			}
		}
	}
}
