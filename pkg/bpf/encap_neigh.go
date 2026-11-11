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
	"github.com/takehaya/vinbero/pkg/netlinksub"
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
	// A nil receiver is a caller whose write was refused before any map
	// was touched; the deferred notification has nothing to say.
	if m == nil || len(dsts) == 0 {
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
//   - a deleted neighbour entry of a next hop in the set, or of one the
//     keeper made, is made managed again, whoever made it managed first: a
//     device that loses its carrier flushes its neighbours, managed ones
//     included;
//   - when a device with a next hop of the set gets its carrier back, the
//     unresolved managed entries on it are marked managed again, which makes
//     the kernel probe a failed one at once instead of at its next periodic
//     re-probe of managed entries (interval_probe_time_ms, 5 s by default).
//     The mark does not restart an entry that is still probing: it resolves
//     at its next solicitation, within the retransmit interval (1 s by
//     default), or fails then; the first failure on the device within
//     encapNeighCarrierWindow of the carrier coming back asks for one more
//     mark;
//   - at start and every resweep, a full walk of the maps (EncapDestinations)
//     picks up writers that do not notify (a plugin writing a map directly,
//     the data plane's End.AD cache) and drops destinations no entry uses
//     any more, conservatively (see Sweep).
//
// A next hop no destination uses any more is given back: the managed entry
// the keeper made is deleted. Entries that were static (permanent, noarp),
// already managed when the keeper first saw them, or kept for the BUM flood
// slots are left alone. An entry the keeper made again after a flush is its
// own, unless the BUM flood slots hold it. Each pass reads the neighbour table once per
// device and family.
type EncapNeighKeeper struct {
	walk    func() ([]netip.Addr, error)
	res     resolver
	neigh   neighOps
	logger  *zap.Logger
	resweep time.Duration

	wake chan struct{}
	// subRoutes subscribes to route, nexthop-object and ip-rule changes
	// (shared with the BUM devmap sync), subNeighs to neighbour changes and
	// subLinks to link changes; linkList lists the devices for the carrier
	// state after the link subscription comes back. Tests replace them.
	subRoutes func() (*routeSub, error)
	subNeighs func() (*neighSub, error)
	subLinks  func() (*linkSub, error)
	linkList  func() ([]netlink.Link, error)
	// routeSt, neighSt and linkSt follow the three subscriptions and log
	// their state changes.
	routeSt, neighSt, linkSt *netlinksub.State

	// pmu guards what the events ask for; Notify takes only it, so a map
	// writer never waits for a pass.
	pmu     sync.Mutex
	pending map[netip.Addr]struct{} // written, not yet resolved
	reroute bool                    // routes changed: re-resolve the set
	rekeep  bool                    // a kept entry was deleted
	relink  map[uint32]struct{}     // devices whose carrier came back
	// walkNotified collects what is written while a sweep runs, from the
	// start of its walk to the end of its releases (nil when no sweep
	// runs): the sweep keeps it whatever the walk saw.
	walkNotified map[netip.Addr]struct{}

	// mu guards the set and the owned entries, and is held by a pass.
	mu sync.Mutex
	// missed counts, per destination, the complete walks in a row that did
	// not see it; it is dropped at sweepsBeforeRelease.
	missed map[netip.Addr]int
	// dests is the destination set with each one's next hops.
	dests map[netip.Addr][]NeighTarget
	// dropped holds, while a sweep runs, the destinations it drops with
	// their next hops, so that one written before its next hop is given back
	// goes back into the set instead (releaseLocked).
	dropped map[netip.Addr][]NeighTarget
	// beforeReleaseDel, when set (tests), runs right before a released
	// entry is deleted, with pmu held.
	beforeReleaseDel func(NeighTarget)
	// owned are the next hops whose managed entry this keeper made.
	owned map[string]NeighTarget
	// wanted and wantedDevs are the next hops of the set and their
	// devices, as of the last pass; the watch reads them.
	wanted     map[string]struct{}
	wantedDevs map[uint32]struct{}
	// warned holds what was logged, so a lasting condition logs once.
	warned map[string]string
}

// encapNeighResweep is the interval of the full walk.
const encapNeighResweep = 30 * time.Second

// encapNeighDebounce coalesces a burst of writes or route changes into one
// pass.
const encapNeighDebounce = 200 * time.Millisecond

// encapNeighCarrierWindow is how long after a carrier came back the first
// failure of a kept entry on the device makes the keeper mark the device's
// unresolved entries once more. An entry whose last solicitation went out
// before the carrier came back fails one retransmit interval after it (1 s
// by default); the mark at the carrier-up found it still probing and did
// nothing.
const encapNeighCarrierWindow = 10 * time.Second

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
		relink:  map[uint32]struct{}{},
		dests:   map[netip.Addr][]NeighTarget{},
		missed:  map[netip.Addr]int{},
		owned:   map[string]NeighTarget{},
		warned:  map[string]string{},
	}
	k.routeSt = netlinksub.New(k.logger, "encap next hops: routes")
	k.neighSt = netlinksub.New(k.logger, "encap next hops: neighbours")
	k.linkSt = netlinksub.New(k.logger, "encap next hops: links")
	k.subRoutes = func() (*routeSub, error) { return subscribeRouteEvents(k.routeSt) }
	k.subNeighs = k.subscribeNeighs
	k.subLinks = k.subscribeLinks
	k.linkList = netlink.LinkList
	return k
}

// Notify queues written destinations. It never blocks.
func (k *EncapNeighKeeper) Notify(dsts []netip.Addr) {
	k.pmu.Lock()
	for _, d := range dsts {
		k.pending[d] = struct{}{}
		if k.walkNotified != nil {
			k.walkNotified[d] = struct{}{}
		}
	}
	k.pmu.Unlock()
	k.poke()
}

// keeperEvents is what the events since the last pass asked for.
type keeperEvents struct {
	pending         map[netip.Addr]struct{}
	reroute, rekeep bool
	relink          map[uint32]struct{}
}

// takeEvents returns and clears what the events since the last pass asked
// for.
func (k *EncapNeighKeeper) takeEvents() keeperEvents {
	k.pmu.Lock()
	defer k.pmu.Unlock()
	ev := keeperEvents{pending: k.pending, reroute: k.reroute, rekeep: k.rekeep, relink: k.relink}
	k.pending = map[netip.Addr]struct{}{}
	k.relink = map[uint32]struct{}{}
	k.reroute, k.rekeep = false, false
	return ev
}

// carrierUp queues a re-probe of the unresolved next hops on ifindex.
func (k *EncapNeighKeeper) carrierUp(ifindex uint32) {
	k.pmu.Lock()
	k.relink[ifindex] = struct{}{}
	k.pmu.Unlock()
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

// sweepsBeforeRelease is how many complete walks in a row must miss a
// destination before it is dropped (and a next hop only it used is given
// back): a destination that moves between maps while a walk runs, or that
// one walk misses for any other reason, keeps its neighbour.
const sweepsBeforeRelease = 2

// Sweep walks the maps, brings the destination set in line with what they
// hold, resolves all of it and brings the neighbour entries in line. It
// returns the next hops kept.
//
// Pruning is conservative. A destination leaves the set only after
// sweepsBeforeRelease complete walks in a row did not see it, and a
// destination written while a walk runs counts as seen by it. A dropped
// destination written after the walk and before its next hop's entry is
// deleted goes back into the set and keeps the entry; one written after the
// delete is resolved again by the next pass (releaseLocked). A walk that failed
// part-way may add destinations, never remove them.
func (k *EncapNeighKeeper) Sweep() ([]NeighTarget, error) {
	// Events from before the walk are covered by it, except a carrier that
	// came back; writes from its start to the end of the releases are
	// collected.
	relink := k.takeEvents().relink
	k.pmu.Lock()
	k.walkNotified = map[netip.Addr]struct{}{}
	k.pmu.Unlock()
	defer func() {
		k.pmu.Lock()
		k.walkNotified = nil
		k.pmu.Unlock()
	}()
	dsts, werr := k.walk()
	k.pmu.Lock()
	notified := make(map[netip.Addr]struct{}, len(k.walkNotified))
	for d := range k.walkNotified {
		notified[d] = struct{}{}
	}
	k.pmu.Unlock()

	k.mu.Lock()
	defer k.mu.Unlock()
	defer func() { k.dropped = nil }()
	seen := make(map[netip.Addr]struct{}, len(dsts)+len(notified))
	for _, d := range dsts {
		seen[d] = struct{}{}
	}
	for d := range notified {
		seen[d] = struct{}{}
	}
	list := make([]netip.Addr, 0, len(seen))
	for d := range seen {
		list = append(list, d)
		delete(k.missed, d)
	}
	if werr != nil {
		// Incomplete: add and re-resolve what was seen, keep the rest.
		err := k.resolveLocked(list, false, relink)
		return k.targetsLocked(), errors.Join(werr, err)
	}
	for d := range k.dests {
		if _, ok := seen[d]; ok {
			continue
		}
		k.missed[d]++
		if k.missed[d] < sweepsBeforeRelease {
			list = append(list, d) // missed once: kept for now
			continue
		}
		delete(k.missed, d)
		if k.dropped == nil {
			k.dropped = map[netip.Addr][]NeighTarget{}
		}
		k.dropped[d] = k.dests[d]
	}
	err := k.resolveLocked(list, true, relink)
	return k.targetsLocked(), err
}

// pass runs what the events since the last pass asked for.
func (k *EncapNeighKeeper) pass() error {
	ev := k.takeEvents()
	k.mu.Lock()
	defer k.mu.Unlock()
	var dsts []netip.Addr
	if ev.reroute {
		for d := range k.dests {
			dsts = append(dsts, d)
		}
	}
	for d := range ev.pending {
		delete(k.missed, d) // written again: in use
		if _, known := k.dests[d]; !known {
			dsts = append(dsts, d)
		}
	}
	if len(dsts) == 0 && !ev.rekeep && len(ev.relink) == 0 {
		return nil
	}
	if len(dsts) == 0 {
		return k.applyLocked(ev.relink)
	}
	return k.resolveLocked(dsts, false, ev.relink)
}

// resolveLocked resolves dsts and merges them into the set: replace makes
// dsts the whole set (a destination not in it is dropped), otherwise they
// are added. Then the neighbour entries are brought in line (applyLocked,
// with relink).
func (k *EncapNeighKeeper) resolveLocked(dsts []netip.Addr, replace bool, relink map[uint32]struct{}) error {
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
	return errors.Join(rerr, k.applyLocked(relink))
}

// applyLocked makes every next hop of the set managed and gives back the
// owned ones no destination uses, reading each device's neighbours once. On
// the devices in relink, whose carrier came back, it marks the unresolved
// managed entries managed again (remarkAfterCarrier).
func (k *EncapNeighKeeper) applyLocked(relink map[uint32]struct{}) error {
	wanted := map[string]NeighTarget{}
	for _, ts := range k.dests {
		for _, t := range ts {
			wanted[t.key()] = t
		}
	}
	k.wanted = make(map[string]struct{}, len(wanted))
	k.wantedDevs = map[uint32]struct{}{}
	byDev := map[neighGroup][]NeighTarget{}
	for key, t := range wanted {
		k.wanted[key] = struct{}{}
		k.wantedDevs[t.Ifindex] = struct{}{}
		g := neighGroup{int(t.Ifindex), ipFamily(t.IP)}
		byDev[g] = append(byDev[g], t)
	}
	var release []NeighTarget
	for key, t := range k.owned {
		if _, ok := wanted[key]; !ok {
			release = append(release, t)
			g := neighGroup{int(t.Ifindex), ipFamily(t.IP)}
			if _, ok := byDev[g]; !ok {
				byDev[g] = nil
			}
		}
	}
	dumps := map[neighGroup]map[string]netlink.Neigh{}
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
			n, exists := dump[t.IP.String()]
			if exists && neighStatic(n) {
				continue
			}
			if exists && neighManaged(n) {
				// Already managed, by this keeper or someone else.
				if _, up := relink[t.Ifindex]; up && remarkAfterCarrier(n) {
					if err := k.neigh.setManaged(t.Ifindex, t.IP); err != nil {
						k.logger.Debug("cannot re-probe an encapsulation next hop after its carrier came back",
							zap.Uint32("ifindex", t.Ifindex), zap.Stringer("nexthop", t.IP), zap.Error(err))
					}
				}
				continue
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
	// Ownership ends only when the entry is gone or is no longer the
	// keeper's to remove; a release whose dump or delete failed stays owned
	// and is retried by a later pass.
	usedBy := map[string][]netip.Addr{}
	for d, ts := range k.dropped {
		for _, t := range ts {
			usedBy[t.key()] = append(usedBy[t.key()], d)
		}
	}
	for _, t := range release {
		if err := k.releaseLocked(t, usedBy[t.key()], dumps); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// remarkAfterCarrier reports whether a managed entry is marked managed again
// when its device gets its carrier back: one that is not resolved and
// carries the flags the mark sets, so that the mark changes nothing but its
// state. The kernel keeps the state of a managed entry it marks and probes
// it (neigh_event_send): a failed one at once, one still probing at its next
// solicitation as before. A resolved entry needs nothing.
func remarkAfterCarrier(n netlink.Neigh) bool {
	return n.State&nudValid == 0 && n.Flags&netlink.NTF_EXT_LEARNED != 0 && neighManaged(n)
}

// nudValid is the kernel's NUD_VALID: the states with a usable link-layer
// address.
const nudValid = netlink.NUD_PERMANENT | netlink.NUD_NOARP | netlink.NUD_REACHABLE |
	netlink.NUD_PROBE | netlink.NUD_STALE | netlink.NUD_DELAY

// neighGroup is one device and family, the unit of a neighbour list.
type neighGroup struct{ ifindex, family int }

// releaseLocked gives back one owned next hop no destination of the set
// uses; droppedUsers are the destinations this sweep drops that used it.
// The check for a write of one of them and the delete of the entry both run
// under pmu, the lock Notify takes, so a write lands either before the check
// (the destination goes back into the set and the entry stays) or after the
// delete (the next pass resolves the destination again, as a new one). A
// release is rare and the delete is one netlink call, so that is as long as
// a writer can wait. Callers hold mu.
func (k *EncapNeighKeeper) releaseLocked(t NeighTarget, droppedUsers []netip.Addr, dumps map[neighGroup]map[string]netlink.Neigh) error {
	k.pmu.Lock()
	defer k.pmu.Unlock()
	key := t.key()
	if k.rescuePLocked(droppedUsers) {
		return nil // written again since the walk: still in use
	}
	if _, bum := bumNeighClaims.Load(key); bum {
		delete(k.owned, key) // the BUM flood slots hold it now
		return nil
	}
	dump, ok := dumps[neighGroup{int(t.Ifindex), ipFamily(t.IP)}]
	if !ok {
		return nil // the list failed: retried later
	}
	n, exists := dump[t.IP.String()]
	if !exists || neighStatic(n) || !neighManaged(n) {
		delete(k.owned, key) // gone, or someone changed it since
		return nil
	}
	if k.beforeReleaseDel != nil {
		k.beforeReleaseDel(t)
	}
	if err := k.neigh.del(n); err != nil && !errors.Is(err, unix.ENOENT) {
		k.warnOnce("release "+key, "cannot give back an encapsulation next hop", err,
			zap.Uint32("ifindex", t.Ifindex), zap.Stringer("nexthop", t.IP))
		return err // still owned: retried later
	}
	delete(k.owned, key)
	delete(k.warned, "release "+key)
	k.logger.Info("encapsulation next hop no longer used; managed neighbour removed",
		zap.Uint32("ifindex", t.Ifindex), zap.Stringer("nexthop", t.IP))
	return nil
}

// rescuePLocked puts back into the set, with their next hops, the dropped
// destinations among dsts that were written since the sweep's walk began
// (queued, or collected by the sweep), and reports whether there was one.
// A rescue asks for one more pass, which makes any next hop of the rescued
// destinations released earlier in this one again. Callers hold mu and pmu.
func (k *EncapNeighKeeper) rescuePLocked(dsts []netip.Addr) bool {
	rescued := false
	for _, d := range dsts {
		_, queued := k.pending[d]
		_, collected := k.walkNotified[d]
		if queued || collected {
			k.dests[d] = k.dropped[d]
			for _, t := range k.dests[d] {
				k.wanted[t.key()] = struct{}{}
				k.wantedDevs[t.Ifindex] = struct{}{}
			}
			rescued = true
		}
	}
	if rescued {
		k.rekeep = true
		k.poke() // never blocks
	}
	return rescued
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

// keepsNeigh reports whether a deleted entry is to be made again: the next
// hop is in the set, whoever made its entry, or the keeper made it.
func (k *EncapNeighKeeper) keepsNeigh(ifindex int, ip net.IP) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	key := neighKey(uint32(ifindex), ip)
	_, wanted := k.wanted[key]
	_, owned := k.owned[key]
	return wanted || owned
}

// hasNexthopsOn reports whether a next hop of the set is on ifindex.
func (k *EncapNeighKeeper) hasNexthopsOn(ifindex int) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	_, ok := k.wantedDevs[uint32(ifindex)]
	return ok
}

// Run sweeps once and then follows writes, route changes, deleted entries,
// carrier changes and the resweep until ctx ends. It returns after the first
// sweep; the watch runs in the background.
func (k *EncapNeighKeeper) Run(ctx context.Context) error {
	if _, err := k.Sweep(); err != nil {
		k.logger.Warn("initial encapsulation next-hop sweep incomplete", zap.Error(err))
	}
	routes, neighs, links, err := k.subscribe()
	if err != nil {
		return err
	}
	go k.watch(ctx, routes, neighs, links)
	return nil
}

// subscribe opens the subscriptions the watch follows.
func (k *EncapNeighKeeper) subscribe() (*routeSub, *neighSub, *linkSub, error) {
	routes, err := k.subRoutes()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("subscribe to route updates: %w", err)
	}
	neighs, err := k.subNeighs()
	if err != nil {
		close(routes.done)
		return nil, nil, nil, err
	}
	links, err := k.subLinks()
	if err != nil {
		close(routes.done)
		close(neighs.done)
		return nil, nil, nil, err
	}
	return routes, neighs, links, nil
}

type neighSub struct {
	updates chan netlink.NeighUpdate
	done    chan struct{}
}

func (k *EncapNeighKeeper) subscribeNeighs() (*neighSub, error) {
	s := &neighSub{updates: make(chan netlink.NeighUpdate, 256), done: make(chan struct{})}
	if err := netlink.NeighSubscribeWithOptions(s.updates, s.done, netlink.NeighSubscribeOptions{
		ErrorCallback: k.neighSt.OnError,
	}); err != nil {
		close(s.done)
		return nil, fmt.Errorf("subscribe to neighbour updates: %w", err)
	}
	return s, nil
}

type linkSub struct {
	updates chan netlink.LinkUpdate
	done    chan struct{}
}

func (k *EncapNeighKeeper) subscribeLinks() (*linkSub, error) {
	s := &linkSub{updates: make(chan netlink.LinkUpdate, 256), done: make(chan struct{})}
	if err := netlink.LinkSubscribeWithOptions(s.updates, s.done, netlink.LinkSubscribeOptions{
		ErrorCallback: k.linkSt.OnError,
	}); err != nil {
		close(s.done)
		return nil, fmt.Errorf("subscribe to link updates: %w", err)
	}
	return s, nil
}

// drain reads ch until it is closed.
func drain[T any](ch <-chan T) {
	for range ch {
	}
}

// carrierState is what the link updates said of each device's carrier.
type carrierState map[int32]bool

// cameUp records u and reports whether its device got its carrier back: it
// is up with a carrier (IFF_UP and IFF_LOWER_UP) and was not, or was not
// seen yet.
func (c carrierState) cameUp(u netlink.LinkUpdate) bool {
	if u.Family == unix.AF_BRIDGE {
		return false // a bridge port's own message
	}
	ifindex := u.Index
	if u.Header.Type == unix.RTM_DELLINK {
		delete(c, ifindex)
		return false
	}
	up := u.Flags&unix.IFF_UP != 0 && u.Flags&unix.IFF_LOWER_UP != 0
	was, seen := c[ifindex]
	c[ifindex] = up
	return up && (!seen || !was)
}

// watch follows the subscriptions until ctx ends. A subscription that ends
// is subscribed again after a wait that grows with each failed attempt
// (netlinksub), while the rest of the watch, the resweep included, goes on.
// One that comes back resyncs what its events cover: the set is re-resolved
// (routes), every kept entry is checked (neighbours), or every device up
// with its carrier counts as having got it back (links).
func (k *EncapNeighKeeper) watch(ctx context.Context, routes *routeSub, neighs *neighSub, links *linkSub) {
	defer func() {
		// The subscriptions' readers block on a full channel; drained, they
		// see the closed socket and end.
		if routes != nil {
			close(routes.done)
			go drain(routes.routes)
		}
		if neighs != nil {
			close(neighs.done)
			go drain(neighs.updates)
		}
		if links != nil {
			close(links.done)
			go drain(links.updates)
		}
	}()
	carrier := carrierState{}
	// rearm holds, per device whose carrier came back, until when the first
	// failure of a kept entry on it asks for one more mark.
	rearm := map[int32]time.Time{}
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
	// While a subscription is down its channels are nil, which a select
	// never picks, and its retry channel fires for the next attempt.
	var routeRetry, neighRetry, linkRetry <-chan time.Time
	routesDown := func() {
		close(routes.done)
		go drain(routes.routes)
		routes = nil
		routeRetry = time.After(k.routeSt.Ended())
	}
	for {
		var (
			routesC   <-chan netlink.RouteUpdate
			nexthopsC <-chan struct{}
			neighsC   <-chan netlink.NeighUpdate
			linksC    <-chan netlink.LinkUpdate
		)
		if routes != nil {
			routesC, nexthopsC = routes.routes, routes.nexthops
		}
		if neighs != nil {
			neighsC = neighs.updates
		}
		if links != nil {
			linksC = links.updates
		}
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case _, ok := <-routesC:
			if !ok {
				routesDown()
				continue
			}
			reroute()
		case _, ok := <-nexthopsC:
			if !ok {
				routesDown()
				continue
			}
			reroute()
		case <-routeRetry:
			routeRetry = nil
			sub, err := k.subRoutes()
			if err != nil {
				routeRetry = time.After(k.routeSt.Failed(err))
				continue
			}
			routes = sub
			k.routeSt.Restored()
			reroute()
		case u, ok := <-neighsC:
			if !ok {
				close(neighs.done)
				neighs = nil
				neighRetry = time.After(k.neighSt.Ended())
				continue
			}
			switch {
			case u.Type == unix.RTM_DELNEIGH && k.keepsNeigh(u.LinkIndex, u.IP):
				k.setFlag(false, true)
				pending()
			case u.Type == unix.RTM_NEWNEIGH && u.State == netlink.NUD_FAILED:
				dev := int32(u.LinkIndex)
				if until, ok := rearm[dev]; ok && time.Now().Before(until) && k.keepsNeigh(u.LinkIndex, u.IP) {
					delete(rearm, dev)
					k.carrierUp(uint32(dev))
					pending()
				}
			}
		case <-neighRetry:
			neighRetry = nil
			sub, err := k.subNeighs()
			if err != nil {
				neighRetry = time.After(k.neighSt.Failed(err))
				continue
			}
			neighs = sub
			k.neighSt.Restored()
			k.setFlag(false, true)
			pending()
		case u, ok := <-linksC:
			if !ok {
				close(links.done)
				links = nil
				linkRetry = time.After(k.linkSt.Ended())
				continue
			}
			if carrier.cameUp(u) && k.hasNexthopsOn(int(u.Index)) {
				k.carrierUp(uint32(u.Index))
				pending()
				rearm[u.Index] = time.Now().Add(encapNeighCarrierWindow)
			} else if !carrier[u.Index] {
				delete(rearm, u.Index) // down again, or gone
			}
		case <-linkRetry:
			linkRetry = nil
			sub, err := k.subLinks()
			if err != nil {
				linkRetry = time.After(k.linkSt.Failed(err))
				continue
			}
			links = sub
			k.linkSt.Restored()
			// The event of a carrier that came back while the subscription
			// was down is lost: every device up with its carrier now counts
			// as having got it back.
			carrier = carrierState{}
			clear(rearm)
			if k.resyncCarrier(carrier, rearm) {
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

// resyncCarrier records in c the carrier of every device and, as a carrier
// that came back would, queues the re-probe of the next hops on each device
// up with its carrier and opens its window in rearm. It reports whether one
// was queued.
func (k *EncapNeighKeeper) resyncCarrier(c carrierState, rearm map[int32]time.Time) bool {
	links, err := k.linkList()
	if err != nil {
		k.logger.Debug("list devices for the carrier state", zap.Error(err))
		return false
	}
	queued := false
	for _, l := range links {
		a := l.Attrs()
		up := a.RawFlags&unix.IFF_UP != 0 && a.RawFlags&unix.IFF_LOWER_UP != 0
		c[int32(a.Index)] = up
		if up && k.hasNexthopsOn(a.Index) {
			k.carrierUp(uint32(a.Index))
			rearm[int32(a.Index)] = time.Now().Add(encapNeighCarrierWindow)
			queued = true
		}
	}
	return queued
}
