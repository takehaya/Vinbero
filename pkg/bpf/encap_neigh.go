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

// SetEncapChangeHook installs fn to run after every map write that can add an
// encapsulation (headend, ECMP path, SR policy, MUP session, L2 headend, BD
// peer, End.B6 SID, service-return circuit); nil removes it. The
// EncapNeighKeeper uses it to look at a new outer destination at once.
func (m *MapOperations) SetEncapChangeHook(fn func()) {
	if fn == nil {
		m.encapHook.Store(nil)
		return
	}
	m.encapHook.Store(&fn)
}

func (m *MapOperations) encapChanged() {
	if fn := m.encapHook.Load(); fn != nil {
		(*fn)()
	}
}

// EncapDestinations returns every outer IPv6 destination an encapsulation
// can be sent to: the first segment of each headend entry (IPv4 and IPv6
// headends, the MUP gate's per-session entries, the ECMP paths, the L2
// headend circuits and the BD peers), the first transport SID of each SR
// policy, the first segment of each End.B6 / End.B6.Encaps policy, the
// encapsulation of each service-return circuit, and the destination of each
// End.AD cached header. They are read from the maps, so every writer is
// covered (operator RPC, BGP, plugins, a pinned map restored after a
// restart). The result is sorted and has no duplicates.
func (m *MapOperations) EncapDestinations() ([]netip.Addr, error) {
	set := map[netip.Addr]struct{}{}
	addSeg := func(seg [IPv6AddrLen]byte) {
		a := netip.AddrFrom16(seg)
		if a.IsUnspecified() || a.Is4In6() || a.IsMulticast() {
			return
		}
		set[a] = struct{}{}
	}
	addEntry := func(e *HeadendEntry) {
		if e.NumSegments == 0 || e.NumSegments > MaxSegments {
			return // a MUP gate or an empty slot: no segment of its own
		}
		addSeg(e.Segments[0])
	}
	var errs []error
	for _, mp := range []*ebpf.Map{
		m.objs.HeadendV4Map, m.objs.HeadendV6Map, m.objs.MupUplinkV4Map, m.objs.MupUplinkV6Map,
		m.objs.EcmpPathMap, m.objs.HeadendL2Map, m.objs.BdPeerMap,
	} {
		var e HeadendEntry
		if err := iterateValues(mp, &e, func() { addEntry(&e) }); err != nil {
			errs = append(errs, err)
		}
	}
	var pol BpfSrPolicyValue
	if err := iterateValues(m.objs.SrPolicyMap, &pol, func() {
		if pol.Len > 0 {
			addSeg(pol.Segs[0])
		}
	}); err != nil {
		errs = append(errs, err)
	}
	var svc ServiceIngressEntry
	if err := iterateValues(m.objs.ServiceIngressMap, &svc, func() { addEntry(&svc.Encap) }); err != nil {
		errs = append(errs, err)
	}
	var ad AdCacheVal
	if err := iterateValues(m.objs.AdCacheMap, &ad, func() {
		// The cached outer IPv6 header, ready to prepend: DA at offset 24.
		if ad.Valid != 0 && ad.HdrLen >= 40 {
			var da [IPv6AddrLen]byte
			copy(da[:], ad.Hdr[24:40])
			addSeg(da)
		}
	}); err != nil {
		errs = append(errs, err)
	}
	sids, err := m.ListSidFunctions()
	if err != nil {
		errs = append(errs, err)
	}
	for _, sid := range sids {
		switch vinberov1.Srv6LocalAction(sid.Action) {
		case vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_B6,
			vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_B6_ENCAPS:
		default:
			continue
		}
		if sid.AuxIndex == 0 {
			continue
		}
		aux, err := m.GetSidAux(uint32(sid.AuxIndex))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		addEntry(SidAuxB6PolicyData(aux))
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

// NeighTarget is one underlay next hop: the device and the address whose
// neighbour entry an encapsulation needs.
type NeighTarget struct {
	Ifindex uint32
	IP      net.IP
}

func (t NeighTarget) key() string { return fmt.Sprintf("%d/%s", t.Ifindex, t.IP) }

// MainTableNexthops resolves dst the way the outer header of an
// encapsulation is routed: the route the host's lookup selects (the main
// table, through the rules a host-originated packet meets), with every
// member of a multipath route. A gatewayed route gives the gateway, an
// on-link one the destination itself. A destination with no unicast route
// gives none.
func MainTableNexthops(dst net.IP) ([]NeighTarget, error) {
	routes, err := netlink.RouteGetWithOptions(dst, &netlink.RouteGetOptions{FIBMatch: true})
	if err != nil {
		if errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) || errors.Is(err, unix.ESRCH) {
			return nil, nil
		}
		return nil, err
	}
	var out []NeighTarget
	add := func(ifindex int, gw net.IP) {
		if ifindex <= 1 {
			return // no device, or the loopback (a local or a reject route)
		}
		ip := gw
		if ip == nil {
			ip = dst
		}
		out = append(out, NeighTarget{Ifindex: uint32(ifindex), IP: ip})
	}
	for _, r := range routes {
		if r.Type != unix.RTN_UNICAST {
			continue
		}
		if len(r.MultiPath) > 0 {
			for _, nh := range r.MultiPath {
				add(nh.LinkIndex, nh.Gw)
			}
			continue
		}
		add(r.LinkIndex, r.Gw)
	}
	return out, nil
}

// EncapNeighKeeper keeps the underlay next hop of every encapsulation
// resolved, so no encapsulation depends on other traffic to resolve it.
//
// An encapsulation whose next hop has no neighbour entry is handed to the
// kernel (XDP_PASS) to resolve it. From a port enslaved to a VRF device the
// kernel looks that packet up in the VRF table, where the unreachable
// default drops it, so the neighbour would never be solicited; the L2 and
// service-return paths drop such a packet outright. The keeper makes each
// next hop a managed neighbour (KeepNeighResolved): the kernel resolves it
// and keeps it resolved whether or not traffic uses it.
//
// The destinations come from the maps (MapOperations.EncapDestinations) and
// are resolved with the route lookup (MainTableNexthops). A sync runs at
// start, after a write that can add an encapsulation (the map hook), after a
// route change, after a kept neighbour entry is deleted, and every resweep as
// a backstop (it also covers changes that send no route event, such as a
// nexthop object or an ip rule). A managed entry is left in place when its
// next hop is no longer used.
type EncapNeighKeeper struct {
	dests   func() ([]netip.Addr, error)
	resolve func(net.IP) ([]NeighTarget, error)
	keep    func(ifindex uint32, ip net.IP) error
	logger  *zap.Logger
	kick    chan struct{}

	mu     sync.Mutex
	kept   map[string]NeighTarget
	failed map[string]string // what was logged, so each failure is logged once
}

// encapNeighResweep is the backstop interval: writes the hook does not see
// (a plugin writing a map directly) are picked up within it.
const encapNeighResweep = 30 * time.Second

// encapNeighDebounce coalesces a burst of route or map changes into one sync.
const encapNeighDebounce = 200 * time.Millisecond

// NewEncapNeighKeeper builds a keeper over mapOps. Nil resolve and keep use
// MainTableNexthops and KeepNeighResolved.
func NewEncapNeighKeeper(mapOps *MapOperations, resolve func(net.IP) ([]NeighTarget, error), keep func(uint32, net.IP) error, logger *zap.Logger) *EncapNeighKeeper {
	if resolve == nil {
		resolve = MainTableNexthops
	}
	if keep == nil {
		keep = KeepNeighResolved
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &EncapNeighKeeper{
		dests:   mapOps.EncapDestinations,
		resolve: resolve,
		keep:    keep,
		logger:  logger.Named("encap.neigh"),
		kick:    make(chan struct{}, 1),
		kept:    map[string]NeighTarget{},
		failed:  map[string]string{},
	}
}

// Kick asks for a sync soon. It never blocks.
func (k *EncapNeighKeeper) Kick() {
	select {
	case k.kick <- struct{}{}:
	default:
	}
}

// Sync resolves every encapsulation destination and makes each next hop a
// managed neighbour. It returns the next hops it covers.
func (k *EncapNeighKeeper) Sync() ([]NeighTarget, error) {
	dests, derr := k.dests()
	k.mu.Lock()
	defer k.mu.Unlock()
	seen := map[string]NeighTarget{}
	var errs []error
	if derr != nil {
		errs = append(errs, derr)
	}
	for _, d := range dests {
		ip := net.IP(d.AsSlice())
		targets, err := k.resolve(ip)
		if err != nil {
			k.logOnce("resolve "+d.String(), "cannot resolve the next hop of an encapsulation destination", err, zap.Stringer("dst", d))
			errs = append(errs, err)
			continue
		}
		for _, t := range targets {
			seen[t.key()] = t
		}
	}
	for key, t := range seen {
		if err := k.keep(t.Ifindex, t.IP); err != nil {
			k.logOnce("keep "+key, "cannot keep an encapsulation next hop resolved", err,
				zap.Uint32("ifindex", t.Ifindex), zap.Stringer("nexthop", t.IP))
			errs = append(errs, err)
			continue
		}
		delete(k.failed, "keep "+key)
		if _, ok := k.kept[key]; !ok {
			k.logger.Info("keeping an encapsulation next hop resolved",
				zap.Uint32("ifindex", t.Ifindex), zap.Stringer("nexthop", t.IP))
		}
	}
	k.kept = seen
	out := make([]NeighTarget, 0, len(seen))
	for _, t := range seen {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out, errors.Join(errs...)
}

func (k *EncapNeighKeeper) logOnce(key, msg string, err error, fields ...zap.Field) {
	if k.failed[key] == err.Error() {
		return
	}
	k.failed[key] = err.Error()
	k.logger.Warn(msg, append(fields, zap.Error(err))...)
}

// isKept reports whether a neighbour on ifindex for ip is one the keeper
// covers.
func (k *EncapNeighKeeper) isKept(ifindex int, ip net.IP) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	_, ok := k.kept[NeighTarget{Ifindex: uint32(ifindex), IP: ip}.key()]
	return ok
}

// Run syncs once and then keeps syncing until ctx ends (see the type). It
// returns after the first sync; the watch runs in the background.
func (k *EncapNeighKeeper) Run(ctx context.Context) error {
	if _, err := k.Sync(); err != nil {
		k.logger.Warn("initial encapsulation next-hop sync incomplete", zap.Error(err))
	}
	routes := make(chan netlink.RouteUpdate, 256)
	neighs := make(chan netlink.NeighUpdate, 256)
	done := make(chan struct{})
	opts := func(what string) func(error) {
		return func(err error) { k.logger.Warn(what+" subscription failed", zap.Error(err)) }
	}
	if err := netlink.RouteSubscribeWithOptions(routes, done, netlink.RouteSubscribeOptions{
		ErrorCallback: opts("route"), ReceiveBufferSize: 1 << 20,
	}); err != nil {
		close(done)
		return fmt.Errorf("subscribe to route updates: %w", err)
	}
	if err := netlink.NeighSubscribeWithOptions(neighs, done, netlink.NeighSubscribeOptions{
		ErrorCallback: opts("neighbour"),
	}); err != nil {
		close(done)
		return fmt.Errorf("subscribe to neighbour updates: %w", err)
	}
	go k.watch(ctx, routes, neighs, done)
	return nil
}

func (k *EncapNeighKeeper) watch(ctx context.Context, routes chan netlink.RouteUpdate, neighs chan netlink.NeighUpdate, done chan struct{}) {
	defer close(done)
	resweep := time.NewTicker(encapNeighResweep)
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
	for {
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case _, ok := <-routes:
			if !ok {
				routes = nil // the resweep still covers route changes
				continue
			}
			pending()
		case u, ok := <-neighs:
			if !ok {
				neighs = nil
				continue
			}
			if u.Type == unix.RTM_DELNEIGH && k.isKept(u.LinkIndex, u.IP) {
				pending()
			}
		case <-k.kick:
			pending()
		case <-resweep.C:
			pending()
		case <-fire:
			fire = nil
			if _, err := k.Sync(); err != nil {
				k.logger.Debug("encapsulation next-hop sync incomplete", zap.Error(err))
			}
		}
	}
}
