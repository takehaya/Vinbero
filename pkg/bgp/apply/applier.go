// Package apply turns decoded BGP route events into Vinbero data-plane
// state: VPNv4 / VPNv6 routes become headend_v4/v6_map encap entries,
// and IPv6 unicast routes are injected into the kernel FIB.
//
// Applier.Apply satisfies bgp.RouteHandler, so it can be passed
// straight to bgp.RouteSubscriber.Subscribe. It runs on a GoBGP
// goroutine and therefore reports failures to the log rather than to a
// caller.
package apply

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/fib"
	"github.com/takehaya/vinbero/pkg/headend"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/prober"
	"github.com/takehaya/vinbero/pkg/vrf"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// headendOps is shared with plugin reconciliation. It deliberately has no
// force-delete operation: the applier deletes only under its own owners.
type headendOps = headend.Writer

// Option configures an applier before it starts receiving routes.
type Option func(*Applier)

// WithHeadendWriter routes incremental headend updates through the same
// reconciler as control-plane plugins. Other data-plane surfaces stay on dp.
func WithHeadendWriter(writer headend.Writer) Option {
	return func(a *Applier) { a.headend = writer }
}

// mupOps is the subset of bpf.MapOperations the BGP MUP uplink path needs:
// the F-TEID maps (mup_uplink_v4/v6_map) that the H.M.GTP{4,6}.D_TEID
// behaviors read, and the ifindex -> uplink-instance map that scopes a
// packet's F-TEID lookup to its access interface's service instance. The
// downlink path reuses headendOps (H.Encaps into headend_v4_map), and the
// uplink gate is an ordinary headend_v4_map entry.
type mupOps interface {
	CreateMupUplinkV4Owned(instance uint32, endpoint string, teid uint32, teidPrefixBits uint8, entry *bpf.HeadendEntry, owner bpf.OwnerTag) error
	DeleteMupUplinkV4Owned(instance uint32, endpoint string, teid uint32, teidPrefixBits uint8, owner bpf.OwnerTag) error
	CreateMupUplinkV6Owned(instance uint32, endpoint string, teid uint32, teidPrefixBits uint8, entry *bpf.HeadendEntry, owner bpf.OwnerTag) error
	DeleteMupUplinkV6Owned(instance uint32, endpoint string, teid uint32, teidPrefixBits uint8, owner bpf.OwnerTag) error
}

// dataPlane is the BPF map surface the applier writes: headend encap
// entries plus the SR Policy transport map. *bpf.MapOperations satisfies
// it; the narrow sub-interfaces keep the applier unit-testable.
type dataPlane interface {
	headendOps
	policyMapOps
	fdbBdOps
	mupOps
	ecmpOps
}

// Applier applies received BGP routes to the Vinbero data plane.
type Applier struct {
	headend     headendOps
	fdbBd       fdbBdOps
	mupUplink   mupOps
	ecmp        ecmpOps
	locators    *locator.Manager
	vrfBindings *vrfbgp.Manager
	fib         fib.Injector
	srcLocator  string
	localASN    uint32
	srPolicy    *srPolicyTable
	evpn        *evpnTable
	// prober mirrors the programmed ECMP groups into the liveness prober
	// (default: no-op). Swapped in via SetProber before the session starts.
	prober prober.Registry
	// vpnGroups aggregates the paths learned for each VPN prefix into one
	// ECMP group, guarded by vpnMu: the GoBGP RouteHandler goroutine applies
	// routes (applyVPN), and an SR Policy transport change re-registers the
	// affected groups' probe targets (reprobeSRPolicy) -- which the
	// SRPolicyService CRUD handlers can trigger from an RPC goroutine. Same
	// pattern as mupMu / evpnMu. NewApplier's startup reset runs before any
	// of that and needs no lock.
	vpnMu sync.Mutex
	// vpnQuiet and vpnQuietDenied, guarded by vpnMu, count import-RT denials
	// instead of logging each one while QuietVPNDenials runs.
	vpnQuiet       bool
	vpnQuietDenied int
	vpnGroups      *vpnGroupTable
	// mupDefaultAllow forces every MUP session route through the historical
	// default-allow path even when some VRF binding has declared a mup_ipv*
	// family. It is the escape hatch for the asymmetric-expansion case where
	// adopting the new mup_ipv* form on ONE binding flips the global filter
	// on and drops every legacy binding's MUP traffic (legacyToFamilies
	// does not synthesize MUP entries). Set from bgp.global.mup_default_allow.
	mupDefaultAllow bool
	// MUP receive state, guarded by mupMu: the GoBGP RouteHandler goroutine
	// applies routes (applyMUP), and VrfBgpService mutations re-reconcile
	// installed downlinks when a binding's GTP4 source prefix changes
	// (ReconcileMUPGTP4SrcForRD), so unlike the single-goroutine VPN state this is
	// touched from two goroutines. mupT1ST / mupT2ST hold each session's
	// full route plus the SID currently programmed for it (so an arriving /
	// withdrawn discovery route can reconcile the install). mupISD / mupDSD
	// are the segment-discovery tables a session resolves against (T1ST
	// against an ISD by endpoint, T2ST against a DSD by MUP segment id).
	// mupGateRefs counts how many uplink sessions share each endpoint's
	// H.M.GTP4.D_TEID gate in each VRF. mupGateDebt counts the references a
	// moved session could not release, and mupT1STStale the downlink
	// entries whose removal failed; the tracked pass retries both.
	mupMu        sync.Mutex
	mupT1ST      map[mupT1STKey]*mupSessionState
	mupT2ST      map[mupT2STKey]*mupSessionState
	mupISD       map[mupISDKey]mupISDEntry
	mupDSD       map[mupDSDKey]mupDSDEntry
	mupGateRefs  map[mupGateKey]int
	mupGateDebt  map[mupGateKey]int
	mupT1STStale map[mupT1STEntry]struct{}
	mupRecovery  *mupStartupRecovery
	// evpnMu serializes the EVPN receive state (evpnTable.peers/fdb/mcast)
	// between the GoBGP RouteHandler goroutine (applyEVPN) and the RPC-driven
	// ReplayEVPN (VrfBridgeAttach / commitBinding re-pull the loc-rib after
	// the EVPN import surface widens). Same pattern as mupMu.
	evpnMu sync.Mutex
	// onTrackedFailure asks for another ReconcileTracked pass (see
	// SetTrackedRetry). The receive path and the RPC-driven reconciles call
	// it when a write of tracked state failed; ReconcileTracked itself
	// reports its failures by its return value.
	onTrackedFailure atomic.Pointer[func()]
	// replaying is set while ReplayAndReconcile delivers its replay. The
	// tracked pass that follows the replay reports what failed, so those
	// deliveries do not ask for a retry of their own.
	replaying atomic.Bool
	// vpnWriteFailed and mupWriteFailed, guarded by vpnMu and mupMu (and
	// evpnTable.writeFailed by evpnMu), record that a tracked write failed
	// while the lock was held. The holder hands them to flushTrackedFailure
	// before it unlocks.
	vpnWriteFailed bool
	mupWriteFailed bool
	logger         *zap.Logger
}

// NewApplier wires an Applier. srcLocator names the locator whose prefix
// supplies the SRv6 encapsulation source address (see plan §6-5).
// vrfBindings supplies the route-target import filter; an empty manager
// accepts every received route.
func NewApplier(dp dataPlane, locators *locator.Manager, vrfBindings *vrfbgp.Manager, fibInjector fib.Injector, srcLocator string, localASN uint32, logger *zap.Logger, options ...Option) *Applier {
	a := &Applier{
		headend:      dp,
		fdbBd:        dp,
		mupUplink:    dp,
		ecmp:         dp,
		locators:     locators,
		vrfBindings:  vrfBindings,
		fib:          fibInjector,
		srcLocator:   srcLocator,
		localASN:     localASN,
		srPolicy:     newSRPolicyTable(dp, logger),
		prober:       prober.Noop{},
		vpnGroups:    newVPNGroupTable(dp, localASN, logger),
		evpn:         newEVPNTable(),
		mupT1ST:      make(map[mupT1STKey]*mupSessionState),
		mupT2ST:      make(map[mupT2STKey]*mupSessionState),
		mupISD:       make(map[mupISDKey]mupISDEntry),
		mupDSD:       make(map[mupDSDKey]mupDSDEntry),
		mupGateRefs:  make(map[mupGateKey]int),
		mupGateDebt:  make(map[mupGateKey]int),
		mupT1STStale: make(map[mupT1STEntry]struct{}),
		logger:       logger.Named("bgp.apply"),
	}
	for _, option := range options {
		option(a)
	}
	// A policy's installed transport changing invalidates the probe journeys
	// registered for the groups steered onto it; the hook re-registers them.
	a.srPolicy.onTransportChange = a.reprobeSRPolicy
	// Runs before the BGP session starts, so it cannot race a route event.
	// The EVPN sweep goes first: it clears the high-partition group ids so
	// the VPN table's high-water seed below is not inflated by them.
	a.resetMUPOwned()
	a.resetEVPNGroups()
	a.vpnGroups.reset()
	return a
}

// SetMUPDefaultAllow toggles the MUP receive-side default-allow escape hatch.
// Set from bgp.global.mup_default_allow before BGP routes start arriving so
// the toggle is not racing applyMUP on a per-route basis.
func (a *Applier) SetMUPDefaultAllow(allow bool) { a.mupDefaultAllow = allow }

// CleanupFIB removes every kernel FIB route Vinbero installed for
// BGP-learned prefixes. It is meant for graceful shutdown so those
// routes do not outlive the process. Headend map entries are
// owner-tagged and reconciled separately.
func (a *Applier) CleanupFIB() error {
	routes, err := a.fib.List()
	if err != nil {
		return fmt.Errorf("list BGP FIB routes: %w", err)
	}
	var errs []error
	for _, r := range routes {
		if err := a.fib.Delete(r.Prefix); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Apply is the bgp.RouteHandler entry point.
func (a *Applier) Apply(ev bgp.RouteEvent) {
	switch {
	case ev.SRPolicy != nil:
		a.srPolicy.apply(*ev.SRPolicy, ev.IsWithdraw)
	case ev.VPN != nil:
		a.applyVPN(ev.VPN, ev.Source, ev.IsWithdraw)
	case ev.Unicast != nil:
		a.applyUnicast(ev.Unicast, ev.IsWithdraw)
	case ev.EVPN != nil:
		a.applyEVPN(ev)
	case ev.MUP != nil:
		a.applyMUP(ev.Family, ev.MUP, ev.IsWithdraw)
	}
}

// ApplyLocalSRPolicy installs or withdraws an operator-defined (origin
// local) SR Policy through the same state machine as BGP-received ones.
// It is the entry point for the SRPolicyService CRUD handlers.
func (a *Applier) ApplyLocalSRPolicy(p bgp.SRPolicy, withdraw bool) {
	a.srPolicy.apply(p, withdraw)
}

// ListSRPolicies returns a snapshot of every known SR Policy (local and
// BGP), for SrPolicyService / vbctl introspection.
func (a *Applier) ListSRPolicies() []SRPolicySnapshot {
	return a.srPolicy.list()
}

// HasLocalSRPolicy reports whether an operator-defined SR Policy exists
// for {color, endpoint}. SrPolicyDelete uses it to reject removing a
// policy that is only known via BGP.
func (a *Applier) HasLocalSRPolicy(color uint32, endpoint netip.Addr) bool {
	return a.srPolicy.hasLocalCandidate(color, endpoint)
}

// ApplyLocalSRPolicyCapped installs a local SR Policy, rejecting a NEW one when
// it would exceed max (0 = unlimited). The count check and the install are
// atomic, so the SrPolicyService cap holds under concurrent RPCs.
func (a *Applier) ApplyLocalSRPolicyCapped(p bgp.SRPolicy, max uint32) error {
	return a.srPolicy.applyLocalCapped(p, max)
}

// QuietVPNDenials runs replay with per-route import-RT denials summarized in
// one log line. A loc-rib replay revisits every route a VRF does not import,
// so warning for each would repeat the whole rib. replay must hold off live
// delivery for its duration, as ReplayBuiltin does.
func (a *Applier) QuietVPNDenials(replay func() error) error {
	a.vpnMu.Lock()
	a.vpnQuiet, a.vpnQuietDenied = true, 0
	a.vpnMu.Unlock()
	err := replay()
	a.vpnMu.Lock()
	denied := a.vpnQuietDenied
	a.vpnQuiet = false
	a.vpnMu.Unlock()
	if denied > 0 {
		a.logger.Info("VPN loc-rib replay dropped routes no VRF imports", zap.Int("routes", denied))
	}
	return err
}

// ReplayScope runs deliver, the delivery of a loc-rib replay, and must call
// it with live delivery held off (demux.ReplayBuiltinScoped does), so that
// what fails inside it is the replay's own.
type ReplayScope func(deliver func() error) error

// ReplayAndReconcile is the loc-rib replay the daemon runs off the RPC
// path: replay re-delivers the received routes through Apply inside the
// scope it is handed (with VPN denials summarized, see QuietVPNDenials),
// then ReconcileTracked writes what is still not in the data plane.
//
// The error says what a retry needs. A *TrackedWriteError (from
// ReconcileTracked) needs only another tracked pass. An
// *UnwrittenRoutesError needs another replay of its family: an EVPN route
// is tracked only once it is written, so one whose first write failed in
// this replay is delivered again by nothing else. Any other error is the
// replay's own (reading the loc-rib failed) and needs the whole replay.
func (a *Applier) ReplayAndReconcile(replay func(scope ReplayScope) error) error {
	unwritten := 0
	scope := func(deliver func() error) error {
		a.evpnMu.Lock()
		a.evpn.replayUnwritten = &unwritten
		a.evpnMu.Unlock()
		a.replaying.Store(true)
		defer func() {
			a.replaying.Store(false)
			a.evpnMu.Lock()
			a.evpn.replayUnwritten = nil
			a.evpnMu.Unlock()
		}()
		return deliver()
	}
	var errs []error
	if err := a.QuietVPNDenials(func() error { return replay(scope) }); err != nil {
		errs = append(errs, err)
	}
	if unwritten > 0 {
		errs = append(errs, &UnwrittenRoutesError{Family: bgp.FamilyEVPN, Routes: unwritten})
	}
	if err := a.ReconcileTracked(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// SetTrackedRetry installs what the applier calls to ask for another
// ReconcileTracked pass after a write of tracked state failed outside that
// pass: on the live receive path, or in a reconcile an RPC drove. f must
// not block or call back into the applier. It may be set while routes
// arrive (the RPC server is set up after the BGP session starts); a failure
// before then is retried by the next event or pass.
func (a *Applier) SetTrackedRetry(f func()) { a.onTrackedFailure.Store(&f) }

// flushTrackedFailure hands a failure recorded under one of the applier's
// locks to the retry, and clears it. The caller holds the lock that guards
// *failed. Deliveries of a replay do not ask: the tracked pass after the
// replay reports what is still failing.
func (a *Applier) flushTrackedFailure(failed *bool) {
	if !*failed {
		return
	}
	*failed = false
	if f := a.onTrackedFailure.Load(); f != nil && !a.replaying.Load() {
		(*f)()
	}
}

// vpnFailed and mupFailed record a failed tracked write and return false,
// for the reconciles to report it with. The caller holds vpnMu / mupMu.
func (a *Applier) vpnFailed() bool {
	a.vpnWriteFailed = true
	return false
}

func (a *Applier) mupFailed() bool {
	a.mupWriteFailed = true
	return false
}

// removeVPNPath drops one tracked path from one VRF's destination and
// reconciles what remains. It reports false when that reconcile failed and
// the destination is still tracked. Callers hold vpnMu.
func (a *Applier) removeVPNPath(dk vpnDestKey, pk vpnPathKey) bool {
	d, released := a.vpnGroups.remove(dk, pk)
	if released != nil {
		// The removal event carries no color or next hop, so the reference
		// recorded against the path is the only way to know which policy
		// to release.
		a.srPolicy.unref(released.color, released.endpoint)
	}
	if d == nil {
		return true
	}
	return a.reconcileVPNGroup(dk, d) || a.vpnGroups.dests[dk] == nil
}

// removeVPNRoute takes one received path out of every VRF it is placed in
// except those in keep, and returns the VRFs it is still recorded in: those
// of keep, and those whose removal failed to reach the data plane. A VRF
// stays recorded until its removal succeeds, so another withdraw or UPDATE
// of the route retries it, as the tracked pass does. A withdraw passes no
// keep. Callers hold vpnMu.
func (a *Applier) removeVPNRoute(rk vpnRouteKey, keep []uint32) []uint32 {
	var left []uint32
	for _, v := range a.vpnGroups.placed[rk] {
		switch {
		case slices.Contains(keep, v):
			left = append(left, v)
		case a.removeVPNPath(rk.dest(v), rk.path):
			a.vpnGroups.unstick(rk.dest(v), rk)
		default:
			left = append(left, v)
			a.vpnGroups.stick(rk.dest(v), rk)
		}
	}
	a.vpnGroups.setPlaced(rk, left)
	return left
}

// vpnImportVRFs returns the VRFs a received VPN route is placed in, and
// whether any VRF accepts it: every VRF whose binding imports one of its
// route targets, each with its own ECMP group and trigger. A family no
// binding declares is default-allow and places every route in the global
// VRF.
func (a *Applier) vpnImportVRFs(vr *bgp.VPNRoute) ([]uint32, bool) {
	targets, defaultAllow := a.vrfBindings.ImportTargetsForFamily(vr.RTs, vr.Family)
	if defaultAllow {
		return []uint32{vrf.GlobalVRFID}, true
	}
	if len(targets) == 0 {
		return nil, false
	}
	ids := make([]uint32, len(targets))
	for i, t := range targets {
		ids[i] = t.ID
	}
	return ids, true
}

func (a *Applier) applyVPN(vr *bgp.VPNRoute, src bgp.PathSource, withdraw bool) {
	a.vpnMu.Lock()
	defer a.vpnMu.Unlock()
	defer a.flushTrackedFailure(&a.vpnWriteFailed)
	// The VRF ids resolved below stay valid until the writes are done: a VRF
	// cannot start its deletion meanwhile (vrf.Manager.HoldIDs).
	release := a.vrfBindings.VRF().HoldIDs()
	defer release()
	rk := vpnRouteKey{family: vr.Family, prefix: vr.Prefix, path: vpnPathKey{rd: vr.RD, source: src}}
	if withdraw {
		// Withdraw bypasses the import-RT filter so a route accepted
		// earlier is always torn down, from every VRF it was placed in, and
		// drops only this path: the prefix survives on whatever other PEs
		// still advertise it. An entry a previous run wrote is not this
		// process's to find: the boot removes them all
		// (PurgeBuiltinHeadends) before the data plane is attached.
		a.removeVPNRoute(rk, nil)
		return
	}
	// Import-RT filter: once any VRF binding declares this family, a
	// received route must carry an RT some VRF imports. A Manager with no
	// binding under fam keeps the historical default-allow, so vpnv4 /
	// vpnv6 gate independently as bindings arrive per family.
	vrfs, importAllowed := a.vpnImportVRFs(vr)
	path, diagnostic := selectVPNPath(vr, importAllowed)
	switch diagnostic {
	case vpnImportDenied:
		if a.vpnQuiet {
			a.vpnQuietDenied++
			break
		}
		a.logger.Warn("VPN route matches no VRF import RT; dropping",
			zap.String("prefix", vr.Prefix), zap.Strings("rts", vr.RTs))
	case vpnSIDMissing:
		a.logger.Warn("VPN route has no usable SRv6 SID; removing any installed path",
			zap.String("prefix", vr.Prefix), zap.String("rd", vr.RD))
	case vpnSteeringInvalidNextHop:
		a.logger.Warn("colored VPN route has no parseable next hop; not steering",
			zap.String("prefix", vr.Prefix), zap.Uint32("color", vr.Color),
			zap.String("nexthop", vr.NextHop))
	case vpnSteeringNonIPv6NextHop:
		a.logger.Warn("colored VPN route next hop is not IPv6; not steering",
			zap.String("prefix", vr.Prefix), zap.Uint32("color", vr.Color),
			zap.String("nexthop", vr.NextHop))
	}
	if path == nil {
		a.removeVPNRoute(rk, nil)
		return
	}
	a.placeVPNRoute(rk, path, vrfs)
}

// placeVPNRoute makes vrfs the VRFs that hold rk's path. A BGP UPDATE is an
// implicit replace: the VRFs that no longer import the route lose its path
// first, then every VRF that does takes the new one. Callers hold vpnMu.
func (a *Applier) placeVPNRoute(rk vpnRouteKey, path *vpnPath, vrfs []uint32) {
	var placed []uint32
	for _, v := range a.removeVPNRoute(rk, vrfs) {
		if !slices.Contains(vrfs, v) {
			placed = append(placed, v) // its removal is still to be retried
		}
	}
	for _, v := range vrfs {
		// Each VRF's destination holds a path of its own: the policy
		// reference is taken and released per VRF.
		p := *path
		if a.upsertVPNPath(rk.dest(v), rk.path, &p) {
			placed = append(placed, v)
		}
		a.vpnGroups.unstick(rk.dest(v), rk)
	}
	a.vpnGroups.setPlaced(rk, placed)
}

// upsertVPNPath records one path in one VRF's destination and reconciles it.
// It reports false when a bound refused the path, which leaves the path out
// of that VRF. Callers hold vpnMu.
func (a *Applier) upsertVPNPath(dk vpnDestKey, pk vpnPathKey, path *vpnPath) bool {
	want := path.steer
	// Take the new reference before releasing the old one so a re-advertise
	// that keeps the same target never drops the refcount to zero and lets
	// the policy be garbage-collected between the two calls.
	// remove is only for the reference the previous advertisement of THIS
	// path held; upsert below re-adds it, so the destination it returns is
	// deliberately ignored.
	_, replaced := a.vpnGroups.remove(dk, pk)
	if want != nil {
		a.srPolicy.ref(want.color, want.endpoint)
	}
	if replaced != nil {
		a.srPolicy.unref(replaced.color, replaced.endpoint)
	}
	d, ok := a.vpnGroups.upsert(dk, pk, path)
	if !ok {
		// Refused by a bound. The reference just taken would otherwise pin
		// a policy no path holds.
		if want != nil {
			a.srPolicy.unref(want.color, want.endpoint)
		}
		if d != nil {
			a.reconcileVPNGroup(dk, d)
		}
		return false
	}
	a.reconcileVPNGroup(dk, d)
	return true
}

func (a *Applier) applyUnicast(ur *bgp.UnicastRoute, withdraw bool) {
	prefix, err := netip.ParsePrefix(ur.Prefix)
	if err != nil {
		a.logger.Error("parse unicast prefix",
			zap.String("prefix", ur.Prefix), zap.Error(err))
		return
	}
	if withdraw {
		if err := a.fib.Delete(prefix); err != nil {
			a.logger.Error("withdraw unicast route",
				zap.String("prefix", ur.Prefix), zap.Error(err))
		}
		return
	}
	r := fib.Route{Prefix: prefix}
	if ur.NextHop != "" {
		nh, err := netip.ParseAddr(ur.NextHop)
		if err != nil {
			a.logger.Error("parse unicast nexthop",
				zap.String("nexthop", ur.NextHop), zap.Error(err))
			return
		}
		r.NextHops = []fib.NextHop{{Gw: nh}}
	}
	if err := a.fib.Add(r); err != nil {
		a.logger.Error("install unicast route",
			zap.String("prefix", ur.Prefix), zap.Error(err))
		return
	}
	a.logger.Info("unicast route installed", zap.String("prefix", ur.Prefix))
}

// buildHeadendEntryFrom assembles the headend entry that encapsulates
// matching traffic towards the remote PE's SRv6 service SID, with src as
// the outer source. The single segment is the SID itself and the outer
// destination equals it; parsing the SID once via ParseSegments keeps
// DstAddr and Segments[0] byte-identical.
// reduced selects H.Encaps.Red -- for a single NEXT-C-SID service SID
// the data plane then emits no SRH (RFC 9800 reduced encapsulation).
// Callers resolve src (encapSource) once per reconcile and record it with
// what they wrote, so a moved source locator is seen as a change.
func buildHeadendEntryFrom(src [16]byte, sid string, reduced bool) (*bpf.HeadendEntry, error) {
	segments, numSegments, err := bpf.ParseSegments([]string{sid})
	if err != nil {
		return nil, fmt.Errorf("parse SRv6 SID %q: %w", sid, err)
	}
	mode := v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS
	if reduced {
		mode = v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_RED
	}
	return &bpf.HeadendEntry{
		Mode:        uint8(mode),
		NumSegments: numSegments,
		SrcAddr:     src,
		DstAddr:     segments[0],
		Segments:    segments,
	}, nil
}

// encapSource returns the SRv6 encapsulation source address, taken from
// the prefix of the configured source locator.
func (a *Applier) encapSource() ([16]byte, error) {
	var zero [16]byte
	if a.srcLocator == "" {
		return zero, fmt.Errorf("bgp.global.source_locator is not configured")
	}
	loc, ok := a.locators.Get(a.srcLocator)
	if !ok {
		return zero, fmt.Errorf("source locator %q is not registered", a.srcLocator)
	}
	return loc.Prefix.Masked().Addr().As16(), nil
}

func (a *Applier) createHeadend(vrfID uint32, fam bgp.Family, prefix string, entry *bpf.HeadendEntry, owner bpf.OwnerTag) error {
	switch fam {
	case bgp.FamilyVPNv4:
		return a.headend.CreateHeadendV4In(vrfID, prefix, entry, owner)
	case bgp.FamilyVPNv6:
		return a.headend.CreateHeadendV6In(vrfID, prefix, entry, owner)
	default:
		return fmt.Errorf("unexpected VPN family %q", fam)
	}
}

func (a *Applier) deleteHeadend(vrfID uint32, fam bgp.Family, prefix string, owner bpf.OwnerTag) error {
	switch fam {
	case bgp.FamilyVPNv4:
		return a.headend.DeleteHeadendV4In(vrfID, prefix, owner)
	case bgp.FamilyVPNv6:
		return a.headend.DeleteHeadendV6In(vrfID, prefix, owner)
	default:
		return fmt.Errorf("unexpected VPN family %q", fam)
	}
}
