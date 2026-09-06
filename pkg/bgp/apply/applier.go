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
	"sync"

	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/fib"
	"github.com/takehaya/vinbero/pkg/headend"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/prober"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// headendOps is shared with plugin reconciliation. It deliberately has no
// force-delete operation: legacy migration deletes under the observed owner.
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
	CreateMupUplinkV4(instance uint32, endpoint string, teid uint32, teidPrefixBits uint8, entry *bpf.HeadendEntry) error
	DeleteMupUplinkV4(instance uint32, endpoint string, teid uint32, teidPrefixBits uint8) error
	CreateMupUplinkV6(instance uint32, endpoint string, teid uint32, teidPrefixBits uint8, entry *bpf.HeadendEntry) error
	DeleteMupUplinkV6(instance uint32, endpoint string, teid uint32, teidPrefixBits uint8) error
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
	vpnMu     sync.Mutex
	vpnGroups *vpnGroupTable
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
	// H.M.GTP4.D_TEID gate.
	mupMu       sync.Mutex
	mupT1ST     map[mupT1STKey]*mupSessionState
	mupT2ST     map[mupT2STKey]*mupSessionState
	mupISD      map[mupISDKey]mupISDEntry
	mupDSD      map[mupDSDKey]mupDSDEntry
	mupGateRefs map[string]int
	// evpnMu serializes the EVPN receive state (evpnTable.peers/fdb/mcast)
	// between the GoBGP RouteHandler goroutine (applyEVPN) and the RPC-driven
	// ReplayEVPN (VrfBridgeAttach / commitBinding re-pull the loc-rib after
	// the EVPN import surface widens). Same pattern as mupMu.
	evpnMu sync.Mutex
	logger *zap.Logger
}

// NewApplier wires an Applier. srcLocator names the locator whose prefix
// supplies the SRv6 encapsulation source address (see plan §6-5).
// vrfBindings supplies the route-target import filter; an empty manager
// accepts every received route.
func NewApplier(dp dataPlane, locators *locator.Manager, vrfBindings *vrfbgp.Manager, fibInjector fib.Injector, srcLocator string, localASN uint32, logger *zap.Logger, options ...Option) *Applier {
	a := &Applier{
		headend:     dp,
		fdbBd:       dp,
		mupUplink:   dp,
		ecmp:        dp,
		locators:    locators,
		vrfBindings: vrfBindings,
		fib:         fibInjector,
		srcLocator:  srcLocator,
		localASN:    localASN,
		srPolicy:    newSRPolicyTable(dp, logger),
		prober:      prober.Noop{},
		vpnGroups:   newVPNGroupTable(dp, localASN, logger),
		evpn:        newEVPNTable(),
		mupT1ST:     make(map[mupT1STKey]*mupSessionState),
		mupT2ST:     make(map[mupT2STKey]*mupSessionState),
		mupISD:      make(map[mupISDKey]mupISDEntry),
		mupDSD:      make(map[mupDSDKey]mupDSDEntry),
		mupGateRefs: make(map[string]int),
		logger:      logger.Named("bgp.apply"),
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
		a.applyEVPN(ev.EVPN, ev.IsWithdraw)
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

// removeVPNPath drops one tracked path and reconciles what remains. Shared
// by withdraw and by a replacement UPDATE whose SID became unusable. Callers
// hold vpnMu.
func (a *Applier) removeVPNPath(dk vpnDestKey, pk vpnPathKey, vr *bgp.VPNRoute) {
	d, released := a.vpnGroups.remove(dk, pk)
	if released != nil {
		// The removal event carries no color or next hop, so the reference
		// recorded against the path is the only way to know which policy
		// to release.
		a.srPolicy.unref(released.color, released.endpoint)
	}
	if d == nil {
		// Nothing tracked for this prefix, but the data plane may still
		// hold an entry this process never saw: with pinned maps an entry
		// installed before a restart outlives the accumulator, and this
		// event arriving before the route is re-advertised is the only
		// chance to remove it. Delete unconditionally; it is a no-op when
		// the entry is already absent.
		if err := a.deleteTrigger(vr.Family, vr.Prefix); err != nil {
			a.logger.Error("remove untracked VPN prefix",
				zap.String("prefix", vr.Prefix), zap.Error(err))
		}
		return
	}
	a.reconcileVPNGroup(dk, d)
}

func (a *Applier) applyVPN(vr *bgp.VPNRoute, src bgp.PathSource, withdraw bool) {
	a.vpnMu.Lock()
	defer a.vpnMu.Unlock()
	dk := vpnDestKey{family: vr.Family, prefix: vr.Prefix}
	pk := vpnPathKey{rd: vr.RD, source: src}
	if withdraw {
		// Withdraw bypasses the import-RT filter so a route accepted
		// earlier is always torn down, and drops only this path: the prefix
		// survives on whatever other PEs still advertise it.
		a.removeVPNPath(dk, pk, vr)
		return
	}
	// Import-RT filter: once any VRF binding declares this family, a
	// received route must carry an RT some VRF imports. A Manager with no
	// binding under fam keeps the historical default-allow, so vpnv4 /
	// vpnv6 gate independently as bindings arrive per family.
	if !a.vrfBindings.EmptyForFamily(vr.Family) {
		if _, _, ok := a.vrfBindings.MatchImportForFamily(vr.RTs, vr.Family); !ok {
			// A replacement UPDATE whose RTs no longer match any import
			// filter must still replace: a path imported earlier under
			// different RTs cannot survive it (BGP UPDATEs replace the
			// whole attribute set).
			a.logger.Warn("VPN route matches no VRF import RT; dropping",
				zap.String("prefix", vr.Prefix), zap.Strings("rts", vr.RTs))
			a.removeVPNPath(dk, pk, vr)
			return
		}
	}
	if vr.SRv6SID == "" {
		// A VPN route with no SRv6 service SID cannot be encapsulated --
		// including one whose SID information failed RFC 9252 §7 validation
		// on decode. A BGP UPDATE is an implicit replace, so a previously
		// installed path for this NLRI must not survive the unusable
		// update: tear it down exactly like a withdraw before skipping.
		a.logger.Warn("VPN route has no usable SRv6 SID; removing any installed path",
			zap.String("prefix", vr.Prefix), zap.String("rd", vr.RD))
		a.removeVPNPath(dk, pk, vr)
		return
	}
	// Color-based auto-steering is decided per path: the paths aggregated
	// onto one prefix can carry different colors, so each contributes its
	// own SR Policy reference rather than the prefix holding a single one.
	var want *policyKey
	if vr.Color != 0 {
		endpoint, perr := netip.ParseAddr(vr.NextHop)
		switch {
		case perr != nil:
			a.logger.Warn("colored VPN route has no parseable next hop; not steering",
				zap.String("prefix", vr.Prefix), zap.Uint32("color", vr.Color),
				zap.String("nexthop", vr.NextHop))
		case !endpoint.Is6():
			// SR Policy endpoints are always IPv6, so an IPv4 next hop
			// could never match. Skip steering and don't reserve a
			// policy_id that would never resolve.
			a.logger.Warn("colored VPN route next hop is not IPv6; not steering",
				zap.String("prefix", vr.Prefix), zap.Uint32("color", vr.Color),
				zap.String("nexthop", vr.NextHop))
		default:
			want = &policyKey{color: vr.Color, endpoint: endpoint}
		}
	}

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
	d, ok := a.vpnGroups.upsert(dk, pk, &vpnPath{
		sid: vr.SRv6SID, reduced: vr.SIDStructure.IsUSID(),
		steer: want, nh: vr.NextHop,
	})
	if !ok {
		// Refused by a bound. The reference just taken would otherwise pin
		// a policy no path holds.
		if want != nil {
			a.srPolicy.unref(want.color, want.endpoint)
		}
		if d != nil {
			a.reconcileVPNGroup(dk, d)
		}
		return
	}
	a.reconcileVPNGroup(dk, d)
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

// buildHeadendEntry assembles the headend entry that encapsulates
// matching traffic towards the remote PE's SRv6 service SID. The single
// segment is the SID itself and the outer destination equals it; parsing
// the SID once via ParseSegments keeps DstAddr and Segments[0]
// byte-identical.
// reduced selects H.Encaps.Red -- for a single NEXT-C-SID service SID
// the data plane then emits no SRH (RFC 9800 reduced encapsulation).
func (a *Applier) buildHeadendEntry(sid string, reduced bool) (*bpf.HeadendEntry, error) {
	src, err := a.encapSource()
	if err != nil {
		return nil, err
	}
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

func (a *Applier) createHeadend(fam bgp.Family, prefix string, entry *bpf.HeadendEntry, owner bpf.OwnerTag) error {
	switch fam {
	case bgp.FamilyVPNv4:
		return a.headend.CreateHeadendV4(prefix, entry, owner)
	case bgp.FamilyVPNv6:
		return a.headend.CreateHeadendV6(prefix, entry, owner)
	default:
		return fmt.Errorf("unexpected VPN family %q", fam)
	}
}

func (a *Applier) deleteHeadend(fam bgp.Family, prefix string, owner bpf.OwnerTag) error {
	switch fam {
	case bgp.FamilyVPNv4:
		return a.headend.DeleteHeadendV4(prefix, owner)
	case bgp.FamilyVPNv6:
		return a.headend.DeleteHeadendV6(prefix, owner)
	default:
		return fmt.Errorf("unexpected VPN family %q", fam)
	}
}
