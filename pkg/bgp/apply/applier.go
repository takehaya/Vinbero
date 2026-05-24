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

	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/fib"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// headendOps is the subset of bpf.MapOperations the applier needs.
// Narrowing it to an interface keeps the applier unit-testable without
// a live BPF collection.
type headendOps interface {
	CreateHeadendV4(triggerPrefix string, entry *bpf.HeadendEntry, owner bpf.OwnerTag) error
	CreateHeadendV6(triggerPrefix string, entry *bpf.HeadendEntry, owner bpf.OwnerTag) error
	DeleteHeadendV4(triggerPrefix string, requester bpf.OwnerTag) error
	DeleteHeadendV6(triggerPrefix string, requester bpf.OwnerTag) error
}

// dataPlane is the BPF map surface the applier writes: headend encap
// entries plus the SR Policy transport map. *bpf.MapOperations satisfies
// it; the narrow sub-interfaces keep the applier unit-testable.
type dataPlane interface {
	headendOps
	policyMapOps
}

// Applier applies received BGP routes to the Vinbero data plane.
type Applier struct {
	headend     headendOps
	locators    *locator.Manager
	vrfBindings *vrfbgp.Manager
	fib         fib.Injector
	srcLocator  string
	localASN    uint32
	srPolicy    *srPolicyTable
	// steeredRoutes maps a steered VPN route to the SR Policy key it
	// references, so a withdraw (which carries no color/next-hop) can unref
	// the right policy. Touched only from applyVPN, which runs on the single
	// GoBGP RouteHandler goroutine, so it needs no extra locking; the
	// srPolicyTable it drives is mutex-guarded for the concurrent CRUD path.
	steeredRoutes map[bgp.RouteKey]policyKey
	logger        *zap.Logger
}

// NewApplier wires an Applier. srcLocator names the locator whose prefix
// supplies the SRv6 encapsulation source address (see plan §6-5).
// vrfBindings supplies the route-target import filter; an empty manager
// accepts every received route.
func NewApplier(dp dataPlane, locators *locator.Manager, vrfBindings *vrfbgp.Manager, fibInjector fib.Injector, srcLocator string, localASN uint32, logger *zap.Logger) *Applier {
	return &Applier{
		headend:       dp,
		locators:      locators,
		vrfBindings:   vrfBindings,
		fib:           fibInjector,
		srcLocator:    srcLocator,
		localASN:      localASN,
		srPolicy:      newSRPolicyTable(dp, logger),
		steeredRoutes: make(map[bgp.RouteKey]policyKey),
		logger:        logger.Named("bgp.apply"),
	}
}

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
		a.applyVPN(ev.VPN, ev.IsWithdraw)
	case ev.Unicast != nil:
		a.applyUnicast(ev.Unicast, ev.IsWithdraw)
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

func (a *Applier) applyVPN(vr *bgp.VPNRoute, withdraw bool) {
	owner := bpf.OwnerBGPVPN(a.localASN, vr.RD)
	rk := bgp.RouteKey{Family: vr.Family, Prefix: vr.Prefix, RD: vr.RD}
	if withdraw {
		// Release any SR Policy reference this route held. The withdraw
		// event carries no color/next-hop, so the reverse index is the only
		// way to know which policy to unref.
		a.steer(rk, nil)
		// Withdraw bypasses the import-RT filter so a route accepted
		// earlier is always torn down (deleteHeadend is a no-op when the
		// entry is already absent).
		if err := a.deleteHeadend(vr.Family, vr.Prefix, owner); err != nil {
			a.logger.Error("withdraw VPN route",
				zap.String("prefix", vr.Prefix), zap.Error(err))
		}
		return
	}
	// Import-RT filter: once any VRF binding is registered, a received
	// route must carry a route target some VRF imports. An empty
	// vrfBindings manager accepts every route (BGP works before any
	// VrfBgpBind call).
	if !a.vrfBindings.Empty() {
		if _, ok := a.vrfBindings.MatchImport(vr.RTs); !ok {
			a.logger.Warn("VPN route matches no VRF import RT; dropping",
				zap.String("prefix", vr.Prefix), zap.Strings("rts", vr.RTs))
			return
		}
	}
	if vr.SRv6SID == "" {
		// A VPN route with no SRv6 service SID cannot be encapsulated;
		// log and skip rather than installing a half-formed entry.
		a.logger.Warn("VPN route has no SRv6 SID; skipping",
			zap.String("prefix", vr.Prefix), zap.String("rd", vr.RD))
		return
	}
	entry, err := a.buildHeadendEntry(vr.SRv6SID)
	if err != nil {
		a.logger.Error("build headend entry",
			zap.String("prefix", vr.Prefix), zap.Error(err))
		return
	}
	// Color-based auto-steering: stamp the SR Policy id for {color, next
	// hop} so the XDP headend composes this route's service SID onto that
	// policy's transport. The id is reserved even if the SR Policy has not
	// arrived yet -- the data plane falls back until it does. reserveID only
	// resolves the id; the steering reference is committed (steer) after the
	// headend write succeeds, so a failed write never pins the id.
	var want *policyKey
	if vr.Color != 0 {
		endpoint, perr := netip.ParseAddr(vr.NextHop)
		if perr != nil {
			a.logger.Warn("colored VPN route has no parseable next hop; not steering",
				zap.String("prefix", vr.Prefix), zap.Uint32("color", vr.Color),
				zap.String("nexthop", vr.NextHop))
		} else {
			want = &policyKey{color: vr.Color, endpoint: endpoint}
			entry.PolicyId = a.srPolicy.reserveID(want.color, want.endpoint)
		}
	}
	if err := a.createHeadend(vr.Family, vr.Prefix, entry, owner); err != nil {
		a.logger.Error("install VPN route",
			zap.String("prefix", vr.Prefix), zap.Error(err))
		return
	}
	// The entry is installed -- commit the steering reference (or release a
	// stale one when the route is no longer steered).
	a.steer(rk, want)
	a.logger.Info("VPN route installed",
		zap.String("prefix", vr.Prefix), zap.String("sid", vr.SRv6SID))
}

// steer reconciles a route's SR Policy reference against its desired target
// (want == nil means "not steered") and returns the policy_id to stamp (0
// when unsteered). It diffs against the recorded reference so a re-advertise
// with an unchanged target neither leaks nor double-counts a reference.
func (a *Applier) steer(rk bgp.RouteKey, want *policyKey) uint32 {
	old, had := a.steeredRoutes[rk]
	switch {
	case want == nil:
		if had {
			a.srPolicy.unref(old.color, old.endpoint)
			delete(a.steeredRoutes, rk)
		}
		return 0
	case had && old == *want:
		return a.srPolicy.idOf(want.color, want.endpoint)
	default:
		if had {
			a.srPolicy.unref(old.color, old.endpoint)
		}
		a.steeredRoutes[rk] = *want
		return a.srPolicy.ref(want.color, want.endpoint)
	}
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
		r.NextHop = nh
	}
	if err := a.fib.Add(r); err != nil {
		a.logger.Error("install unicast route",
			zap.String("prefix", ur.Prefix), zap.Error(err))
		return
	}
	a.logger.Info("unicast route installed", zap.String("prefix", ur.Prefix))
}

// buildHeadendEntry assembles an H.Encaps headend entry that encapsulates
// matching traffic towards the remote PE's SRv6 service SID. The single
// segment is the SID itself and the outer destination equals it; parsing
// the SID once via ParseSegments keeps DstAddr and Segments[0]
// byte-identical.
func (a *Applier) buildHeadendEntry(sid string) (*bpf.HeadendEntry, error) {
	src, err := a.encapSource()
	if err != nil {
		return nil, err
	}
	segments, numSegments, err := bpf.ParseSegments([]string{sid})
	if err != nil {
		return nil, fmt.Errorf("parse SRv6 SID %q: %w", sid, err)
	}
	return &bpf.HeadendEntry{
		Mode:        uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS),
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
