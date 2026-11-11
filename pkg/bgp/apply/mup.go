package apply

import (
	"errors"
	"net/netip"
	"slices"
	"strings"

	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/headend"
	"github.com/takehaya/vinbero/pkg/vrf"
)

// mupDefaultArgsOffset is the byte offset within the SID where Args.Mob.Session
// begins on the downlink path (RFC 9433 GTP4: 9 bytes, so offset <= 7). 7 matches
// a /48 locator + 1-byte function, the convention the gtp4-encap example uses,
// and MUST equal the args_offset configured on the remote interwork End.M.GTP4.E.
// Deriving it from the SID Structure sub-TLV is a future refinement (G5).
const mupDefaultArgsOffset = 7

// mupT1STKey identifies an installed downlink (T1ST) headend for withdrawal:
// the {RD, UE prefix} the H.Encaps entry is keyed on.
type mupT1STKey struct {
	rd     string
	prefix string
}

// mupT2STKey identifies an installed uplink (T2ST) F-TEID entry for withdrawal:
// the {RD, endpoint, TEID, TEID-prefix-length} tuple the mup_uplink_v4_map entry
// is keyed on.
type mupT2STKey struct {
	rd       string
	endpoint string
	teid     uint32
	teidLen  uint8
}

// mupISDKey / mupDSDKey identify a received segment-discovery route in the
// resolution tables (and for withdrawal).
type (
	mupISDKey struct{ rd, prefix string }
	mupDSDKey struct{ rd, address string }
)

// mupISDEntry is an Interwork Segment Discovery route: the prefix it covers, the
// interwork SID (locator:function) a T1ST whose gNB endpoint falls inside that
// prefix resolves to, and the route-targets that scope which sessions it may
// resolve -- same-VPN membership, see rtsIntersect.
type mupISDEntry struct {
	prefix netip.Prefix
	sid    string
	rts    []string
}

// mupDSDEntry is a Direct Segment Discovery route: the MUP segment id it carries,
// the direct SID (locator:function) a T2ST tagged with that segment id resolves
// to, and the route-targets that scope resolution to the same VPN (rtsIntersect).
type mupDSDEntry struct {
	segID uint64
	sid   string
	rts   []string
}

// mupSessionState holds a session route (T1ST or T2ST) plus the SID currently
// programmed for it. installedSID is "" when nothing is in the data plane (the
// session is deferred, waiting for a discovery route to resolve its SID); for
// T2ST a non-empty installedSID also means the endpoint gate reference is held.
// deferLogged squelches the per-reconcile "deferred" log so a still-deferred
// session is not re-logged on every unrelated discovery-route event (the
// resolution model re-reconciles every session of a type on each ISD/DSD change).
type mupSessionState struct {
	withdrawn bool
	// A gate can remain held after an uplink create or delete fails. Track it
	// independently of installedSID so retries do not acquire a second reference.
	gateHeld     bool
	route        bgp.MUPRoute
	installedSID string
	// installedSrc is the outer IPv6 source the installed entry carries. It can
	// change while installedSID stays the same (the source locator registered
	// again under another prefix, or for T1ST the GTP4 source embed following
	// the T2ST anchor, see mupGTP4DownlinkSrc), so both reconciles'
	// short-circuits compare both.
	installedSrc [16]byte
	// fam is the route's MUP family (mup_ipv4 / mup_ipv6), kept so the
	// binding-mutation reconcile can re-resolve the VRF without the original
	// apply context.
	fam bgp.Family
	// instance is the vrf_id the session's F-TEID entry is keyed under
	// (0 = the global VRF): the id of the VRF named by the binding whose
	// import RTs matched the route at apply time. Uninstall must use the same
	// value the install used, so it lives on the session, not recomputed ad
	// hoc. T2ST only.
	instance uint32
	// gateVRF is the VRF of the gate the session holds a reference to while
	// gateHeld. T2ST only.
	gateVRF uint32
	// headendVRF is the VRF the installed downlink entry is keyed under while
	// installedSID is set. T1ST only.
	headendVRF  uint32
	deferLogged bool
	// locatorSrc is the source-locator address the session was last written
	// with (zero if never). While the locator is missing a changed SID is
	// written with it. It differs from installedSrc when the GTP4 embed
	// supplied the source.
	locatorSrc [16]byte
	// awaitingSource records that the session could not be written for lack
	// of the source locator and that this was logged, so the reconciles that
	// every discovery-route event runs do not log it again.
	awaitingSource bool
}

// mupUpsertSession returns the session state for key, creating it when absent.
// The per-table cap is enforced only for a NEW key (re-advertising an existing
// session is always honored); ok=false means the table is full and the caller
// must drop the route. Shared by the T1ST and T2ST apply paths.
func mupUpsertSession[K comparable](t map[K]*mupSessionState, key K, max int) (*mupSessionState, bool) {
	if st, ok := t[key]; ok {
		return st, true
	}
	if len(t) >= max {
		return nil, false
	}
	st := &mupSessionState{}
	t[key] = st
	return st, true
}

// Bounds on the remote-controlled MUP tables, mirroring the EVPN applier's
// bounded-table guard (maxTrackedESIs/maxMembersPerESI) so a peer flooding
// routes cannot grow memory — or amplify the reconcile-all cost — without bound.
const (
	maxMUPDiscoveryRoutes = 1024 // ISD or DSD entries per table
	maxMUPSessions        = 4096 // T1ST or T2ST entries (matches mup_uplink map capacity)
)

// mupSegIDNone is the sentinel value mupSegID returns when the BGP MUP Extended
// Community is absent. A genuinely-zero segment id is indistinguishable from
// absent and therefore cannot drive DSD resolution (it falls back to the route's
// own SID), which is acceptable: 0 is not a valid advertised segment id here.
const mupSegIDNone uint64 = 0

// mupSegID packs the two halves of a BGP MUP Extended Community segment id into
// one comparable key (see mupSegIDNone for the absent case).
func mupSegID(s2 uint16, s4 uint32) uint64 { return uint64(s2)<<32 | uint64(s4) }

// rtsIntersect reports whether two route-target lists share at least one
// RT. MUP segment-discovery and session routes resolve against each other
// only when they belong to the same VPN, and route-target membership --
// not RD, which is per-advertiser -- defines a VPN (RFC 4364 §4.3). Two
// empty lists do not intersect, so a route carrying no RT resolves
// nothing. The lists are short, so a nested scan is fine.
func rtsIntersect(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

// applyMUP turns a received BGP MUP route (SAFI 85, draft-mpmz-bess-mup-safi)
// into Vinbero data-plane state.
//
// Segment discovery and session transformed routes resolve against each
// other (RFC 9433 §3): a T1ST's interwork SID comes from the ISD whose
// prefix covers its gNB endpoint, and a T2ST's direct SID from the DSD
// carrying its segment id. When no discovery route resolves, the session
// falls back to the SID on its own Prefix-SID attribute. Arrival order
// does not matter: a discovery route that arrives later re-resolves any
// deferred sessions, and a withdrawal tears down (or re-resolves) the
// ones that depended on it.
//
// fam scopes the optional import-RT filter: once any VRF binding declares
// the matching MUP family, a received SESSION route (T1ST/T2ST) must carry
// an RT some VRF imports. ISD/DSD discovery routes bypass the filter
// because they carry the controller/gateway's own RTs and feed cross-VRF
// resolution. Withdraws also bypass it so a route accepted earlier is
// always torn down. A Manager with no MUP-family binding keeps the
// historical default-allow.
func (a *Applier) applyMUP(fam bgp.Family, r *bgp.MUPRoute, withdraw bool) {
	a.mupMu.Lock()
	defer a.mupMu.Unlock()
	defer a.flushTrackedFailure(&a.mupWriteFailed)
	a.retryMUPOwnedCleanup()
	sessionRoute := r.Type == bgp.MUPRouteTypeT1ST || r.Type == bgp.MUPRouteTypeT2ST
	if !withdraw && sessionRoute && !a.mupDefaultAllow && !a.vrfBindings.EmptyForFamily(fam) {
		if _, _, ok := a.vrfBindings.MatchImportForFamily(r.RTs, fam); !ok {
			// A BGP UPDATE is an implicit replace: a session route imported
			// earlier must not survive a re-advertisement whose RTs no
			// longer match any import filter. Dispatching it as a withdraw
			// removes exactly this NLRI's tracked state (a no-op when
			// nothing was installed).
			// A loc-rib replay revisits every route no VRF imports;
			// warning for each would repeat the whole rib.
			log := a.logger.Warn
			if a.replaying.Load() {
				log = a.logger.Debug
			}
			log("MUP route matches no VRF import RT; removing any previous session",
				zap.String("type", r.Type.String()),
				zap.String("rd", r.RD), zap.Strings("rts", r.RTs))
			withdraw = true
		}
	}
	switch r.Type {
	case bgp.MUPRouteTypeISD:
		a.applyMUPISD(r, withdraw)
	case bgp.MUPRouteTypeDSD:
		a.applyMUPDSD(r, withdraw)
	case bgp.MUPRouteTypeT1ST:
		a.applyMUPT1ST(fam, r, withdraw)
	case bgp.MUPRouteTypeT2ST:
		a.applyMUPT2ST(fam, r, withdraw)
	default:
		a.logger.Warn("unknown MUP route type", zap.String("type", r.Type.String()))
	}
}

// applyMUPISD records (or removes) an Interwork Segment Discovery route in the
// resolution table, then re-reconciles every downlink session: an arriving ISD
// may satisfy a deferred T1ST, a withdrawn one may strand an installed T1ST.
func (a *Applier) applyMUPISD(r *bgp.MUPRoute, withdraw bool) {
	prefix, err := netip.ParsePrefix(r.Prefix)
	if err != nil {
		a.logger.Error("parse MUP ISD prefix", zap.String("prefix", r.Prefix), zap.Error(err))
		return
	}
	key := mupISDKey{rd: r.RD, prefix: r.Prefix}
	if withdraw {
		delete(a.mupISD, key)
	} else if !isUsableSRv6SID(r.SRv6SID) {
		// A BGP UPDATE is an implicit replace: a re-advertisement whose SID
		// became unusable (empty, all-zero, or otherwise not a routable
		// IPv6 SID -- including one invalidated on decode per RFC 9252 §7)
		// must stop this key resolving, exactly like a withdraw -- an
		// earlier discovery left in place would keep steering sessions
		// over a path the route no longer backs. An untracked key returns
		// before the sweep so a flood of unusable advertisements cannot
		// drive the reconcile-all loop.
		a.logger.Warn("MUP ISD has no usable SRv6 SID; removing any previous discovery",
			zap.String("prefix", r.Prefix), zap.String("sid", r.SRv6SID), zap.String("rd", r.RD))
		if _, tracked := a.mupISD[key]; !tracked {
			return
		}
		delete(a.mupISD, key)
	} else {
		if _, exists := a.mupISD[key]; !exists && len(a.mupISD) >= maxMUPDiscoveryRoutes {
			a.logger.Warn("MUP ISD table full; dropping route",
				zap.Int("max", maxMUPDiscoveryRoutes),
				zap.String("rd", r.RD), zap.String("prefix", r.Prefix))
			return
		}
		a.mupISD[key] = mupISDEntry{prefix: prefix, sid: r.SRv6SID, rts: slices.Clone(r.RTs)}
	}
	a.logger.Info("MUP ISD segment discovery",
		zap.Bool("withdraw", withdraw), zap.String("rd", r.RD),
		zap.String("prefix", r.Prefix), zap.String("sid", r.SRv6SID))
	for k := range a.mupT1ST {
		a.reconcileMUPT1ST(k)
	}
}

// applyMUPDSD records (or removes) a Direct Segment Discovery route in the
// resolution table, keyed by its MUP segment id, then re-reconciles every
// uplink session.
func (a *Applier) applyMUPDSD(r *bgp.MUPRoute, withdraw bool) {
	key := mupDSDKey{rd: r.RD, address: r.Address}
	if withdraw {
		delete(a.mupDSD, key)
	} else if !isUsableSRv6SID(r.SRv6SID) {
		// Same implicit-replace rule as ISD: an unusable SID on a
		// re-advertisement removes the previous discovery, and an
		// untracked key returns before the reconcile sweep.
		a.logger.Warn("MUP DSD has no usable SRv6 SID; removing any previous discovery",
			zap.String("address", r.Address), zap.String("sid", r.SRv6SID), zap.String("rd", r.RD))
		if _, tracked := a.mupDSD[key]; !tracked {
			return
		}
		delete(a.mupDSD, key)
	} else {
		if _, exists := a.mupDSD[key]; !exists && len(a.mupDSD) >= maxMUPDiscoveryRoutes {
			a.logger.Warn("MUP DSD table full; dropping route",
				zap.Int("max", maxMUPDiscoveryRoutes),
				zap.String("rd", r.RD), zap.String("address", r.Address))
			return
		}
		seg := mupSegID(r.SegmentID2, r.SegmentID4)
		// A same-VPN segment-id collision (two DSDs, same id, different SID)
		// still resolves deterministically in resolveDirectSID (lowest SID),
		// but the operator should know about the ambiguity.
		if seg != mupSegIDNone {
			for ek, ev := range a.mupDSD {
				if ek.address != r.Address && rtsIntersect(ev.rts, r.RTs) && ev.segID == seg && ev.sid != r.SRv6SID {
					a.logger.Warn("MUP DSD segment-id collision; resolution is deterministic but ambiguous",
						zap.String("rd", r.RD), zap.Uint64("segment_id", seg),
						zap.String("address", r.Address), zap.String("other_address", ek.address))
					break
				}
			}
		}
		a.mupDSD[key] = mupDSDEntry{segID: seg, sid: r.SRv6SID, rts: slices.Clone(r.RTs)}
	}
	a.logger.Info("MUP DSD segment discovery",
		zap.Bool("withdraw", withdraw), zap.String("rd", r.RD),
		zap.String("address", r.Address), zap.String("sid", r.SRv6SID))
	for k := range a.mupT2ST {
		a.reconcileMUPT2ST(k)
	}
}

// resolveInterworkSID returns the interwork SID for a T1ST: the
// longest-match ISD, within the session's VPN (RT-scoped via rtsIntersect),
// whose prefix contains the gNB endpoint. Falls back to the route's own
// Prefix-SID; "" means unresolvable (defer the session). On a longest-prefix
// tie across RDs the lexicographically lowest SID wins, so resolution stays
// deterministic regardless of map iteration order.
func (a *Applier) resolveInterworkSID(r *bgp.MUPRoute, ep netip.Addr) string {
	best, bestBits := "", -1
	for _, e := range a.mupISD {
		if !rtsIntersect(e.rts, r.RTs) || !e.prefix.Contains(ep) {
			continue
		}
		bits := e.prefix.Bits()
		if bits > bestBits || (bits == bestBits && e.sid < best) {
			best, bestBits = e.sid, bits
		}
	}
	if best != "" {
		return best
	}
	return r.SRv6SID
}

// resolveDirectSID returns the direct SID for a T2ST: the DSD within the
// session's VPN (RT-scoped) carrying the same MUP segment id. Falls back
// to the route's own Prefix-SID; "" means unresolvable. A same-VPN
// segment-id collision is logged at insert (applyMUPDSD); here we still
// pick deterministically -- the lexicographically lowest SID -- so a
// benign duplicate cannot make the F-TEID flap across reconciles.
func (a *Applier) resolveDirectSID(r *bgp.MUPRoute) string {
	seg := mupSegID(r.SegmentID2, r.SegmentID4)
	if seg == mupSegIDNone {
		return r.SRv6SID
	}
	best := ""
	for _, e := range a.mupDSD {
		if !rtsIntersect(e.rts, r.RTs) || e.segID != seg {
			continue
		}
		if best == "" || e.sid < best {
			best = e.sid
		}
	}
	if best != "" {
		return best
	}
	return r.SRv6SID
}

// applyMUPT1ST records (or withdraws) a per-UE downlink session, then
// reconciles its data-plane install against the current ISD table.
//
// The key is {RD, UE prefix} -- NOT keyed on TEID, unlike T2ST -- because
// the headend map is keyed on the UE prefix, so Vinbero holds exactly one
// downlink transform per UE prefix (last advertise wins). The route's TEID
// rides in the composed SID, so a re-advertise with a different TEID
// replaces the install.
func (a *Applier) applyMUPT1ST(fam bgp.Family, r *bgp.MUPRoute, withdraw bool) {
	key := mupT1STKey{rd: r.RD, prefix: r.Prefix}
	if withdraw {
		st, ok := a.mupT1ST[key]
		if !ok {
			return
		}
		// Ignore a withdraw whose TEID does not match the installed session: it is
		// for a superseded T1ST that a newer advertise on the same UE prefix already
		// replaced. Tearing down here would remove the active downlink (the bug the
		// {RD,prefix}-only key would otherwise hide).
		if st.route.TEID != r.TEID {
			return
		}
		if st.installedSID != "" {
			a.uninstallMUPT1ST(st)
		}
		delete(a.mupT1ST, key)
		return
	}
	// Validate the parseable fields once here so a re-reconcile triggered by an
	// unrelated ISD does not re-log the same parse error.
	if _, err := netip.ParsePrefix(r.Prefix); err != nil {
		a.logger.Error("parse MUP T1ST UE prefix", zap.String("ue_prefix", r.Prefix), zap.Error(err))
		return
	}
	if _, err := netip.ParseAddr(r.Endpoint); err != nil {
		a.logger.Error("parse MUP T1ST endpoint", zap.String("endpoint", r.Endpoint), zap.Error(err))
		return
	}
	// Update the route in place on a re-advertise so installedSID is preserved;
	// reconcile then no-ops when the resolved SID is unchanged (the F-TEID/gate
	// state must not churn on a BGP refresh or current=true replay).
	st, ok := mupUpsertSession(a.mupT1ST, key, maxMUPSessions)
	if !ok {
		a.logger.Warn("MUP T1ST table full; dropping route",
			zap.Int("max", maxMUPSessions), zap.String("rd", r.RD), zap.String("ue_prefix", r.Prefix))
		return
	}
	if r.SRv6SID != "" && !isUsableSRv6SID(r.SRv6SID) {
		// An unusable own Prefix-SID (e.g. an all-zero "::") is normalized
		// to the empty fallback: resolution then goes through discovery
		// alone, and a session no discovery covers is torn down by the
		// reconcile instead of being (re-)installed toward the bad SID.
		a.logger.Warn("MUP session route has an unusable own SRv6 SID; treating as absent",
			zap.String("rd", r.RD), zap.String("sid", r.SRv6SID))
		rr := *r
		rr.SRv6SID = ""
		r = &rr
	}
	st.route = *r
	st.fam = fam
	a.reconcileMUPT1ST(key)
}

// reconcileMUPT1ST (re)programs one downlink session: it resolves the interwork
// SID, composes Args.Mob.Session onto it, and installs the H.Encaps entry on the
// UE prefix. An unresolvable SID tears down any prior install and waits; an
// unchanged SID is a no-op so re-resolution does not churn the data plane.
// It reports false when a data-plane write failed, which a later reconcile
// can fix.
func (a *Applier) reconcileMUPT1ST(key mupT1STKey) bool {
	st, ok := a.mupT1ST[key]
	if !ok {
		return true
	}
	r := &st.route
	uePrefix, _ := netip.ParsePrefix(r.Prefix) // validated in applyMUPT1ST
	endpoint, _ := netip.ParseAddr(r.Endpoint) // validated in applyMUPT1ST

	base := a.resolveInterworkSID(r, endpoint)
	if base == "" {
		if st.installedSID != "" {
			a.uninstallMUPT1ST(st)
		}
		// Log the deferral only on the transition into it, not on every unrelated
		// ISD/DSD event that re-reconciles this still-deferred session.
		if !st.deferLogged {
			a.logger.Info("MUP T1ST downlink deferred (no interwork SID yet)",
				zap.String("ue_prefix", r.Prefix), zap.String("endpoint", r.Endpoint))
			st.deferLogged = true
		}
		return true
	}
	st.deferLogged = false

	// GTP6 args carry only TEID+QFI (the gNB IPv6 lives in the End.M.GTP6.E aux);
	// GTP4 args also carry the gNB IPv4 destination.
	var composed string
	var err error
	if endpoint.Is6() {
		composed, err = bpf.ComposeGTP6ArgsSID(base, mupDefaultArgsOffset, r.TEID, r.QFI, r.RQI)
	} else {
		composed, err = bpf.ComposeGTP4ArgsSID(base, mupDefaultArgsOffset, r.Endpoint, r.TEID, r.QFI, r.RQI)
	}
	if err != nil {
		a.logger.Error("compose MUP T1ST interwork SID",
			zap.String("ue_prefix", r.Prefix), zap.String("sid", base),
			zap.String("endpoint", r.Endpoint), zap.Error(err))
		return true
	}

	// The GTP4 embed derives the source from the binding, so only the plain
	// downlink needs the source locator.
	src, embedded := a.mupGTP4DownlinkSrc(r, endpoint)
	if !embedded {
		var ok bool
		if src, ok = a.mupEncapSource(st, "ue_prefix", r.Prefix); !ok {
			return true
		}
	}
	instance, _ := a.mupVRFForRoute(st.fam, r)
	vrfID := a.mupHeadendVRF(instance)
	if st.installedSID == composed && st.installedSrc == src && st.headendVRF == vrfID {
		return true // already programmed with this SID and source, in this VRF
	}
	entry, err := buildHeadendEntryFrom(src, composed, false)
	if err != nil {
		a.logger.Error("build MUP T1ST headend entry",
			zap.String("ue_prefix", r.Prefix), zap.Error(err))
		return true
	}

	createHeadend, _ := a.mupT1STHeadendFns(uePrefix)
	owner := bpf.OwnerBGPMUP(a.localASN, r.RD)
	if err := createHeadend(vrfID, r.Prefix, entry, owner); err != nil {
		a.logger.Error("install MUP T1ST headend",
			zap.Uint32("vrf_id", vrfID), zap.String("ue_prefix", r.Prefix), zap.Error(err))
		return a.mupFailed()
	}
	// The entry is this session's again: an earlier failed removal of the
	// same key must not delete it later.
	delete(a.mupT1STStale, mupT1STEntry{vrf: vrfID, prefix: r.Prefix, owner: owner})
	if st.installedSID != "" && st.headendVRF != vrfID {
		// The session moved to another VRF: the new entry is in place, so
		// the old one goes. A failed removal is retried by the tracked pass.
		a.removeMUPT1STEntry(mupT1STEntry{vrf: st.headendVRF, prefix: r.Prefix, owner: owner})
	}
	st.installedSID = composed
	st.installedSrc = entry.SrcAddr
	st.headendVRF = vrfID
	if !embedded {
		st.locatorSrc = src
	}
	a.logger.Info("MUP T1ST downlink installed",
		zap.Uint32("vrf_id", vrfID), zap.String("ue_prefix", r.Prefix), zap.String("endpoint", r.Endpoint),
		zap.Uint32("teid", r.TEID), zap.Uint8("qfi", r.QFI), zap.String("sid", composed),
		zap.String("src", netip.AddrFrom16(entry.SrcAddr).String()))
	return true
}

// mupGTP4SrcPrefixForRD returns the GTP4 downlink source prefix of the unique
// VRF binding whose RD is rd. ok=false when no (or an ambiguous) binding
// matches, or the binding carries no prefix — BindingByRD's refuse-to-guess
// rule means a duplicated RD silently disables the embed for that RD until
// the operator resolves the ambiguity.
func (a *Applier) mupGTP4SrcPrefixForRD(rd string) (netip.Prefix, bool) {
	b, ok := a.vrfBindings.BindingByRD(rd)
	if !ok || !b.MupGTP4SourcePrefix.IsValid() {
		return netip.Prefix{}, false
	}
	return b.MupGTP4SourcePrefix, true
}

// mupGTP4DownlinkSrc synthesizes the outer IPv6 source for a GTP4 downlink
// session per RFC 9433 §6.6: the source prefix of the session RD's VRF
// binding with the session's UPF IPv4 anchor embedded immediately after the
// prefix bits, so the peer GW's End.M.GTP4.E extracts it as the GTP-U outer
// IPv4 source (v4src_position = prefix length). The anchor is the IPv4
// endpoint of a same-RD T2ST whose TEID prefix covers this session's TEID —
// the controller distributes the UPF N3 address as session state, so no
// extra config names it here. ok=false (the caller keeps the plain
// locator-derived encap source) when no binding carries a prefix for the RD,
// the session is not GTP4, or no anchor is known yet; a later T2ST or
// binding mutation re-reconciles the session (see applyMUPT2ST and
// ReconcileMUPGTP4SrcForRD).
func (a *Applier) mupGTP4DownlinkSrc(r *bgp.MUPRoute, endpoint netip.Addr) ([16]byte, bool) {
	var zero [16]byte
	if !endpoint.Is4() {
		return zero, false
	}
	pfx, ok := a.mupGTP4SrcPrefixForRD(r.RD)
	if !ok {
		return zero, false
	}
	anchor, ok := a.mupT2STAnchor(r.RD, r.TEID)
	if !ok {
		return zero, false
	}
	return embedV4AfterPrefix(pfx, anchor), true
}

// mupT2STAnchor returns the UPF IPv4 anchor for a downlink session: the IPv4
// endpoint of a same-RD T2ST whose TEID prefix matches teid. The longest
// TEID-prefix match wins; among equals the lexicographically smallest endpoint
// keeps the choice deterministic across map iteration order.
func (a *Applier) mupT2STAnchor(rd string, teid uint32) (netip.Addr, bool) {
	var (
		best    netip.Addr
		bestLen = -1
	)
	for key := range a.mupT2ST {
		if key.rd != rd || key.teidLen > 32 {
			continue
		}
		ep, err := netip.ParseAddr(key.endpoint)
		if err != nil || !ep.Is4() {
			continue
		}
		var mask uint32
		if key.teidLen > 0 {
			mask = ^uint32(0) << (32 - key.teidLen)
		}
		if (teid & mask) != (key.teid & mask) {
			continue
		}
		if int(key.teidLen) > bestLen || (int(key.teidLen) == bestLen && ep.Less(best)) {
			best, bestLen = ep, int(key.teidLen)
		}
	}
	return best, bestLen >= 0
}

// embedV4AfterPrefix places the 32 bits of v4 immediately after the prefix
// bits of p (everything past them is zero): the RFC 9433 §6.6
// [Source UPF Prefix][IPv4 SA][padding] IPv6 source-address layout.
func embedV4AfterPrefix(p netip.Prefix, v4 netip.Addr) [16]byte {
	out := p.Masked().Addr().As16()
	v4b := v4.As4()
	off := p.Bits()
	for i := range 32 {
		if (v4b[i/8]>>(7-i%8))&1 == 1 {
			pos := off + i
			out[pos/8] |= 1 << (7 - pos%8)
		}
	}
	return out
}

// uninstallMUPT1ST removes a downlink session's headend entry and marks it
// uninstalled. A failed removal is kept apart from the session
// (mupT1STStale) and retried by the tracked pass, so the session can be
// forgotten on a withdraw while its entry is still being removed.
func (a *Applier) uninstallMUPT1ST(st *mupSessionState) {
	r := &st.route
	a.removeMUPT1STEntry(mupT1STEntry{vrf: st.headendVRF, prefix: r.Prefix, owner: bpf.OwnerBGPMUP(a.localASN, r.RD)})
	st.installedSID = ""
	st.installedSrc = [16]byte{}
}

// mupT1STEntry is one downlink headend entry the applier wrote.
type mupT1STEntry struct {
	vrf    uint32
	prefix string
	owner  bpf.OwnerTag
}

// removeMUPT1STEntry deletes one downlink entry, and records it for the
// tracked pass when the delete fails. It reports whether it is gone.
func (a *Applier) removeMUPT1STEntry(e mupT1STEntry) bool {
	uePrefix, err := netip.ParsePrefix(e.prefix)
	if err != nil {
		delete(a.mupT1STStale, e)
		return true
	}
	_, deleteHeadend := a.mupT1STHeadendFns(uePrefix)
	// An entry another owner holds now is not this session's to remove.
	if err := deleteHeadend(e.vrf, e.prefix, e.owner); err != nil && !errors.Is(err, bpf.ErrEntryOwnerMismatch) {
		a.logger.Error("withdraw MUP T1ST headend; retrying",
			zap.Uint32("vrf_id", e.vrf), zap.String("ue_prefix", e.prefix), zap.Error(err))
		a.mupT1STStale[e] = struct{}{}
		a.mupFailed()
		return false
	}
	delete(a.mupT1STStale, e)
	return true
}

// retryMUPT1STStale removes again the downlink entries whose removal failed.
// It returns how many are still left. Callers hold mupMu.
func (a *Applier) retryMUPT1STStale() int {
	left := 0
	for e := range a.mupT1STStale {
		if !a.removeMUPT1STEntry(e) {
			left++
		}
	}
	return left
}

// mupEncapSource resolves the encapsulation source for one session
// reconcile. Without the source locator, a session written earlier with the
// locator's address keeps it, so a changed SID is still written (deleting
// the locator logs that once); one never written is logged once and waits
// for ReconcileTracked. key / value name the session in that log.
func (a *Applier) mupEncapSource(st *mupSessionState, key, value string) ([16]byte, bool) {
	src, err := a.encapSource()
	if err != nil {
		if st.installedSID != "" && st.locatorSrc != ([16]byte{}) {
			return st.locatorSrc, true
		}
		if st.installedSID == "" && !st.awaitingSource {
			st.awaitingSource = true
			a.logger.Warn("MUP session not installed until the source locator is registered",
				zap.String(key, value), zap.Error(err))
		}
		return src, false
	}
	st.awaitingSource = false
	return src, true
}

// mupT1STHeadendFns selects the headend map writers for the UE prefix's family.
func (a *Applier) mupT1STHeadendFns(uePrefix netip.Prefix) (headendCreateFn, headendDeleteFn) {
	if uePrefix.Addr().Is6() {
		return a.headend.CreateHeadendV6In, a.headend.DeleteHeadendV6In
	}
	return a.headend.CreateHeadendV4In, a.headend.DeleteHeadendV4In
}

// headendCreateFn / headendDeleteFn are the headend map writers (v4 or v6) the
// downlink headend and the uplink gate are installed through, selected by the
// relevant address family. The first argument is the VRF.
type (
	headendCreateFn func(uint32, string, *bpf.HeadendEntry, bpf.OwnerTag) error
	headendDeleteFn func(uint32, string, bpf.OwnerTag) error
)

// mupHeadendVRF is the VRF of the headend map a MUP session whose route
// resolved to instance writes: the downlink entry of a T1ST and the gate of
// a T2ST. It is the session's own VRF, where the packets it serves (DN
// traffic toward the UE, GTP-U from the access side) are looked up.
func (a *Applier) mupHeadendVRF(instance uint32) uint32 { return instance }

// mupT2STDataPlane bundles the family-specific data-plane selectors for an
// uplink session: the F-TEID map writers, the gate behavior/prefix, and the gate
// map writers. GTP4 vs GTP6 is the endpoint's address family.
type mupT2STDataPlane struct {
	uplinkCreate func(uint32, string, uint32, uint8, *bpf.HeadendEntry, bpf.OwnerTag) error
	uplinkDelete func(uint32, string, uint32, uint8, bpf.OwnerTag) error
	gateMode     uint8
	createGate   headendCreateFn
	deleteGate   headendDeleteFn
	gatePrefix   string
}

func (a *Applier) mupT2STDataPlane(endpoint netip.Addr, endpointStr string) mupT2STDataPlane {
	if endpoint.Is6() {
		return mupT2STDataPlane{
			uplinkCreate: a.createMUPUplinkOwned,
			uplinkDelete: a.mupUplink.DeleteMupUplinkV6Owned,
			gateMode:     uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_M_GTP6_D_TEID),
			createGate:   a.headend.CreateHeadendV6In,
			deleteGate:   a.headend.DeleteHeadendV6In,
			gatePrefix:   endpointStr + "/128",
		}
	}
	return mupT2STDataPlane{
		uplinkCreate: a.createMUPUplinkOwned,
		uplinkDelete: a.mupUplink.DeleteMupUplinkV4Owned,
		gateMode:     uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_M_GTP4_D_TEID),
		createGate:   a.headend.CreateHeadendV4In,
		deleteGate:   a.headend.DeleteHeadendV4In,
		gatePrefix:   endpointStr + "/32",
	}
}

// applyMUPT2ST records (or withdraws) an uplink session, then reconciles its
// data-plane install against the current DSD table. fam scopes the uplink
// instance resolution: the session installs under the instance of the binding
// whose import RTs matched it (0 = default).
func (a *Applier) applyMUPT2ST(fam bgp.Family, r *bgp.MUPRoute, withdraw bool) {
	key := mupT2STKey{rd: r.RD, endpoint: r.Endpoint, teid: r.TEID, teidLen: r.TEIDLen}
	if withdraw {
		st, ok := a.mupT2ST[key]
		if !ok {
			return
		}
		st.withdrawn = true
		if (st.installedSID != "" || st.gateHeld) && !a.uninstallMUPT2ST(st) {
			return
		}
		delete(a.mupT2ST, key)
		a.reconcileMUPT1STForGTP4Src(r.RD)
		return
	}
	if _, err := netip.ParseAddr(r.Endpoint); err != nil {
		a.logger.Error("parse MUP T2ST endpoint", zap.String("endpoint", r.Endpoint), zap.Error(err))
		return
	}
	// Update the route in place on a re-advertise so installedSID (and the gate
	// reference it implies) is preserved; reconcile no-ops when the resolved SID
	// is unchanged, so a BGP refresh never re-acquires the gate.
	st, ok := mupUpsertSession(a.mupT2ST, key, maxMUPSessions)
	if !ok {
		a.logger.Warn("MUP T2ST table full; dropping route",
			zap.Int("max", maxMUPSessions), zap.String("rd", r.RD), zap.String("endpoint", r.Endpoint))
		return
	}
	// A re-advertise can land on a different vrf_id when the bindings moved
	// underneath it. The session key {rd, endpoint, teid, teidLen} is the
	// F-TEID key minus the vrf_id, so an installed entry can move without
	// touching the shared gate; a failed move keeps the session on its old
	// vrf_id until the next reconcile.
	vrfID, _ := a.mupVRFForRoute(fam, r)
	if st.installedSID != "" && st.instance != vrfID {
		a.rekeyMUPT2ST(st, vrfID)
	} else if st.installedSID == "" {
		st.instance = vrfID
	}
	if r.SRv6SID != "" && !isUsableSRv6SID(r.SRv6SID) {
		// An unusable own Prefix-SID (e.g. an all-zero "::") is normalized
		// to the empty fallback: resolution then goes through discovery
		// alone, and a session no discovery covers is torn down by the
		// reconcile instead of being (re-)installed toward the bad SID.
		a.logger.Warn("MUP session route has an unusable own SRv6 SID; treating as absent",
			zap.String("rd", r.RD), zap.String("sid", r.SRv6SID))
		rr := *r
		rr.SRv6SID = ""
		r = &rr
	}
	st.route = *r
	st.withdrawn = false
	st.fam = fam
	a.reconcileMUPT2ST(key)
	a.reconcileMUPT1STForGTP4Src(r.RD)
}

// rekeyMUPT2ST moves an installed uplink session's F-TEID entry to a new
// instance. Put-new-then-delete-old, so the F-TEID entry never disappears
// for the instance it lives in; a failed Put keeps the session fully on its
// old instance (retried by the next reconcile).
//
// The gate follows the session when the new instance's gate is in another
// VRF (mupHeadendVRF): the new gate is taken before the new F-TEID entry is
// written, and the old one released after the old entry is gone. When both
// instances share the gate's VRF it is left alone, so the endpoint's last
// session moving does not delete and recreate it -- a window where GTP-U
// passes unprocessed.
//
// It reports false when a write failed and the session stayed where it was.
func (a *Applier) rekeyMUPT2ST(st *mupSessionState, inst uint32) bool {
	r := &st.route
	endpoint, _ := netip.ParseAddr(r.Endpoint) // validated at apply time
	dp := a.mupT2STDataPlane(endpoint, r.Endpoint)
	// The entry moves as it is written; a new source is the reconcile's job.
	entry, err := buildHeadendEntryFrom(st.installedSrc, st.installedSID, false)
	if err != nil {
		a.logger.Error("re-key MUP T2ST uplink entry (keeping old instance)",
			zap.String("endpoint", r.Endpoint), zap.Uint32("teid", r.TEID), zap.Error(err))
		return true
	}
	entry.ArgsOffset = bpf.MupArgsOffsetNone
	gateOwner := bpf.OwnerBGPMUPGate(a.localASN)
	newGate := a.mupHeadendVRF(inst)
	moveGate := st.gateHeld && newGate != st.gateVRF
	if moveGate {
		if err := a.acquireMUPGate(newGate, dp.gatePrefix, dp.gateMode, gateOwner, dp.createGate); err != nil {
			a.logger.Error("re-key MUP T2ST gate (keeping old instance)",
				zap.String("endpoint", r.Endpoint), zap.Uint32("vrf_id", newGate), zap.Error(err))
			return a.mupFailed()
		}
	}
	if err := dp.uplinkCreate(inst, r.Endpoint, r.TEID, r.TEIDLen, entry, bpf.OwnerBGPMUP(a.localASN, r.RD)); err != nil {
		a.logger.Error("re-key MUP T2ST uplink entry (keeping old instance)",
			zap.String("endpoint", r.Endpoint), zap.Uint32("teid", r.TEID),
			zap.Uint32("instance", inst), zap.Error(err))
		if moveGate && !a.releaseMUPGate(newGate, dp.gatePrefix, gateOwner, dp.deleteGate) {
			a.oweMUPGateRelease(mupGateKey{vrf: newGate, prefix: dp.gatePrefix})
		}
		return a.mupFailed()
	}
	if err := dp.uplinkDelete(st.instance, r.Endpoint, r.TEID, r.TEIDLen, bpf.OwnerBGPMUP(a.localASN, r.RD)); err != nil {
		a.logger.Error("remove old-instance MUP T2ST uplink entry (retaining for retry)",
			zap.String("endpoint", r.Endpoint), zap.Uint32("teid", r.TEID),
			zap.Uint32("instance", st.instance), zap.Error(err))
		// The startup-style cleanup keeps the old instance's gate while the
		// old entry is still there.
		a.rememberMUPOwnedCleanup(mupRecoveryKey{st.instance, endpoint, r.TEID, r.TEIDLen, bpf.OwnerBGPMUP(a.localASN, r.RD)})
	}
	// The session has moved; a release still owed is reported as a failed
	// write so the tracked pass runs again to pay it.
	moved := true
	if moveGate {
		if !a.releaseMUPGate(st.gateVRF, dp.gatePrefix, gateOwner, dp.deleteGate) {
			a.oweMUPGateRelease(mupGateKey{vrf: st.gateVRF, prefix: dp.gatePrefix})
			moved = false
		}
		st.gateVRF = newGate
	}
	old := st.instance
	st.instance = inst
	a.logger.Info("MUP T2ST uplink re-keyed",
		zap.String("endpoint", r.Endpoint), zap.Uint32("teid", r.TEID),
		zap.Uint32("from_vrf_id", old), zap.Uint32("vrf_id", inst))
	return moved
}

// mupVRFForRoute resolves the VRF a MUP session belongs to: the id of the
// VRF named by the binding whose import RTs match the route for fam, the
// lowest VRF name when several do (a session is placed in one VRF only).
// accepted reports whether the session may be installed at all: it may when
// a binding matches, when no binding declares fam (default-allow) or when
// bgp.global.mup_default_allow is set; the last two place a session no
// binding matches in the global VRF (id 0). The {ifindex,vlan} -> vrf_id
// ingress side is owned by vrf.Manager (programmed from the VRF's ACs), so
// this only resolves the install-side id; the two agree because they
// reference the same VRF.
func (a *Applier) mupVRFForRoute(fam bgp.Family, r *bgp.MUPRoute) (id uint32, accepted bool) {
	vrfName, _, ok := a.vrfBindings.MatchImportForFamily(r.RTs, fam)
	if !ok {
		return vrf.GlobalVRFID, a.mupDefaultAllow || a.vrfBindings.EmptyForFamily(fam)
	}
	id, _ = a.vrfBindings.VRF().IDForName(vrfName)
	return id, true
}

// ReconcileMUPUplinkInstances moves every tracked MUP session to the VRF its
// route resolves to after a VRF binding mutation (an RT change can move a
// session to a different VRF, or an unbind back to the global VRF): a T2ST's
// F-TEID entry and gate are re-keyed, a T1ST's downlink entry is written in
// the new VRF and removed from the old one. A session no binding accepts any
// more (its family is declared and no import RT matches it, without
// mup_default_allow) is removed, as an UPDATE with such RTs would be; a later
// binding that imports it again brings it back through the MUP loc-rib
// replay. It does NOT touch ingress_vrf_map — that is owned by vrf.Manager
// and programmed from the VRFs' ACs (VrfService), independent of which
// binding a route matches. Safe to call from RPC goroutines (mupMu).
func (a *Applier) ReconcileMUPUplinkInstances() {
	a.mupMu.Lock()
	defer a.mupMu.Unlock()
	defer a.flushTrackedFailure(&a.mupWriteFailed)
	release := a.vrfBindings.VRF().HoldIDs()
	defer release()
	a.retryMUPOwnedCleanup()
	for key, st := range a.mupT2ST {
		id, accepted := a.mupVRFForRoute(st.fam, &st.route)
		if !accepted && !st.withdrawn {
			a.logger.Warn("MUP session no longer matches a VRF import RT; removing it",
				zap.String("type", "T2ST"), zap.String("rd", st.route.RD),
				zap.String("endpoint", st.route.Endpoint), zap.Strings("rts", st.route.RTs))
			st.withdrawn = true
			if (st.installedSID == "" && !st.gateHeld) || a.uninstallMUPT2ST(st) {
				delete(a.mupT2ST, key)
			}
			continue
		}
		if st.withdrawn || id == st.instance {
			continue
		}
		if st.installedSID == "" {
			// Deferred session: nothing in the data plane to move, and a
			// binding change cannot make its SID resolvable (resolution is
			// RT-scoped between routes), so just adopt the new vrf_id.
			st.instance = id
			continue
		}
		a.rekeyMUPT2ST(st, id) // a failed move is retried by reconcileMUPT2ST
	}
	for key, st := range a.mupT1ST {
		if _, accepted := a.mupVRFForRoute(st.fam, &st.route); !accepted {
			a.logger.Warn("MUP session no longer matches a VRF import RT; removing it",
				zap.String("type", "T1ST"), zap.String("rd", st.route.RD),
				zap.String("ue_prefix", st.route.Prefix), zap.Strings("rts", st.route.RTs))
			if st.installedSID != "" {
				a.uninstallMUPT1ST(st)
			}
			delete(a.mupT1ST, key)
			continue
		}
		// Writes the downlink in the session's current VRF and removes it
		// from the one it was in.
		a.reconcileMUPT1ST(key)
	}
}

// reconcileMUPT1STForGTP4Src re-reconciles rd's downlink sessions after its
// T2ST table changed. Only relevant when rd's binding carries a GTP4 source
// prefix: the embedded source follows the session's same-RD T2ST anchor
// (mupGTP4DownlinkSrc), so a T2ST arriving after its T1ST upgrades the
// install, and a withdraw reverts it to the plain encap source. Reconcile
// no-ops on sessions whose SID and source are unchanged. Gating on the
// prefix here is safe: an embed-installed session whose prefix later
// disappears is reverted by ReconcileMUPGTP4SrcForRD (the binding-mutation
// hook), not by this T2ST-driven path.
func (a *Applier) reconcileMUPT1STForGTP4Src(rd string) {
	if _, ok := a.mupGTP4SrcPrefixForRD(rd); !ok {
		return
	}
	for k := range a.mupT1ST {
		if k.rd == rd {
			a.reconcileMUPT1ST(k)
		}
	}
}

// ReconcileMUPGTP4SrcForRD re-reconciles every installed T1ST downlink under
// rd after the binding that owns rd changed at runtime (VrfBgpService bind /
// update / unbind): a new or changed GTP4 source prefix re-embeds the outer
// source, a removed prefix (or removed binding) reverts the install to the
// plain locator-derived encap source. Unlike the T2ST-driven internal path
// it does NOT gate on a prefix being present — the revert case is exactly a
// missing prefix. reconcileMUPT1ST no-ops on an unchanged {SID, source}, so
// a spurious call is cheap. Safe to call from RPC goroutines (mupMu).
func (a *Applier) ReconcileMUPGTP4SrcForRD(rd string) {
	a.mupMu.Lock()
	defer a.mupMu.Unlock()
	defer a.flushTrackedFailure(&a.mupWriteFailed)
	for k := range a.mupT1ST {
		if k.rd == rd {
			a.reconcileMUPT1ST(k)
		}
	}
}

// reconcileMUPT2ST (re)programs one uplink session: it resolves the direct SID,
// installs the F-TEID entry (matching {endpoint, TEID-prefix}) and the per-
// endpoint H.M.GTP{4,6}.D_TEID gate (reference counted). An unresolvable SID
// tears the session down and waits for its DSD; a changed SID re-Puts the F-TEID
// entry without touching the gate. It reports false when a data-plane write
// or delete failed, which a later reconcile can fix.
func (a *Applier) reconcileMUPT2ST(key mupT2STKey) bool {
	st, ok := a.mupT2ST[key]
	if !ok {
		return true
	}
	if st.withdrawn {
		if (st.installedSID == "" && !st.gateHeld) || a.uninstallMUPT2ST(st) {
			delete(a.mupT2ST, key)
			return true
		}
		return a.mupFailed()
	}
	r := &st.route
	endpoint, _ := netip.ParseAddr(r.Endpoint) // validated in applyMUPT2ST
	dp := a.mupT2STDataPlane(endpoint, r.Endpoint)
	gateOwner := bpf.OwnerBGPMUPGate(a.localASN)
	sid := a.resolveDirectSID(r)
	if sid == "" {
		if (st.installedSID != "" || st.gateHeld) && !a.uninstallMUPT2ST(st) {
			// The uplink entry or the gate is still in the data plane, and
			// forwards towards the SID that no longer resolves. The state is
			// kept, so the next reconcile retries the removal.
			return a.mupFailed()
		}
		// Log the deferral only on the transition into it (see reconcileMUPT1ST).
		if !st.deferLogged {
			a.logger.Info("MUP T2ST uplink deferred (no direct SID yet)",
				zap.String("endpoint", r.Endpoint), zap.Uint32("teid", r.TEID))
			st.deferLogged = true
		}
		return true
	}
	st.deferLogged = false
	// A move to another VRF that failed earlier is retried here, so the
	// tracked pass converges on the VRF the bindings name. It runs only
	// once the SID resolves: an unresolvable session is removed from where
	// it is, above, whether or not it could move.
	if id, accepted := a.mupVRFForRoute(st.fam, r); accepted && id != st.instance {
		if st.installedSID != "" {
			if !a.rekeyMUPT2ST(st, id) {
				return false
			}
		} else {
			st.instance = id
		}
	}
	// A gate kept after a failed rollback may be in the VRF the session
	// was in before: the session's gate is the one of its current VRF.
	if st.installedSID == "" && st.gateHeld && st.gateVRF != a.mupHeadendVRF(st.instance) {
		if !a.releaseMUPGate(st.gateVRF, dp.gatePrefix, gateOwner, dp.deleteGate) {
			return a.mupFailed()
		}
		st.gateHeld = false
	}

	src, ok := a.mupEncapSource(st, "endpoint", r.Endpoint)
	if !ok {
		// Waiting for the source locator is not a failed write.
		return true
	}
	if st.installedSID == sid && st.installedSrc == src {
		return true // already programmed with this direct SID and source
	}

	// The direct SID is a plain End.DT4/DT6 target: H.Encaps toward it with no
	// Args.Mob.Session patch (MupArgsOffsetNone), so the TEID stays only the
	// lookup key.
	entry, err := buildHeadendEntryFrom(src, sid, false)
	if err != nil {
		a.logger.Error("build MUP T2ST uplink entry",
			zap.String("endpoint", r.Endpoint), zap.Error(err))
		return true
	}
	entry.ArgsOffset = bpf.MupArgsOffsetNone

	if st.installedSID == "" {
		// New session. Install the gate first: without it the data plane never
		// parses GTP-U for this endpoint, so the F-TEID entry would be dead. Roll
		// the gate back if the F-TEID write fails so a failed install leaks no gate.
		if !st.gateHeld {
			gateVRF := a.mupHeadendVRF(st.instance)
			if err := a.acquireMUPGate(gateVRF, dp.gatePrefix, dp.gateMode, gateOwner, dp.createGate); err != nil {
				a.logger.Error("install MUP T2ST gate",
					zap.Uint32("vrf_id", gateVRF), zap.String("endpoint", r.Endpoint), zap.Error(err))
				return a.mupFailed()
			}
			st.gateHeld, st.gateVRF = true, gateVRF
		}
		if err := dp.uplinkCreate(st.instance, r.Endpoint, r.TEID, r.TEIDLen, entry, bpf.OwnerBGPMUP(a.localASN, r.RD)); err != nil {
			a.logger.Error("install MUP T2ST uplink entry",
				zap.String("endpoint", r.Endpoint), zap.Uint32("teid", r.TEID), zap.Error(err))
			if a.releaseMUPGate(st.gateVRF, dp.gatePrefix, gateOwner, dp.deleteGate) {
				st.gateHeld = false
			}
			return a.mupFailed()
		}
	} else if err := dp.uplinkCreate(st.instance, r.Endpoint, r.TEID, r.TEIDLen, entry, bpf.OwnerBGPMUP(a.localASN, r.RD)); err != nil {
		// SID changed (a different DSD now resolves) or the source did (the
		// source locator moved): re-Put the F-TEID entry. The gate already
		// exists and its ref-count is unchanged.
		a.logger.Error("re-Put MUP T2ST uplink entry",
			zap.String("endpoint", r.Endpoint), zap.Uint32("teid", r.TEID), zap.Error(err))
		return a.mupFailed()
	}
	st.installedSID = sid
	st.installedSrc = src
	st.locatorSrc = src
	a.logger.Info("MUP T2ST uplink installed",
		zap.String("endpoint", r.Endpoint), zap.Uint32("teid", r.TEID),
		zap.Uint8("teid_len", r.TEIDLen), zap.String("sid", sid),
		zap.Uint32("vrf_id", st.instance))
	return true
}

// uninstallMUPT2ST removes an uplink session's F-TEID entry and releases its
// endpoint gate reference. A failure retains the state and dependency for retry.
func (a *Applier) uninstallMUPT2ST(st *mupSessionState) bool {
	r := &st.route
	endpoint, _ := netip.ParseAddr(r.Endpoint)
	dp := a.mupT2STDataPlane(endpoint, r.Endpoint)
	if st.installedSID != "" {
		if err := dp.uplinkDelete(st.instance, r.Endpoint, r.TEID, r.TEIDLen, bpf.OwnerBGPMUP(a.localASN, r.RD)); err != nil {
			a.logger.Error("withdraw MUP T2ST uplink entry; retaining gate",
				zap.String("endpoint", r.Endpoint), zap.Uint32("teid", r.TEID), zap.Error(err))
			return a.mupFailed()
		}
		// A gate-only cleanup failure must not make a later reconcile believe
		// this SID is still programmed and skip recreating the deleted uplink.
		st.installedSID = ""
		st.installedSrc = [16]byte{}
	}
	if st.gateHeld {
		if !a.releaseMUPGate(st.gateVRF, dp.gatePrefix, bpf.OwnerBGPMUPGate(a.localASN), dp.deleteGate) {
			return a.mupFailed()
		}
		st.gateHeld = false
	}
	return true
}

// mupGateKey names one endpoint gate: the gate prefix in one VRF.
type mupGateKey struct {
	vrf    uint32
	prefix string
}

// sharedMUPGate is the gate reference count the built-in applier shares with
// control-plane plugins (headend.Reconciler).
type sharedMUPGate interface {
	SetGateReferences(headend.Family, uint32, string, uint8, bpf.OwnerTag, int) error
}

func gateFamily(gatePrefix string) (headend.Family, uint8) {
	if strings.Contains(gatePrefix, ":") {
		return headend.AFv6, uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_M_GTP6_D_TEID)
	}
	return headend.AFv4, uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_M_GTP4_D_TEID)
}

// acquireMUPGate ensures the H.M.GTP{4,6}.D_TEID gate for endpoint exists in
// vrfID and bumps its reference count. The gate's segment list is unused (the
// behavior resolves the real SID from mup_uplink_v{4,6}_map), so a bare
// mode-only headend entry suffices.
func (a *Applier) acquireMUPGate(vrfID uint32, gatePrefix string, mode uint8, owner bpf.OwnerTag, create headendCreateFn) error {
	key := mupGateKey{vrf: vrfID, prefix: gatePrefix}
	if shared, ok := a.headend.(sharedMUPGate); ok {
		af, _ := gateFamily(gatePrefix)
		n := a.mupGateRefs[key] + 1
		if err := shared.SetGateReferences(af, vrfID, gatePrefix, mode, owner, n); err != nil {
			return err
		}
		a.mupGateRefs[key] = n
		return nil
	}
	if a.mupGateRefs[key] > 0 {
		a.mupGateRefs[key]++
		return nil
	}
	gate := &bpf.HeadendEntry{Mode: mode}
	if err := create(vrfID, gatePrefix, gate, owner); err != nil {
		return err
	}
	a.mupGateRefs[key] = 1
	return nil
}

// releaseMUPGate drops one reference to endpoint's gate in vrfID and removes
// it when the last uplink session on that endpoint is gone.
func (a *Applier) releaseMUPGate(vrfID uint32, gatePrefix string, owner bpf.OwnerTag, del headendDeleteFn) bool {
	key := mupGateKey{vrf: vrfID, prefix: gatePrefix}
	if shared, ok := a.headend.(sharedMUPGate); ok {
		af, mode := gateFamily(gatePrefix)
		n := max(a.mupGateRefs[key]-1, 0)
		if err := shared.SetGateReferences(af, vrfID, gatePrefix, mode, owner, n); err != nil {
			a.logger.Error("remove MUP gate", zap.Uint32("vrf_id", vrfID), zap.Error(err))
			return false
		}
		if n == 0 {
			delete(a.mupGateRefs, key)
		} else {
			a.mupGateRefs[key] = n
		}
		return true
	}
	n := a.mupGateRefs[key]
	if n <= 1 {
		if err := del(vrfID, gatePrefix, owner); err != nil {
			a.logger.Error("remove MUP T2ST gate",
				zap.Uint32("vrf_id", vrfID), zap.String("gate", gatePrefix), zap.Error(err))
			return false
		}
		delete(a.mupGateRefs, key)
		return true
	}
	a.mupGateRefs[key] = n - 1
	return true
}

// oweMUPGateRelease records a gate reference a moved session no longer
// holds but could not release; the tracked pass releases it.
func (a *Applier) oweMUPGateRelease(key mupGateKey) {
	a.mupGateDebt[key]++
	a.mupFailed()
}

// payMUPGateDebt releases the gate references oweMUPGateRelease recorded.
// It returns how many are still owed. Callers hold mupMu.
func (a *Applier) payMUPGateDebt() int {
	left := 0
	gateOwner := bpf.OwnerBGPMUPGate(a.localASN)
	for key, n := range a.mupGateDebt {
		ep := strings.SplitN(key.prefix, "/", 2)[0]
		addr, err := netip.ParseAddr(ep)
		if err != nil {
			delete(a.mupGateDebt, key)
			continue
		}
		dp := a.mupT2STDataPlane(addr, ep)
		for n > 0 && a.releaseMUPGate(key.vrf, key.prefix, gateOwner, dp.deleteGate) {
			n--
		}
		if n == 0 {
			delete(a.mupGateDebt, key)
		} else {
			a.mupGateDebt[key] = n
			left += n
		}
	}
	return left
}
