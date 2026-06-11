package apply

import (
	"net"
	"net/netip"
	"slices"

	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
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
	route        bgp.MUPRoute
	installedSID string
	// installedSrc is the outer IPv6 source the installed entry carries. It can
	// change while installedSID stays the same (the GTP4 source embed follows
	// the T2ST anchor, see mupGTP4DownlinkSrc), so the T1ST reconcile
	// short-circuit compares both.
	installedSrc [16]byte
	// fam is the route's MUP family (mup_ipv4 / mup_ipv6), kept so the
	// binding-mutation reconcile can re-resolve the uplink instance without
	// the original apply context. T2ST only.
	fam bgp.Family
	// instance is the uplink service instance the session's F-TEID entry is
	// keyed under (0 = default): the instance of the binding whose import RTs
	// matched the route at apply time. Uninstall must use the same value the
	// install used, so it lives on the session, not recomputed ad hoc. T2ST
	// only.
	instance    uint32
	deferLogged bool
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
	sessionRoute := r.Type == bgp.MUPRouteTypeT1ST || r.Type == bgp.MUPRouteTypeT2ST
	if !withdraw && sessionRoute && !a.mupDefaultAllow && !a.vrfBindings.EmptyForFamily(fam) {
		if _, _, ok := a.vrfBindings.MatchImportForFamily(r.RTs, fam); !ok {
			a.logger.Warn("MUP route matches no VRF import RT; dropping",
				zap.String("type", r.Type.String()),
				zap.String("rd", r.RD), zap.Strings("rts", r.RTs))
			return
		}
	}
	switch r.Type {
	case bgp.MUPRouteTypeISD:
		a.applyMUPISD(r, withdraw)
	case bgp.MUPRouteTypeDSD:
		a.applyMUPDSD(r, withdraw)
	case bgp.MUPRouteTypeT1ST:
		a.applyMUPT1ST(r, withdraw)
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
	} else {
		if r.SRv6SID == "" {
			a.logger.Warn("MUP ISD has no SRv6 SID; ignoring (resolves nothing)",
				zap.String("prefix", r.Prefix), zap.String("rd", r.RD))
			return
		}
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
	} else {
		if r.SRv6SID == "" {
			a.logger.Warn("MUP DSD has no SRv6 SID; ignoring (resolves nothing)",
				zap.String("address", r.Address), zap.String("rd", r.RD))
			return
		}
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
func (a *Applier) applyMUPT1ST(r *bgp.MUPRoute, withdraw bool) {
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
	st.route = *r
	a.reconcileMUPT1ST(key)
}

// reconcileMUPT1ST (re)programs one downlink session: it resolves the interwork
// SID, composes Args.Mob.Session onto it, and installs the H.Encaps entry on the
// UE prefix. An unresolvable SID tears down any prior install and waits; an
// unchanged SID is a no-op so re-resolution does not churn the data plane.
func (a *Applier) reconcileMUPT1ST(key mupT1STKey) {
	st, ok := a.mupT1ST[key]
	if !ok {
		return
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
		return
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
		return
	}

	entry, err := a.buildHeadendEntry(composed)
	if err != nil {
		a.logger.Error("build MUP T1ST headend entry",
			zap.String("ue_prefix", r.Prefix), zap.Error(err))
		return
	}
	if src, ok := a.mupGTP4DownlinkSrc(r, endpoint); ok {
		entry.SrcAddr = src
	}
	if st.installedSID == composed && st.installedSrc == entry.SrcAddr {
		return // already programmed with this SID and source
	}

	createHeadend, _ := a.mupT1STHeadendFns(uePrefix)
	owner := bpf.OwnerBGPMUP(a.localASN, r.RD)
	if err := createHeadend(r.Prefix, entry, owner); err != nil {
		a.logger.Error("install MUP T1ST headend",
			zap.String("ue_prefix", r.Prefix), zap.Error(err))
		return
	}
	st.installedSID = composed
	st.installedSrc = entry.SrcAddr
	a.logger.Info("MUP T1ST downlink installed",
		zap.String("ue_prefix", r.Prefix), zap.String("endpoint", r.Endpoint),
		zap.Uint32("teid", r.TEID), zap.Uint8("qfi", r.QFI), zap.String("sid", composed),
		zap.String("src", netip.AddrFrom16(entry.SrcAddr).String()))
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
// uninstalled. Clears installedSID (and the source that rode with it) even
// when the BPF delete errors so the index cannot diverge from the
// (idempotent) map.
func (a *Applier) uninstallMUPT1ST(st *mupSessionState) {
	r := &st.route
	uePrefix, _ := netip.ParsePrefix(r.Prefix)
	_, deleteHeadend := a.mupT1STHeadendFns(uePrefix)
	if err := deleteHeadend(r.Prefix, bpf.OwnerBGPMUP(a.localASN, r.RD)); err != nil {
		a.logger.Error("withdraw MUP T1ST headend (clearing index anyway)",
			zap.String("ue_prefix", r.Prefix), zap.Error(err))
	}
	st.installedSID = ""
	st.installedSrc = [16]byte{}
}

// mupT1STHeadendFns selects the headend map writers for the UE prefix's family.
func (a *Applier) mupT1STHeadendFns(uePrefix netip.Prefix) (headendCreateFn, headendDeleteFn) {
	if uePrefix.Addr().Is6() {
		return a.headend.CreateHeadendV6, a.headend.DeleteHeadendV6
	}
	return a.headend.CreateHeadendV4, a.headend.DeleteHeadendV4
}

// headendCreateFn / headendDeleteFn are the headend map writers (v4 or v6) the
// downlink headend and the uplink gate are installed through, selected by the
// relevant address family.
type (
	headendCreateFn func(string, *bpf.HeadendEntry, bpf.OwnerTag) error
	headendDeleteFn func(string, bpf.OwnerTag) error
)

// mupT2STDataPlane bundles the family-specific data-plane selectors for an
// uplink session: the F-TEID map writers, the gate behavior/prefix, and the gate
// map writers. GTP4 vs GTP6 is the endpoint's address family.
type mupT2STDataPlane struct {
	uplinkCreate func(uint32, string, uint32, uint8, *bpf.HeadendEntry) error
	uplinkDelete func(uint32, string, uint32, uint8) error
	gateMode     uint8
	createGate   headendCreateFn
	deleteGate   headendDeleteFn
	gatePrefix   string
}

func (a *Applier) mupT2STDataPlane(endpoint netip.Addr, endpointStr string) mupT2STDataPlane {
	if endpoint.Is6() {
		return mupT2STDataPlane{
			uplinkCreate: a.mupUplink.CreateMupUplinkV6,
			uplinkDelete: a.mupUplink.DeleteMupUplinkV6,
			gateMode:     uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_M_GTP6_D_TEID),
			createGate:   a.headend.CreateHeadendV6,
			deleteGate:   a.headend.DeleteHeadendV6,
			gatePrefix:   endpointStr + "/128",
		}
	}
	return mupT2STDataPlane{
		uplinkCreate: a.mupUplink.CreateMupUplinkV4,
		uplinkDelete: a.mupUplink.DeleteMupUplinkV4,
		gateMode:     uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_M_GTP4_D_TEID),
		createGate:   a.headend.CreateHeadendV4,
		deleteGate:   a.headend.DeleteHeadendV4,
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
		if st.installedSID != "" {
			a.uninstallMUPT2ST(st)
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
	// A re-advertise can land on a different instance when the bindings moved
	// underneath it; the old F-TEID key must go before the route is replaced,
	// since uninstall keys off the stored instance.
	inst := a.mupUplinkInstanceForRoute(fam, r)
	if st.installedSID != "" && st.instance != inst {
		a.uninstallMUPT2ST(st)
	}
	st.route = *r
	st.fam = fam
	st.instance = inst
	a.reconcileMUPT2ST(key)
	a.reconcileMUPT1STForGTP4Src(r.RD)
}

// mupUplinkInstanceForRoute resolves the uplink instance a T2ST installs
// under: the instance of the binding whose import RTs match the route for
// fam. Routes matching no binding — including the default-allow path with no
// bindings at all — and bindings without mup_uplink_interfaces fall to the
// default instance 0.
func (a *Applier) mupUplinkInstanceForRoute(fam bgp.Family, r *bgp.MUPRoute) uint32 {
	vrfName, _, ok := a.vrfBindings.MatchImportForFamily(r.RTs, fam)
	if !ok {
		return 0
	}
	return a.vrfBindings.UplinkInstanceForVRF(vrfName)
}

// ReconcileMUPUplinkInstances reprograms the data plane's uplink instance
// state after a VRF binding changed at runtime (bind / update / unbind) or at
// boot once the config bindings are registered. It rewrites
// mup_ifindex_instance_map from the bindings' mup_uplink_interfaces (names
// resolved to ifindexes here; unresolvable names are logged and skipped, and
// a later call re-resolves them), then re-keys every T2ST session whose
// instance assignment changed. Safe to call from RPC goroutines (mupMu).
func (a *Applier) ReconcileMUPUplinkInstances() {
	mapping := make(map[uint32]uint32)
	for inst, ifnames := range a.vrfBindings.UplinkInstanceInterfaces() {
		for _, name := range ifnames {
			ifi, err := net.InterfaceByName(name)
			if err != nil {
				a.logger.Warn("resolve MUP uplink interface (skipping; rebind to retry)",
					zap.String("interface", name), zap.Uint32("instance", inst), zap.Error(err))
				continue
			}
			idx := uint32(ifi.Index)
			// An interface claimed by two bindings is operator misconfiguration;
			// resolve it deterministically (lowest instance id wins) so the
			// outcome cannot flap with map iteration order across reconciles.
			if prev, dup := mapping[idx]; dup {
				a.logger.Warn("MUP uplink interface claimed by multiple instances; lowest instance id wins",
					zap.String("interface", name), zap.Uint32("instance_a", prev), zap.Uint32("instance_b", inst))
				if prev <= inst {
					continue
				}
			}
			mapping[idx] = inst
		}
	}
	if err := a.mupUplink.SetMupUplinkInstances(mapping); err != nil {
		a.logger.Error("program MUP uplink instance map", zap.Error(err))
	}

	a.mupMu.Lock()
	defer a.mupMu.Unlock()
	for k, st := range a.mupT2ST {
		inst := a.mupUplinkInstanceForRoute(st.fam, &st.route)
		if inst == st.instance {
			continue
		}
		if st.installedSID != "" {
			a.uninstallMUPT2ST(st)
		}
		st.instance = inst
		a.reconcileMUPT2ST(k)
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
// entry without touching the gate.
func (a *Applier) reconcileMUPT2ST(key mupT2STKey) {
	st, ok := a.mupT2ST[key]
	if !ok {
		return
	}
	r := &st.route
	endpoint, _ := netip.ParseAddr(r.Endpoint) // validated in applyMUPT2ST
	dp := a.mupT2STDataPlane(endpoint, r.Endpoint)
	gateOwner := bpf.OwnerBGPMUPGate(a.localASN)

	sid := a.resolveDirectSID(r)
	if sid == "" {
		if st.installedSID != "" {
			a.uninstallMUPT2ST(st)
		}
		// Log the deferral only on the transition into it (see reconcileMUPT1ST).
		if !st.deferLogged {
			a.logger.Info("MUP T2ST uplink deferred (no direct SID yet)",
				zap.String("endpoint", r.Endpoint), zap.Uint32("teid", r.TEID))
			st.deferLogged = true
		}
		return
	}
	st.deferLogged = false
	if st.installedSID == sid {
		return // already programmed with this direct SID
	}

	// The direct SID is a plain End.DT4/DT6 target: H.Encaps toward it with no
	// Args.Mob.Session patch (MupArgsOffsetNone), so the TEID stays only the
	// lookup key.
	entry, err := a.buildHeadendEntry(sid)
	if err != nil {
		a.logger.Error("build MUP T2ST uplink entry",
			zap.String("endpoint", r.Endpoint), zap.Error(err))
		return
	}
	entry.ArgsOffset = bpf.MupArgsOffsetNone

	if st.installedSID == "" {
		// New session. Install the gate first: without it the data plane never
		// parses GTP-U for this endpoint, so the F-TEID entry would be dead. Roll
		// the gate back if the F-TEID write fails so a failed install leaks no gate.
		if err := a.acquireMUPGate(dp.gatePrefix, dp.gateMode, gateOwner, dp.createGate); err != nil {
			a.logger.Error("install MUP T2ST gate",
				zap.String("endpoint", r.Endpoint), zap.Error(err))
			return
		}
		if err := dp.uplinkCreate(st.instance, r.Endpoint, r.TEID, r.TEIDLen, entry); err != nil {
			a.logger.Error("install MUP T2ST uplink entry",
				zap.String("endpoint", r.Endpoint), zap.Uint32("teid", r.TEID), zap.Error(err))
			a.releaseMUPGate(dp.gatePrefix, gateOwner, dp.deleteGate)
			return
		}
	} else if err := dp.uplinkCreate(st.instance, r.Endpoint, r.TEID, r.TEIDLen, entry); err != nil {
		// SID changed (a different DSD now resolves): re-Put the F-TEID entry. The
		// gate already exists and its ref-count is unchanged.
		a.logger.Error("re-Put MUP T2ST uplink entry",
			zap.String("endpoint", r.Endpoint), zap.Uint32("teid", r.TEID), zap.Error(err))
		return
	}
	st.installedSID = sid
	a.logger.Info("MUP T2ST uplink installed",
		zap.String("endpoint", r.Endpoint), zap.Uint32("teid", r.TEID),
		zap.Uint8("teid_len", r.TEIDLen), zap.String("sid", sid),
		zap.Uint32("instance", st.instance))
}

// uninstallMUPT2ST removes an uplink session's F-TEID entry and releases its
// endpoint gate reference. Continues past a delete error (the BPF delete is
// idempotent) so the gate ref-count is always released, never stranded.
func (a *Applier) uninstallMUPT2ST(st *mupSessionState) {
	r := &st.route
	endpoint, _ := netip.ParseAddr(r.Endpoint)
	dp := a.mupT2STDataPlane(endpoint, r.Endpoint)
	if err := dp.uplinkDelete(st.instance, r.Endpoint, r.TEID, r.TEIDLen); err != nil {
		a.logger.Error("withdraw MUP T2ST uplink entry (continuing to release gate)",
			zap.String("endpoint", r.Endpoint), zap.Uint32("teid", r.TEID), zap.Error(err))
	}
	a.releaseMUPGate(dp.gatePrefix, bpf.OwnerBGPMUPGate(a.localASN), dp.deleteGate)
	st.installedSID = ""
}

// acquireMUPGate ensures the H.M.GTP{4,6}.D_TEID gate for endpoint exists and
// bumps its reference count. The gate's segment list is unused (the behavior
// resolves the real SID from mup_uplink_v{4,6}_map), so a bare mode-only headend
// entry suffices.
func (a *Applier) acquireMUPGate(gatePrefix string, mode uint8, owner bpf.OwnerTag, create headendCreateFn) error {
	if a.mupGateRefs[gatePrefix] > 0 {
		a.mupGateRefs[gatePrefix]++
		return nil
	}
	gate := &bpf.HeadendEntry{Mode: mode}
	if err := create(gatePrefix, gate, owner); err != nil {
		return err
	}
	a.mupGateRefs[gatePrefix] = 1
	return nil
}

// releaseMUPGate drops one reference to endpoint's gate and removes it when the
// last uplink session on that endpoint is gone.
func (a *Applier) releaseMUPGate(gatePrefix string, owner bpf.OwnerTag, del headendDeleteFn) {
	n := a.mupGateRefs[gatePrefix]
	if n <= 1 {
		delete(a.mupGateRefs, gatePrefix)
		if err := del(gatePrefix, owner); err != nil {
			a.logger.Error("remove MUP T2ST gate",
				zap.String("gate", gatePrefix), zap.Error(err))
		}
		return
	}
	a.mupGateRefs[gatePrefix] = n - 1
}
