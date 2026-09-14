package apply

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"

	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// EVPN RT4 membership is bounded so a peer flooding crafted Ethernet Segment
// routes cannot grow the in-memory tables without limit.
const (
	maxTrackedESIs   = 256 // distinct ESIs whose membership we track
	maxMembersPerESI = 32  // member PE sources per ESI (DF candidates)

	// maxEVPNContribsPerEntry caps how many ledger contributions may share
	// one data-plane entry (the {bd, mac} FDB entry for RT2, the {bd, sid}
	// flood bd_peer for RT3) -- the same spirit as vpngroup's
	// maxPathsPerDest. Without it a peer that negotiated ADD-PATH can mint
	// unbounded {NLRI, source} contributions by inventing path ids.
	maxEVPNContribsPerEntry = 32
)

// fdbBdOps is the subset of bpf.MapOperations the EVPN applier writes:
// the FDB (MAC -> peer), the per-PE bd_peer encap entry, and the Ethernet
// Segment (ESI) table that DF election drives.
type fdbBdOps interface {
	CreateFdb(bdID uint16, mac net.HardwareAddr, entry *bpf.FdbEntry) error
	DeleteFdb(bdID uint16, mac net.HardwareAddr) error
	CreateBdPeer(bdID, index uint16, entry *bpf.HeadendEntry, esi [bpf.ESILen]byte, remoteSrc [bpf.IPv6AddrLen]byte, writeReverse bool) error
	// DeleteBdPeer reports whether the forward entry existed; false with a
	// nil error is an already-free slot, and an error is always paired with
	// the occupancy the caller's ledger must keep.
	DeleteBdPeer(bdID, index uint16) (bool, error)
	// CreateBdPeerAtFreeIndex probes for the lowest free index and installs
	// the peer under one critical section, so a concurrent writer (the
	// operator RPC path) cannot land on the same slot.
	CreateBdPeerAtFreeIndex(bdID uint16, entry *bpf.HeadendEntry, esi [bpf.ESILen]byte, remoteSrc [bpf.IPv6AddrLen]byte, writeReverse bool) (uint16, error)
	// DeleteBdPeerIfEntry deletes {bdID, index} only when the slot holds
	// exactly the expected entry, checking and deleting inside one
	// critical section -- the identity guard for ledger-driven deletes of
	// slots an external writer might have freed and reused.
	// (existed, matched, err): existed=false is an already-free slot;
	// matched=false with existed=true is a different occupant (nothing
	// deleted); a transient read failure is an error, never a mismatch.
	DeleteBdPeerIfEntry(bdID, index uint16, want *bpf.HeadendEntry) (bool, bool, error)
	// BdPeerEntryIs reports whether the slot currently holds exactly this
	// entry, under the writers' critical section. The full comparison
	// keeps a ledger from adopting a different owner's entry that merely
	// shares the SID. ErrKeyNotExist is (false, nil); other read failures
	// are errors.
	BdPeerEntryIs(bdID, index uint16, want *bpf.HeadendEntry) (bool, error)
	// FindFreeBdPeerIndex returns the lowest bd_peer index not in use in the
	// real map, so a BGP-allocated peer never collides with an operator-created
	// or restart-pinned entry.
	FindFreeBdPeerIndex(bdID uint16) uint16
	// ListBdPeers / ListFdb back the startup sweep of the ES peers -- and
	// the FDB entries pointing at them -- that a previous run left in the
	// pinned maps.
	ListBdPeers() (map[bpf.BdPeerKey]*bpf.HeadendEntry, error)
	ListFdb() (map[bpf.FdbKey]*bpf.FdbEntry, error)
	// GetEsi / SetEsiDfPe drive DF election: GetEsi reports whether this PE
	// locally attaches the segment (and its local source), SetEsiDfPe writes
	// the elected DF's source address. RT4 never creates an ES locally; the
	// operator declares attachment via `vbctl es create --local-attached`.
	GetEsi(esi [bpf.ESILen]byte) (*bpf.EsiEntry, error)
	SetEsiDfPe(esi [bpf.ESILen]byte, dfAddr [bpf.IPv6AddrLen]byte) (*bpf.EsiEntry, error)
}

// evpnPeerKey identifies a remote PE within a bridge domain by its End.DT2U
// transport SID. Every MAC learned from that PE shares one bd_peer entry.
type evpnPeerKey struct {
	bdID uint16
	sid  string
}

// evpnFdbKey identifies one RT2 contribution: the NLRI ({RD, EthernetTag,
// MAC, IP} -- MAC-only and MAC+IP advertisements are distinct routes) plus
// the path that delivered it (bgp.PathSource, so two route reflectors'
// copies of one NLRI are separate contributions and a per-peer withdraw on
// session loss removes only its own). Used as a reverse index so a
// withdrawal -- whose path attributes (route targets, Prefix-SID) may be
// absent -- can still find the bridge domain and peer the advertisement
// installed.
type evpnFdbKey struct {
	rd     string
	etag   uint32
	mac    string
	ip     string
	source bgp.PathSource
}

type evpnPeerState struct {
	index uint16
	refs  int
	// entry is the flood bd_peer exactly as installed (RT3 flood paths
	// only; zero for RT2 unicast peers). It is the ownership truth for
	// guarded verify/replace/delete: rebuilding the expectation from the
	// current locator would misread our own slot as foreign after a
	// locator delete/recreate and duplicate the peer, and a rebuilt
	// expectation can also fail outright, orphaning the map entry.
	entry bpf.HeadendEntry
}

type evpnFdbState struct {
	bdID uint16
	mac  net.HardwareAddr
	peer evpnPeerKey
	// esi and pe record which multi-homed segment and which PE taught us
	// this MAC, so a mass withdraw can find every MAC one PE contributed to
	// a segment. esi is all-zero for a single-homed MAC, which is not
	// indexed: there is no segment to converge off.
	esi [bpf.ESILen]byte
	pe  string
}

// esMemberKey identifies one PE's contribution to one Ethernet Segment.
type esMemberKey struct {
	esi [bpf.ESILen]byte
	pe  string
}

// rt3NLRIKey is the RT3 NLRI identity ({RD, EthernetTag, Originating
// Router's IP} per RFC 7432 §7.3): the unit that holds one flood
// reference, however many paths deliver it. Without the originating IP,
// two legitimate RT3s delivered by one peer would collide on one
// contribution and a withdraw of one would tear down the other.
type rt3NLRIKey struct {
	rd     string
	etag   uint32
	origIP string
}

// evpnMcastState records one RT3 contribution's resolved view: the bridge
// domain and SID its NLRI would flood toward. The flood bd_peer itself is
// owned by the floodPeers ledger and referenced per NLRI via rt3Flood.
type evpnMcastState struct {
	bdID uint16
	sid  string
	// pe is the advertising PE (the route's next hop), recorded so an
	// unusable re-advertisement tears the flood peer down only when it
	// comes from the same PE.
	pe string
}

// evpnTable holds the EVPN applier's in-memory bookkeeping. peers/fdb/mcast
// are touched from the GoBGP RouteHandler goroutine (applyEVPN) and from the
// RPC-driven ReplayEVPN; both take Applier.evpnMu, and any new accessor must
// too. esMembers and DF election have their own lock: the operator path
// (es create -> ReelectDF) re-runs election from the RPC goroutine, so esMu
// serializes esMembers access and electDF (esMu nests inside evpnMu on the
// applyEVPN path and is taken alone by ReelectDF -- one direction only).
type evpnTable struct {
	peers map[evpnPeerKey]*evpnPeerState
	fdb   map[evpnFdbKey]evpnFdbState
	mcast map[rt3NLRIKey]map[bgp.PathSource]evpnMcastState
	// floodPeers refcounts the flood bd_peer shared per {bd, End.DT2M SID}
	// -- the RT3 counterpart of peers: one data-plane entry, refs = the
	// number of NLRIs currently backing it (via rt3Flood, not raw
	// contributions: an NLRI holds exactly one ref however many sources
	// deliver it).
	floodPeers map[evpnPeerKey]*evpnPeerState
	// rt3Flood records which {bd, SID} each RT3 NLRI's single flood ref is
	// held on: the representative (contribLess-minimum source)
	// contribution decides the SID, so two sources' divergent copies of
	// one NLRI never replicate BUM traffic twice.
	rt3Flood map[rt3NLRIKey]evpnPeerKey
	// esMembers maps an ESI to the set of member PE source IPs learned from
	// RT4 (Ethernet Segment routes), the candidate set for DF election.
	// Guarded by esMu.
	esMembers map[[bpf.ESILen]byte]map[string]struct{}
	esMu      sync.Mutex
	// macsByES indexes the MACs each PE taught us on each Ethernet Segment.
	// It exists for mass withdraw (RFC 7432 §8.2): when a PE withdraws its
	// per-ES Ethernet A-D route it is saying the whole segment is gone, and
	// waiting for a withdrawal per MAC would keep blackholing traffic for as
	// long as that takes. Guarded by evpnMu, like fdb itself.
	macsByES map[esMemberKey]map[evpnFdbKey]struct{}

	// Aliasing state (see evpn_alias.go), guarded by evpnMu like fdb.
	// esAD records each PE's per-ES Ethernet A-D (value: the Single-Active
	// bit -- true forbids aliasing), eviAD each per-EVI A-D contribution,
	// esDests the programmed group per {bd, ESI}, and macContribs the RT2
	// ledger entries sharing one data-plane {bd, MAC} key.
	esAD map[esMemberKey]bool
	// esADByNLRI maps a per-ES NLRI ({RD, ESI}) to the PE it last named,
	// so a re-advertisement under a new next hop -- an implicit replace,
	// the NLRI identity carries no PE -- drops the old PE's contribution.
	esADByNLRI  map[esNLRIKey]string
	eviAD       map[evpnEviADKey]eviADState
	esDests     map[esDestKey]*esDest
	macContribs map[macDPKey]map[evpnFdbKey]struct{}
	// esWithdrawn marks a {ESI, PE} whose per-ES A-D was withdrawn while an
	// aliasing group still covered its MACs, so a later dissolve knows to
	// finish the mass withdraw for them instead of pointing them back at
	// the departed PE. Cleared when the PE re-advertises the per-ES route
	// or its last indexed MAC drains.
	esWithdrawn map[esMemberKey]struct{}
	// Segment group id allocation, in the partition above esGroupIDBase.
	nextGroupID  uint32
	freeGroupIDs []uint32
}

func newEVPNTable() *evpnTable {
	return &evpnTable{
		peers:       make(map[evpnPeerKey]*evpnPeerState),
		fdb:         make(map[evpnFdbKey]evpnFdbState),
		mcast:       make(map[rt3NLRIKey]map[bgp.PathSource]evpnMcastState),
		floodPeers:  make(map[evpnPeerKey]*evpnPeerState),
		rt3Flood:    make(map[rt3NLRIKey]evpnPeerKey),
		macsByES:    make(map[esMemberKey]map[evpnFdbKey]struct{}),
		esMembers:   make(map[[bpf.ESILen]byte]map[string]struct{}),
		esAD:        make(map[esMemberKey]bool),
		esADByNLRI:  make(map[esNLRIKey]string),
		eviAD:       make(map[evpnEviADKey]eviADState),
		esDests:     make(map[esDestKey]*esDest),
		macContribs: make(map[macDPKey]map[evpnFdbKey]struct{}),
		esWithdrawn: make(map[esMemberKey]struct{}),
	}
}

// releaseIndex drops one reference to key's peer in m and reports whether
// the peer is now unreferenced (so the caller deletes the bd_peer). The
// RT3 floodPeers ledger releases through reconcileRT3Flood instead: its
// final-reference delete carries keep-on-failure and slot-identity
// semantics this helper deliberately does not know about.
func releaseIndex(m map[evpnPeerKey]*evpnPeerState, key evpnPeerKey) (uint16, bool) {
	st, ok := m[key]
	if !ok {
		return 0, false
	}
	st.refs--
	if st.refs > 0 {
		return st.index, false
	}
	delete(m, key)
	return st.index, true
}

// remoteSrcOrLocal renders the advertising PE's source (derived from the SID
// locator) as a 16-byte reverse-map key, falling back to the local encap
// source when it could not be derived, so the reverse entry stays
// self-consistent for delete.
func remoteSrcOrLocal(remoteSrc string, local [bpf.IPv6AddrLen]byte) [bpf.IPv6AddrLen]byte {
	if addr, err := netip.ParseAddr(remoteSrc); err == nil && addr.Is6() && !addr.Is4In6() {
		return addr.As16()
	}
	return local
}

// matchEVPNBD resolves a received EVPN route's route-targets to a bridge
// domain: MatchImportForFamily matches the binding and returns the bd_id of
// the matched VRF's bridge facet, skipping facet-less bindings under
// FamilyEVPN. The zero-bd guard stays as belt-and-suspenders so an EVPN
// install without a real bridge domain is impossible.
func (a *Applier) matchEVPNBD(rts []string) (uint16, bool) {
	_, bdID, ok := a.vrfBindings.MatchImportForFamily(rts, bgp.FamilyEVPN)
	if !ok || bdID == 0 {
		return 0, false
	}
	return bdID, true
}

// isUsableSRv6SID reports whether sid is a global-scope IPv6 SID a remote
// PE can be reached at. An unparseable, IPv4-mapped, unspecified (::),
// loopback (::1), link-local (fe80::/10), or multicast (ff00::/8) address
// would install a black-hole or wrong-target peer, so callers reject the
// route -- the same shape the next-hop validator in pkg/bgp enforces.
func isUsableSRv6SID(sid string) bool {
	addr, err := netip.ParseAddr(sid)
	return err == nil && addr.Is6() && !addr.Is4In6() && !addr.IsUnspecified() &&
		!addr.IsLoopback() && !addr.IsLinkLocalUnicast() && !addr.IsMulticast()
}

func (a *Applier) applyEVPN(r *bgp.EVPNRoute, src bgp.PathSource, withdraw bool) {
	a.evpnMu.Lock()
	defer a.evpnMu.Unlock()
	a.applyEVPNLocked(r, src, withdraw)
}

// applyEVPNLocked dispatches one EVPN route. Caller holds evpnMu. RT2 and
// RT3 track per-{NLRI, source} contributions; RT1 and RT4 are still
// source-blind (their per-source folding is the recorded follow-up stage).
func (a *Applier) applyEVPNLocked(r *bgp.EVPNRoute, src bgp.PathSource, withdraw bool) {
	switch r.Type {
	case bgp.EVPNRouteTypeMACIP:
		a.applyEVPNMacIP(r, src, withdraw)
	case bgp.EVPNRouteTypeInclusiveMulticast:
		a.applyEVPNInclusiveMulticast(r, src, withdraw)
	case bgp.EVPNRouteTypeEthernetSegment:
		a.applyEVPNEthernetSegment(r, withdraw)
	case bgp.EVPNRouteTypeEthernetAD:
		a.applyEVPNEthernetAD(r, withdraw)
	default:
		// RT5 IP Prefix is not decoded, so it never reaches here.
	}
}

// applyEVPNEthernetAD handles RT1 Ethernet A-D in both its forms (RFC 7432
// §8.2, §8.4). The per-ES route declares a PE's attachment to the segment
// and, on withdrawal, is the mass-withdraw signal; the per-EVI route carries
// the aliasing SID. Both feed the segment ECMP groups in evpn_alias.go.
// Caller holds evpnMu.
func (a *Applier) applyEVPNEthernetAD(r *bgp.EVPNRoute, withdraw bool) {
	if r.IsPerES() {
		a.applyEVPNPerESAD(r, withdraw)
		return
	}
	a.applyEVPNPerEVIAD(r, withdraw)
}

// ReplayEVPN re-applies the current EVPN loc-rib through the receive path.
// VrfBridgeAttach / commitBinding call it after the EVPN import surface
// widens (a bridge facet attached, an import RT added): a route that arrived
// while no binding+facet could match it was dropped fail-closed and the
// watch stream never re-delivers it, so the rib snapshot is the only way to
// rescue it. snapshot is a closure over bgp.RouteLister.ListRoutes; every
// install it triggers is idempotent, so replaying already-applied routes is
// a no-op.
//
// evpnMu is held across the snapshot AND the re-applies, which makes any
// interleaving with the live watch goroutine converge: a route withdrawn
// before the snapshot is not in it, and a withdraw racing the replay blocks
// on evpnMu and lands after, overwriting the re-install. Holding the mutex
// across ListRoutes cannot deadlock: gobgp's watch delivery runs on a
// dedicated goroutine fed by an unbounded queue, so the mgmt loop ListRoutes
// waits on never blocks on our callback.
//
// The snapshot carries every known path per NLRI (best first; lister.go
// emits one event per path). RT2/RT3 record each path as its own {NLRI,
// source} contribution with a deterministic representative, so replay
// order does not change the outcome. RT1/RT4 are still source-blind: their
// values (the PE) agree across sources so the install replay is
// idempotent, but per-source withdraw safety is the recorded follow-up.
func (a *Applier) ReplayEVPN(snapshot func(bgp.RouteHandler) error) error {
	a.evpnMu.Lock()
	defer a.evpnMu.Unlock()
	n := 0
	err := snapshot(func(ev bgp.RouteEvent) {
		// Rib-resident paths always carry IsWithdraw=false; the guard keeps a
		// misbehaving snapshot from turning the rescue into a teardown.
		if ev.Family != bgp.FamilyEVPN || ev.EVPN == nil || ev.IsWithdraw {
			return
		}
		a.applyEVPNLocked(ev.EVPN, ev.Source, false)
		n++
	})
	if err != nil {
		return fmt.Errorf("replay EVPN rib: %w", err)
	}
	a.logger.Debug("replayed EVPN loc-rib", zap.Int("routes", n))
	return nil
}

func (a *Applier) applyEVPNMacIP(r *bgp.EVPNRoute, src bgp.PathSource, withdraw bool) {
	if r.MAC == "" {
		a.logger.Warn("EVPN RT2 has no MAC; skipping", zap.String("rd", r.RD))
		return
	}
	fk := evpnFdbKey{rd: r.RD, etag: r.EthernetTag, mac: r.MAC, ip: r.IPAddr, source: src}

	if withdraw {
		// A withdrawal may carry no route targets, so the bridge domain and
		// peer are recovered from the reverse index rather than re-resolved
		// from RTs. An unknown withdraw is a no-op.
		if st, ok := a.evpn.fdb[fk]; ok {
			a.withdrawEVPNMac(fk, st)
		}
		return
	}

	mac, err := net.ParseMAC(r.MAC)
	if err != nil {
		a.logger.Error("parse EVPN MAC", zap.String("mac", r.MAC), zap.Error(err))
		return
	}
	// dropTracked fails closed for an unusable re-advertisement of a
	// tracked NLRI: a BGP UPDATE is an implicit replace, so a MAC learned
	// from an earlier advertisement must not keep forwarding over a path
	// the route no longer backs (same rule as the per-EVI A-D applier).
	// The contribution key carries the delivering path, so teardown is
	// inherently confined to this path's own contribution -- another
	// reflector's (or PE's) state lives under a different key. The old
	// same-next-hop approximation would now WEAKEN the replace rule: a
	// path whose next hop moved while becoming unusable must still drop.
	dropTracked := func() {
		if st, ok := a.evpn.fdb[fk]; ok {
			a.withdrawEVPNMac(fk, st)
		}
	}
	bdID, ok := a.matchEVPNBD(r.RTs)
	if !ok {
		dropTracked()
		a.logger.Warn("EVPN RT2 matches no bridge-domain binding; dropping",
			zap.String("mac", r.MAC), zap.Strings("rts", r.RTs))
		return
	}
	if r.SRv6SID == "" {
		dropTracked()
		a.logger.Warn("EVPN RT2 has no SRv6 SID; removing any previous entry",
			zap.String("mac", r.MAC), zap.String("rd", r.RD))
		return
	}
	// The End.DT2U SID must be a routable IPv6 SID; see isUsableSRv6SID.
	if !isUsableSRv6SID(r.SRv6SID) {
		dropTracked()
		a.logger.Warn("EVPN RT2 SID is not a usable IPv6 SID; removing any previous entry",
			zap.String("mac", r.MAC), zap.String("sid", r.SRv6SID))
		return
	}
	pk := evpnPeerKey{bdID: bdID, sid: r.SRv6SID}

	// Re-advertise / MAC move: an unchanged NLRI returns early so a second
	// install would not bump refs and leak the bd_peer slot. Any changed
	// dimension tears the old mapping down first so its peer ref, FDB entry
	// and segment index release before the new install. ESI and PE are part
	// of the comparison: an RT2 re-advertised with a different ESI is how a
	// host joins or leaves a multi-homed segment (the ESI is not in the
	// route key), and skipping it would leave the MAC in the wrong segment
	// index -- missed by that segment's mass withdraw, kept in one it left.
	if prev, ok := a.evpn.fdb[fk]; ok {
		if prev.peer == pk && prev.bdID == bdID && prev.esi == r.ESI && prev.pe == r.NextHop {
			return
		}
		if !a.withdrawEVPNMac(fk, prev) {
			return
		}
	}

	// Contribution cap: a peer that negotiated ADD-PATH could mint
	// unbounded {NLRI, source} contributions onto one {bd, MAC}. An
	// already-tracked contribution refreshing itself bypasses the cap; a
	// dropped route installs nothing, so its later withdraw is a no-op,
	// and it is re-admitted only by its next UPDATE or a replay (the same
	// trade the vpngroup cap makes).
	mk := macDPKey{bdID: bdID, mac: mac.String()}
	if _, tracked := a.evpn.macContribs[mk][fk]; !tracked &&
		len(a.evpn.macContribs[mk]) >= maxEVPNContribsPerEntry {
		a.logger.Warn("EVPN RT2 contribution cap reached; dropping route",
			zap.String("mac", r.MAC), zap.Int("max", maxEVPNContribsPerEntry))
		return
	}

	entry, err := a.buildL2HeadendEntry(r.SRv6SID, bdID, true)
	if err != nil {
		a.logger.Error("build EVPN headend entry",
			zap.String("mac", r.MAC), zap.Error(err))
		return
	}
	rsrc := remoteSrcOrLocal(r.RemoteSrc, entry.SrcAddr)
	if st, tracked := a.evpn.peers[pk]; tracked {
		// The PE already has a peer in this BD: refresh it in place and
		// bump the reference count.
		if err := a.fdbBd.CreateBdPeer(bdID, st.index, entry, r.ESI, rsrc, true); err != nil {
			a.logger.Error("install EVPN bd_peer",
				zap.Uint16("bd_id", bdID), zap.Error(err))
			return
		}
		st.refs++
	} else {
		// Probe-and-create runs inside one critical section: probing here
		// and creating later would race the operator RPC path onto the
		// same free slot (both allocate from the same operator range).
		newIdx, err := a.fdbBd.CreateBdPeerAtFreeIndex(bdID, entry, r.ESI, rsrc, true)
		if err != nil {
			a.logger.Error("install EVPN bd_peer",
				zap.Uint16("bd_id", bdID), zap.String("sid", r.SRv6SID), zap.Error(err))
			return
		}
		a.evpn.peers[pk] = &evpnPeerState{index: newIdx, refs: 1}
	}
	// A MAC behind an aliased segment points at the segment's ES peer, so
	// every all-active PE forwards for it; otherwise at the advertising PE's
	// own peer. The per-PE peer is allocated either way: the RX path needs
	// its reverse-map entry, and it is the fallback target when aliasing
	// dissolves.
	// Record the contribution first, then program the shared {bd, MAC}
	// FDB entry through the single representative-driven writer: the
	// programmed entry is a pure function of the ledgers, so install and
	// replay order cannot change the outcome, and alias formation /
	// dissolve reuse the same writer. A non-representative contribution
	// still allocated its PE's peer above -- the RX path needs the
	// reverse-map entry, and survivor hand-off falls back to it.
	st := evpnFdbState{bdID: bdID, mac: mac, peer: pk, esi: r.ESI, pe: r.NextHop}
	a.evpn.fdb[fk] = st
	a.indexMACByES(fk, st)
	if a.evpn.macContribs[mk] == nil {
		a.evpn.macContribs[mk] = make(map[evpnFdbKey]struct{})
	}
	a.evpn.macContribs[mk][fk] = struct{}{}
	if !a.writeFdbForMac(mk, func(evpnFdbKey, evpnFdbState) bool { return false }) {
		// Roll the contribution back out: keeping a ledger entry whose
		// data-plane write failed would leave the withdraw path believing
		// there is something to hand off.
		delete(a.evpn.fdb, fk)
		delete(a.evpn.macContribs[mk], fk)
		if len(a.evpn.macContribs[mk]) == 0 {
			delete(a.evpn.macContribs, mk)
		}
		a.unindexMACByES(fk, st)
		if rIdx, gone := releaseIndex(a.evpn.peers, pk); gone {
			if existed, derr := a.fdbBd.DeleteBdPeer(bdID, rIdx); derr != nil && existed {
				// Same recovery contract as withdrawEVPNMac: the peer entry
				// survived the failed rollback, so re-pin the index (refs 0)
				// -- releasing it would orphan the slot and a re-learn would
				// allocate a duplicate.
				a.evpn.peers[pk] = &evpnPeerState{index: rIdx, refs: 0}
				a.logger.Error("roll back EVPN bd_peer",
					zap.Uint16("bd_id", bdID), zap.Uint16("index", rIdx), zap.Error(derr))
			} else if derr != nil {
				a.logger.Error("roll back EVPN bd_peer (slot already free)",
					zap.Uint16("bd_id", bdID), zap.Uint16("index", rIdx), zap.Error(derr))
			}
		}
		return
	}
	a.logger.Info("EVPN MAC installed",
		zap.String("mac", r.MAC), zap.Uint16("bd_id", bdID), zap.String("sid", r.SRv6SID))
}

// indexMACByES records that one PE taught this MAC on a multi-homed segment,
// so a per-ES withdraw can find it. A single-homed MAC (all-zero ESI) or one
// with no identifiable PE is not indexed: neither can be converged off a
// segment failure.
func (a *Applier) indexMACByES(fk evpnFdbKey, st evpnFdbState) {
	var zeroESI [bpf.ESILen]byte
	if st.esi == zeroESI || st.pe == "" {
		return
	}
	k := esMemberKey{esi: st.esi, pe: st.pe}
	macs := a.evpn.macsByES[k]
	if macs == nil {
		if len(a.evpn.macsByES) >= maxTrackedESIs*maxMembersPerESI {
			a.logger.Warn("EVPN ES MAC index full; mass withdraw will not cover this segment",
				zap.String("pe", st.pe))
			return
		}
		macs = make(map[evpnFdbKey]struct{})
		a.evpn.macsByES[k] = macs
	}
	macs[fk] = struct{}{}
}

// unindexMACByES drops one MAC from the segment index.
func (a *Applier) unindexMACByES(fk evpnFdbKey, st evpnFdbState) {
	var zeroESI [bpf.ESILen]byte
	if st.esi == zeroESI || st.pe == "" {
		return
	}
	k := esMemberKey{esi: st.esi, pe: st.pe}
	macs := a.evpn.macsByES[k]
	if macs == nil {
		return
	}
	delete(macs, fk)
	if len(macs) == 0 {
		delete(a.evpn.macsByES, k)
		// Nothing left for a deferred mass withdraw to finish.
		delete(a.evpn.esWithdrawn, k)
	}
}

// withdrawEVPNMac removes one RT2's contribution to the FDB and releases its
// peer reference, deleting the bd_peer when the last MAC stops referencing
// it.
//
// The data-plane key {bd, MAC} is shared: with all-active multi-homing every
// attached PE advertises the MAC under its own RD, so several fdb-ledger
// entries stand behind one FDB entry. The entry is deleted only with the
// last contribution; while others survive it is re-installed from one of
// them, so a single PE's withdrawal can no longer tear down a MAC the
// remaining PEs still back. Caller holds evpnMu.
// withdrawEVPNMac removes one RT2 contribution and reports whether its
// ledger entry is gone. false means a map write failed and every ledger
// was kept for an event-driven retry -- a replacing caller must then abort
// its own install, or it would overwrite the retained bookkeeping and leak
// the old contribution's peer reference.
func (a *Applier) withdrawEVPNMac(fk evpnFdbKey, st evpnFdbState) bool {
	mk := macDPKey{bdID: st.bdID, mac: st.mac.String()}
	if sfk, sst, ok := a.survivingContrib(mk, fk); ok {
		if idx, resolvable := a.fdbTargetIndex(sst); resolvable {
			fdb := &bpf.FdbEntry{IsRemote: 1, PeerIndex: idx, BdId: sst.bdID, Esi: sst.esi}
			if err := a.fdbBd.CreateFdb(sst.bdID, sst.mac, fdb); err != nil {
				// The FDB entry still points at the withdrawn contribution's
				// target. Keep every ledger so a later retry can hand off.
				a.logger.Error("hand EVPN MAC to surviving PE",
					zap.String("mac", st.mac.String()), zap.Error(err))
				return false
			}
		} else {
			// The ledgers disagree (no peer to point at); leave the entry as
			// is rather than black-hole it, and still drop this
			// contribution.
			a.logger.Error("EVPN MAC survivor has no resolvable peer",
				zap.String("mac", st.mac.String()), zap.String("rd", sfk.rd))
		}
	} else if err := a.fdbBd.DeleteFdb(st.bdID, st.mac); err != nil {
		// The FDB entry is still in the map. Keep the reverse index so a
		// later retry can find and remove it; dropping it here would orphan
		// the map entry and the peer reference it holds.
		a.logger.Error("withdraw EVPN MAC",
			zap.String("mac", st.mac.String()), zap.Error(err))
		return false
	}
	delete(a.evpn.fdb, fk)
	if contribs := a.evpn.macContribs[mk]; contribs != nil {
		delete(contribs, fk)
		if len(contribs) == 0 {
			delete(a.evpn.macContribs, mk)
		}
	}
	a.unindexMACByES(fk, st)
	if idx, gone := releaseIndex(a.evpn.peers, st.peer); gone {
		if existed, err := a.fdbBd.DeleteBdPeer(st.bdID, idx); err != nil && existed {
			// The bd_peer is still in the map but releaseIndex already
			// dropped it from the ledger. Re-pin the index (refs 0) so a
			// re-learn of this PE reuses the surviving entry instead of
			// allocating a duplicate and leaking the slot -- note the
			// recovery is event-driven (nothing retries on its own; the
			// next route for this PE does). An already-free slot is the
			// opposite situation: re-pinning it would collide with the
			// next peer FindFreeBdPeerIndex hands the index to.
			a.evpn.peers[st.peer] = &evpnPeerState{index: idx, refs: 0}
			a.logger.Error("delete EVPN bd_peer",
				zap.Uint16("bd_id", st.bdID), zap.Uint16("index", idx), zap.Error(err))
		} else if err != nil {
			a.logger.Error("delete EVPN bd_peer (slot already free)",
				zap.Uint16("bd_id", st.bdID), zap.Uint16("index", idx), zap.Error(err))
		}
	}
	return true
}

// applyEVPNInclusiveMulticast records (or withdraws) one RT3 Inclusive
// Multicast contribution and reconciles its NLRI's flood state. The
// data-plane flood loop (tc_dispatch_bum_clones) replicates BUM frames to
// every bd_peer in the bridge domain, so the control plane's whole job is
// keeping exactly one flood bd_peer per distinct {bd, End.DT2M SID}: each
// NLRI holds one reference on its representative's SID (rt3Flood), and
// the shared peer itself is refcounted in floodPeers.
// setMcast / deleteMcast maintain the per-NLRI contribution index; the
// nesting bounds every cap count and representative election to one
// NLRI's at-most-maxEVPNContribsPerEntry entries instead of scanning the
// whole ledger per route.
func (t *evpnTable) setMcast(nk rt3NLRIKey, src bgp.PathSource, st evpnMcastState) {
	inner := t.mcast[nk]
	if inner == nil {
		inner = make(map[bgp.PathSource]evpnMcastState)
		t.mcast[nk] = inner
	}
	inner[src] = st
}

func (t *evpnTable) deleteMcast(nk rt3NLRIKey, src bgp.PathSource) {
	inner := t.mcast[nk]
	delete(inner, src)
	if len(inner) == 0 {
		delete(t.mcast, nk)
	}
}

func (a *Applier) applyEVPNInclusiveMulticast(r *bgp.EVPNRoute, src bgp.PathSource, withdraw bool) {
	nk := rt3NLRIKey{rd: r.RD, etag: r.EthernetTag, origIP: r.IPAddr}

	// removeContribution drops this path's contribution and reconciles the
	// NLRI's single flood ref; when the reconcile cannot release the old
	// flood peer (map delete failed with the entry installed) the
	// contribution is restored, so the ledger keeps tracking the entry for
	// an event-driven retry -- the pre-existing keep-ledger contract.
	removeContribution := func() {
		st, ok := a.evpn.mcast[nk][src]
		if !ok {
			return
		}
		a.evpn.deleteMcast(nk, src)
		if releasedOK, _ := a.reconcileRT3Flood(nk); !releasedOK {
			a.evpn.setMcast(nk, src, st)
		}
	}

	if withdraw {
		// A withdrawal may carry no route targets, so the bridge domain
		// comes from the reverse index. An unknown withdraw is a no-op.
		removeContribution()
		return
	}

	// Same implicit-replace rule as RT2: the contribution key carries the
	// delivering path, so an unusable re-advertisement tears down exactly
	// its own contribution.
	bdID, ok := a.matchEVPNBD(r.RTs)
	if !ok {
		removeContribution()
		a.logger.Warn("EVPN RT3 matches no bridge-domain binding; dropping",
			zap.String("rd", r.RD), zap.Strings("rts", r.RTs))
		return
	}
	if r.SRv6SID == "" {
		removeContribution()
		a.logger.Warn("EVPN RT3 has no SRv6 SID; removing any previous flood contribution", zap.String("rd", r.RD))
		return
	}
	// The End.DT2M SID must be a routable IPv6 SID, same guard as RT2.
	if !isUsableSRv6SID(r.SRv6SID) {
		removeContribution()
		a.logger.Warn("EVPN RT3 SID is not a usable IPv6 SID; removing any previous flood contribution",
			zap.String("rd", r.RD), zap.String("sid", r.SRv6SID))
		return
	}

	prev, tracked := a.evpn.mcast[nk][src]
	if tracked && prev.bdID == bdID && prev.sid == r.SRv6SID {
		// Forwarding-relevant state unchanged; pe is informational. A
		// refresh of any contribution is the retry event for a floodless
		// NLRI (an earlier acquire failed, e.g. a full BD) and for a slot
		// an operator flush freed underneath the ledger, so reconcile
		// unconditionally -- the held-and-verified case is one map read.
		if prev.pe != r.NextHop {
			prev.pe = r.NextHop
			a.evpn.setMcast(nk, src, prev)
		}
		a.reconcileRT3Flood(nk)
		return
	}
	if !tracked {
		// Contribution cap per NLRI: an ADD-PATH peer could otherwise mint
		// contributions without bound. A dropped route installs nothing,
		// so its later withdraw is a no-op; re-admission happens on its
		// next UPDATE or a replay, the same trade the vpngroup cap makes.
		if len(a.evpn.mcast[nk]) >= maxEVPNContribsPerEntry {
			a.logger.Warn("EVPN RT3 contribution cap reached; dropping route",
				zap.String("rd", r.RD), zap.Int("max", maxEVPNContribsPerEntry))
			return
		}
	}
	a.evpn.setMcast(nk, src, evpnMcastState{bdID: bdID, sid: r.SRv6SID, pe: r.NextHop})
	releasedOK, acquiredOK := a.reconcileRT3Flood(nk)
	if !releasedOK {
		// The reconcile could not release the previously held flood peer:
		// revert this contribution to its old state (or drop it when new)
		// so the ledger still matches the data plane and the retry
		// contract holds.
		if tracked {
			a.evpn.setMcast(nk, src, prev)
		} else {
			a.evpn.deleteMcast(nk, src)
		}
		return
	}
	if !acquiredOK {
		if _, held := a.evpn.rt3Flood[nk]; held {
			// The failure was a repair of the still-held flood ref (the
			// representative's slot), not this contribution's own
			// acquire. Keep the contribution: its target stays available
			// for a later re-election (e.g. the representative
			// withdraws), and the kept ref retries the repair on any
			// refresh.
			return
		}
		// The new flood peer could not be installed (e.g. the BD is full):
		// keep the ledger honest by dropping this contribution -- the old
		// contract recorded nothing on an install failure -- and let the
		// remaining contributions re-elect.
		a.evpn.deleteMcast(nk, src)
		a.reconcileRT3Flood(nk)
	}
}

// rt3Representative returns the flood target the NLRI's contributions
// elect: the {bd, SID} of the contribLess-minimum source among them (false
// when the NLRI has no contributions). One NLRI holds exactly one flood
// ref however many paths deliver it, so two sources' divergent copies
// (e.g. one reflector lagging a PE's SID change) never replicate BUM
// traffic toward both SIDs.
func (a *Applier) rt3Representative(nk rt3NLRIKey) (evpnPeerKey, bool) {
	var (
		best   bgp.PathSource
		target evpnPeerKey
		found  bool
	)
	for src, st := range a.evpn.mcast[nk] {
		if !found || pathSourceLess(src, best) {
			best = src
			target = evpnPeerKey{bdID: st.bdID, sid: st.sid}
			found = true
		}
	}
	return target, found
}

func pathSourceLess(x, y bgp.PathSource) bool {
	if c := x.Peer.Compare(y.Peer); c != 0 {
		return c < 0
	}
	return x.PathID < y.PathID
}

// ensureFloodPeerInstalled re-checks that the ledger's slot for want still
// holds its SID before the slot is re-referenced: an operator delete or
// flush can free and re-issue indexes underneath the ledger, and trusting
// the ledger alone would pile references onto whatever occupies the slot
// now. A stale slot is repaired in place (fresh index, same state) so
// every NLRI already referencing want stays consistent. A transient read
// failure keeps the ledger as-is -- optimistic, matching the pre-check
// behavior -- and false means the slot is stale and could not be
// reinstalled.
func (a *Applier) ensureFloodPeerInstalled(want evpnPeerKey, fs *evpnPeerState) bool {
	// The slot is compared against the entry exactly as this ledger
	// installed it, so a different owner's peer that merely shares the
	// SID (same first segment, other attributes) reads as stale and is
	// never adopted -- the ledger moves to a fresh slot and leaves the
	// foreign entry alone. The stored copy, not a rebuild from the
	// current locator, is the ownership truth: a locator delete/recreate
	// must not make the ledger disown its own slot.
	holds, err := a.fdbBd.BdPeerEntryIs(want.bdID, fs.index, &fs.entry)
	if err != nil {
		a.logger.Error("verify EVPN BUM bd_peer occupant",
			zap.Uint16("bd_id", want.bdID), zap.Uint16("index", fs.index), zap.Error(err))
		return true
	}
	if holds {
		return true
	}
	entry, err := a.buildL2HeadendEntry(want.sid, want.bdID, false)
	if err != nil {
		a.logger.Error("build EVPN RT3 headend entry",
			zap.String("sid", want.sid), zap.Error(err))
		return false
	}
	var noRemoteSrc [bpf.IPv6AddrLen]byte
	var zeroESI [bpf.ESILen]byte
	idx, err := a.fdbBd.CreateBdPeerAtFreeIndex(want.bdID, entry, zeroESI, noRemoteSrc, false)
	if err != nil {
		a.logger.Error("reinstall EVPN BUM bd_peer",
			zap.Uint16("bd_id", want.bdID), zap.Error(err))
		return false
	}
	a.logger.Warn("EVPN flood peer slot was freed underneath the ledger; reinstalled",
		zap.Uint16("bd_id", want.bdID), zap.Uint16("old_index", fs.index),
		zap.Uint16("index", idx), zap.String("sid", want.sid))
	fs.index = idx
	fs.entry = *entry
	return true
}

// reconcileRT3Flood drives the NLRI's single flood reference to its
// representative target: release the previously held {bd, SID} (deleting
// the shared flood bd_peer on the last reference, after verifying the slot
// still holds this SID -- an operator flush can free and reuse indexes
// underneath the ledger), then acquire the new one. Release-first keeps
// the pre-existing move semantics: a brief flood gap over a duplicate
// window. releasedOK is false only when the release failed with the entry
// still installed (the caller must then revert its contribution change so
// the ledger keeps matching the data plane); acquiredOK is false when the
// wanted flood peer could not be installed.
func (a *Applier) reconcileRT3Flood(nk rt3NLRIKey) (releasedOK, acquiredOK bool) {
	want, wantOK := a.rt3Representative(nk)
	have, haveOK := a.evpn.rt3Flood[nk]
	if haveOK && wantOK && have == want {
		if fs, ok := a.evpn.floodPeers[have]; ok {
			if a.ensureFloodPeerInstalled(have, fs) {
				return true, true
			}
			// The slot was freed underneath the ledger and could not be
			// reinstalled. Keep the shared state and this NLRI's ref:
			// refs counts sibling NLRIs on the same {bd, SID}, so
			// dropping the entry here would strand their references and
			// let a later recreation undercount them. The next refresh
			// of any referencing NLRI retries the same repair.
			return true, false
		}
		a.logger.Error("EVPN flood peer ledger missing for tracked RT3",
			zap.Uint16("bd_id", have.bdID), zap.String("sid", have.sid))
		delete(a.evpn.rt3Flood, nk)
		return true, false
	}
	if haveOK {
		fs, ok := a.evpn.floodPeers[have]
		switch {
		case ok && fs.refs > 1:
			fs.refs--
		case ok:
			// Last reference: delete the shared peer, but only if the slot
			// still holds the entry exactly as this ledger installed it --
			// checked and deleted in one critical section so an operator
			// free-and-reuse cannot slip in between, and compared against
			// the stored installed copy so a foreign same-SID entry on a
			// reused index is never deleted as ours and a locator change
			// cannot orphan our own entry. A transient read failure keeps
			// the ledger (it is an error, never a mismatch).
			existed, matched, err := a.fdbBd.DeleteBdPeerIfEntry(have.bdID, fs.index, &fs.entry)
			switch {
			case err != nil && existed && matched:
				a.logger.Error("delete EVPN BUM bd_peer",
					zap.Uint16("bd_id", have.bdID), zap.Uint16("index", fs.index), zap.Error(err))
				return false, false
			case err != nil:
				// Read failure: keep everything for a retry.
				a.logger.Error("verify EVPN BUM bd_peer occupant",
					zap.Uint16("bd_id", have.bdID), zap.Uint16("index", fs.index), zap.Error(err))
				return false, false
			case existed && !matched:
				a.logger.Warn("EVPN flood peer slot no longer holds this SID; dropping ledger without delete",
					zap.Uint16("bd_id", have.bdID), zap.Uint16("index", fs.index), zap.String("sid", have.sid))
				delete(a.evpn.floodPeers, have)
			default:
				delete(a.evpn.floodPeers, have)
			}
		default:
			a.logger.Error("EVPN flood peer ledger missing for tracked RT3",
				zap.Uint16("bd_id", have.bdID), zap.String("sid", have.sid))
		}
		delete(a.evpn.rt3Flood, nk)
	}
	if !wantOK {
		return true, true
	}
	if fs, ok := a.evpn.floodPeers[want]; ok {
		// The reference cap guards the shared peer's fan-in (distinct
		// NLRIs anycasting one SID are as attacker-mintable as the
		// per-NLRI contributions) and sits directly before the refs
		// increment so every acquire path -- admission, withdraw-driven
		// re-election, refresh -- hits the same judgment.
		if fs.refs >= maxEVPNContribsPerEntry {
			a.logger.Warn("EVPN RT3 flood reference cap reached; leaving the NLRI floodless",
				zap.Uint16("bd_id", want.bdID), zap.String("sid", want.sid), zap.Int("max", maxEVPNContribsPerEntry))
			return true, false
		}
		if !a.ensureFloodPeerInstalled(want, fs) {
			// Repair failed: leave the shared state for the NLRIs already
			// referencing it (their next refresh retries the repair) and
			// report the acquire failure without taking a ref.
			return true, false
		}
		fs.refs++
		a.evpn.rt3Flood[nk] = want
		return true, true
	}
	entry, err := a.buildL2HeadendEntry(want.sid, want.bdID, false)
	if err != nil {
		a.logger.Error("build EVPN RT3 headend entry",
			zap.String("sid", want.sid), zap.Error(err))
		return true, false
	}
	// The RT3 BUM peer does NOT write bd_peer_reverse_map (writeReverse=
	// false): that index-less map identifies the remote PE for the End.DT2
	// RX path (remote-MAC learning, Local-Bias split-horizon) and must
	// hold the unicast RT2 (End.DT2U) peer toward the same PE, not this
	// flood peer. remoteSrc is therefore unused here. Probe-and-create is
	// one critical section for the same reason as RT2.
	var noRemoteSrc [bpf.IPv6AddrLen]byte
	var zeroESI [bpf.ESILen]byte
	idx, err := a.fdbBd.CreateBdPeerAtFreeIndex(want.bdID, entry, zeroESI, noRemoteSrc, false)
	if err != nil {
		a.logger.Error("install EVPN BUM bd_peer",
			zap.Uint16("bd_id", want.bdID), zap.Error(err))
		return true, false
	}
	a.evpn.floodPeers[want] = &evpnPeerState{index: idx, refs: 1, entry: *entry}
	a.evpn.rt3Flood[nk] = want
	a.logger.Info("EVPN inclusive multicast (BUM) peer installed",
		zap.Uint16("bd_id", want.bdID), zap.String("sid", want.sid))
	return true, true
}

// applyEVPNEthernetSegment records (or removes) a remote PE's membership in an
// Ethernet Segment from an RT4 route, then re-runs DF election for that ESI.
// RT4 carries no SID; the ESI plus the originating router IP (next hop)
// identify the attaching PE. Membership is tracked for every ESI, but DF
// election only writes esi_map for an ESI this PE locally attaches (declared by
// the operator via `vbctl es create --local-attached`); an RT4 for an
// unattached ESI is recorded informationally and never creates a local ES, so a
// crafted RT4 cannot mint a phantom segment.
func (a *Applier) applyEVPNEthernetSegment(r *bgp.EVPNRoute, withdraw bool) {
	var zeroESI [bpf.ESILen]byte
	if r.ESI == zeroESI {
		a.logger.Warn("EVPN RT4 has all-zero ESI; skipping", zap.String("rd", r.RD))
		return
	}
	pe := r.NextHop
	if pe == "" {
		a.logger.Warn("EVPN RT4 has no originating PE (next hop); skipping",
			zap.String("rd", r.RD))
		return
	}

	// Record membership for every ESI, attached or not, so a later local
	// attach can elect a DF from RT4s that arrived first (ReelectDF).
	// electDF itself gates on local attachment, so an unattached ESI stays
	// informational. Membership is bounded (maxTrackedESIs /
	// maxMembersPerESI) so crafted RT4s cannot grow it without limit.
	// esMu serializes against ReelectDF on the RPC goroutine.
	a.evpn.esMu.Lock()
	defer a.evpn.esMu.Unlock()

	members := a.evpn.esMembers[r.ESI]
	if withdraw {
		if members == nil {
			return
		}
		delete(members, pe)
		if len(members) == 0 {
			delete(a.evpn.esMembers, r.ESI)
		}
	} else {
		if members == nil {
			if len(a.evpn.esMembers) >= maxTrackedESIs {
				a.logger.Warn("EVPN RT4 ESI table full; ignoring segment",
					zap.String("rd", r.RD), zap.Int("max", maxTrackedESIs))
				return
			}
			members = make(map[string]struct{})
			a.evpn.esMembers[r.ESI] = members
		}
		if _, known := members[pe]; !known && len(members) >= maxMembersPerESI {
			a.logger.Warn("EVPN RT4 member set full for ESI; ignoring PE",
				zap.String("rd", r.RD), zap.String("pe", pe), zap.Int("max", maxMembersPerESI))
			return
		}
		members[pe] = struct{}{}
	}
	a.electDF(r.ESI)
}

// ReelectDF re-runs DF election for an ESI from the membership already learned
// over RT4. The operator path calls it right after `es create` marks an ESI
// locally attached, so an RT4 that arrived before the local attach -- recorded
// in esMembers but skipped by election at the time, since electDF gates on local
// attachment -- is finally acted on. Safe to call for an unattached ESI (no-op).
func (a *Applier) ReelectDF(esi [bpf.ESILen]byte) {
	a.evpn.esMu.Lock()
	defer a.evpn.esMu.Unlock()
	a.electDF(esi)
}

// electDF runs the RFC 8584 default DF election for an ESI and writes the
// winner to esi_map. It is a no-op unless this PE locally attaches the ESI. The
// candidate set is the union of the RT4-advertised member PE sources and this
// PE's own local source; sorted numerically, the DF is index (ETag mod N).
// ELAN uses a single Ethernet Tag (0), so this picks the lowest PE in the
// ordered list -- deterministic and identical across PEs that see the same
// membership. The caller must hold a.evpn.esMu (it reads esMembers).
func (a *Applier) electDF(esi [bpf.ESILen]byte) {
	entry, err := a.fdbBd.GetEsi(esi)
	if err != nil || entry == nil || entry.LocalAttached == 0 {
		return // not locally attached: membership recorded only, no map write
	}
	local := netip.AddrFrom16(entry.LocalPeSrcAddr)
	// The server requires a local PE source when an ES is locally attached, but
	// guard here too: an unspecified or IPv4-mapped local source would sort
	// first (::) and win DF, installing a black-hole. Skip election (fail-open:
	// DF stays unset so all PEs forward) rather than write a bogus DF.
	if !local.Is6() || local.Is4In6() || local.IsUnspecified() {
		a.logger.Error("EVPN ES locally attached but local PE source is not a usable IPv6; skipping DF election",
			zap.String("local", local.String()))
		return
	}

	// Candidate set: local PE plus the RT4 member PEs, deduplicated. Reject
	// IPv4-mapped member addresses (the same guard RT2/RT3 apply to SIDs) so a
	// crafted next hop cannot skew the ordering or be elected as a bogus DF.
	seen := map[netip.Addr]struct{}{local: {}}
	cands := []netip.Addr{local}
	for peStr := range a.evpn.esMembers[esi] {
		addr, perr := netip.ParseAddr(peStr)
		if perr != nil || !addr.Is6() || addr.Is4In6() {
			continue
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		cands = append(cands, addr)
	}
	slices.SortFunc(cands, func(x, y netip.Addr) int { return x.Compare(y) })

	const etag = 0 // ELAN: single Ethernet Tag
	df := cands[etag%len(cands)]
	if _, err := a.fdbBd.SetEsiDfPe(esi, df.As16()); err != nil {
		a.logger.Error("set EVPN DF",
			zap.String("df", df.String()), zap.Error(err))
		return
	}
	a.logger.Info("EVPN DF elected",
		zap.String("df", df.String()), zap.Int("candidates", len(cands)))
}

// buildL2HeadendEntry assembles an H.Encaps.L2 entry that encapsulates the
// matched L2 frame toward a remote PE's L2 service SID -- End.DT2U for an RT2
// unicast peer, End.DT2M for an RT3 BUM flood peer. SrcAddr is the local encap
// source (the outer IPv6 source on the wire); the destination is the SID, taken
// from Segments[0] by the data plane, so DstAddr is left unset to match the
// server's L2 peer construction.
func (a *Applier) buildL2HeadendEntry(sid string, bdID uint16, floodExclude bool) (*bpf.HeadendEntry, error) {
	src, err := a.encapSource()
	if err != nil {
		return nil, err
	}
	segments, numSegments, err := bpf.ParseSegments([]string{sid})
	if err != nil {
		return nil, fmt.Errorf("parse L2 service SID %q: %w", sid, err)
	}
	e := &bpf.HeadendEntry{
		Mode:        uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2),
		NumSegments: numSegments,
		SrcAddr:     src,
		Segments:    segments,
		BdId:        bdID,
	}
	if floodExclude {
		// An RT2 unicast peer (End.DT2U) is a known-unicast target, not a BUM
		// flood destination; exclude it from the TC flood loop.
		e.FloodExclude = 1
	}
	return e, nil
}
