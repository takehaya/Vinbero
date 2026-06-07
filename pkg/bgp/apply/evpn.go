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
)

// fdbBdOps is the subset of bpf.MapOperations the EVPN applier writes:
// the FDB (MAC -> peer), the per-PE bd_peer encap entry, and the Ethernet
// Segment (ESI) table that DF election drives.
type fdbBdOps interface {
	CreateFdb(bdID uint16, mac net.HardwareAddr, entry *bpf.FdbEntry) error
	DeleteFdb(bdID uint16, mac net.HardwareAddr) error
	CreateBdPeer(bdID, index uint16, entry *bpf.HeadendEntry, esi [bpf.ESILen]byte, remoteSrc [bpf.IPv6AddrLen]byte, writeReverse bool) error
	DeleteBdPeer(bdID, index uint16) error
	// FindFreeBdPeerIndex returns the lowest bd_peer index not in use in the
	// real map, so a BGP-allocated peer never collides with an operator-created
	// or restart-pinned entry.
	FindFreeBdPeerIndex(bdID uint16) uint16
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

// evpnFdbKey is the stable identity of an RT2 NLRI ({RD, EthernetTag, MAC}),
// used as a reverse index so a withdrawal -- whose path attributes (route
// targets, Prefix-SID) may be absent -- can still find the bridge domain and
// peer the advertisement installed.
type evpnFdbKey struct {
	rd   string
	etag uint32
	mac  string
}

type evpnPeerState struct {
	index uint16
	refs  int
}

type evpnFdbState struct {
	bdID uint16
	mac  net.HardwareAddr
	peer evpnPeerKey
}

// evpnMcastKey is the stable identity of an RT3 Inclusive Multicast NLRI
// ({RD, EthernetTag}). A withdrawal -- whose route targets may be absent --
// recovers the bridge domain and bd_peer index from this reverse index.
type evpnMcastKey struct {
	rd   string
	etag uint32
}

// evpnMcastState records the BUM flood bd_peer an RT3 installed. Unlike a
// unicast peer it carries no reference count: one RT3 per remote PE maps to
// exactly one flood bd_peer.
type evpnMcastState struct {
	bdID  uint16
	index uint16
	sid   string
}

// evpnTable holds the EVPN applier's in-memory bookkeeping. peers/fdb/mcast are
// touched only from the single GoBGP RouteHandler goroutine (like steeredRoutes)
// and need no locking. esMembers and DF election are the exception: the operator
// path (es create -> ReelectDF) re-runs election from the RPC goroutine, so
// esMu serializes esMembers access and electDF across the two goroutines.
type evpnTable struct {
	peers map[evpnPeerKey]*evpnPeerState
	fdb   map[evpnFdbKey]evpnFdbState
	mcast map[evpnMcastKey]evpnMcastState
	// esMembers maps an ESI to the set of member PE source IPs learned from
	// RT4 (Ethernet Segment routes), the candidate set for DF election.
	// Guarded by esMu.
	esMembers map[[bpf.ESILen]byte]map[string]struct{}
	esMu      sync.Mutex
}

func newEVPNTable() *evpnTable {
	return &evpnTable{
		peers:     make(map[evpnPeerKey]*evpnPeerState),
		fdb:       make(map[evpnFdbKey]evpnFdbState),
		mcast:     make(map[evpnMcastKey]evpnMcastState),
		esMembers: make(map[[bpf.ESILen]byte]map[string]struct{}),
	}
}

// allocIndex returns a stable bd_peer index for key, reusing the existing one
// (and bumping its reference count) when the PE already has a peer in this BD.
// For a new peer it takes the index from newIdx -- backed by the real
// bd_peer_map via FindFreeBdPeerIndex -- so the slot never collides with an
// operator-created or restart-pinned entry. ok is false when the BD is full.
func (t *evpnTable) allocIndex(key evpnPeerKey, newIdx func() uint16) (uint16, bool) {
	if st, ok := t.peers[key]; ok {
		st.refs++
		return st.index, true
	}
	idx := newIdx()
	if idx >= bpf.MaxBumNexthops {
		return 0, false
	}
	t.peers[key] = &evpnPeerState{index: idx, refs: 1}
	return idx, true
}

// releaseIndex drops one reference to key's peer and reports whether the peer
// is now unreferenced (so the caller deletes the bd_peer).
func (t *evpnTable) releaseIndex(key evpnPeerKey) (uint16, bool) {
	st, ok := t.peers[key]
	if !ok {
		return 0, false
	}
	st.refs--
	if st.refs > 0 {
		return st.index, false
	}
	delete(t.peers, key)
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
// domain. MatchImportForFamily already skips BDID==0 bindings under
// FamilyEVPN, but the guard stays as belt-and-suspenders so an EVPN install
// without a real bridge domain is impossible.
func (a *Applier) matchEVPNBD(rts []string) (uint16, bool) {
	_, bdID, ok := a.vrfBindings.MatchImportForFamily(rts, bgp.FamilyEVPN)
	if !ok || bdID == 0 {
		return 0, false
	}
	return bdID, true
}

// isUsableSRv6SID reports whether sid is a routable IPv6 SID. An unspecified
// (::), IPv4-mapped, or unparseable address would install a black-hole or
// wrong-target peer, so callers reject the route. The SR Policy decode
// applies the same guard to transport SIDs.
func isUsableSRv6SID(sid string) bool {
	addr, err := netip.ParseAddr(sid)
	return err == nil && addr.Is6() && !addr.Is4In6() && !addr.IsUnspecified()
}

func (a *Applier) applyEVPN(r *bgp.EVPNRoute, withdraw bool) {
	switch r.Type {
	case bgp.EVPNRouteTypeMACIP:
		a.applyEVPNMacIP(r, withdraw)
	case bgp.EVPNRouteTypeInclusiveMulticast:
		a.applyEVPNInclusiveMulticast(r, withdraw)
	case bgp.EVPNRouteTypeEthernetSegment:
		a.applyEVPNEthernetSegment(r, withdraw)
	default:
		// Unsupported route types (RT1 Ethernet A-D, RT5 IP Prefix) are ignored.
	}
}

func (a *Applier) applyEVPNMacIP(r *bgp.EVPNRoute, withdraw bool) {
	if r.MAC == "" {
		a.logger.Warn("EVPN RT2 has no MAC; skipping", zap.String("rd", r.RD))
		return
	}
	fk := evpnFdbKey{rd: r.RD, etag: r.EthernetTag, mac: r.MAC}

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
	bdID, ok := a.matchEVPNBD(r.RTs)
	if !ok {
		a.logger.Warn("EVPN RT2 matches no bridge-domain binding; dropping",
			zap.String("mac", r.MAC), zap.Strings("rts", r.RTs))
		return
	}
	if r.SRv6SID == "" {
		a.logger.Warn("EVPN RT2 has no SRv6 SID; skipping",
			zap.String("mac", r.MAC), zap.String("rd", r.RD))
		return
	}
	// The End.DT2U SID must be a routable IPv6 SID; see isUsableSRv6SID.
	if !isUsableSRv6SID(r.SRv6SID) {
		a.logger.Warn("EVPN RT2 SID is not a usable IPv6 SID; skipping",
			zap.String("mac", r.MAC), zap.String("sid", r.SRv6SID))
		return
	}
	pk := evpnPeerKey{bdID: bdID, sid: r.SRv6SID}

	// Re-advertise / MAC move: an unchanged NLRI returns early so a second
	// allocIndex would not bump refs and leak the bd_peer slot. A MAC move
	// (different PE or BD) tears the old mapping down first so its peer
	// ref and FDB entry release before the new install.
	if prev, ok := a.evpn.fdb[fk]; ok {
		if prev.peer == pk && prev.bdID == bdID {
			return
		}
		a.withdrawEVPNMac(fk, prev)
	}

	entry, err := a.buildL2HeadendEntry(r.SRv6SID, bdID, true)
	if err != nil {
		a.logger.Error("build EVPN headend entry",
			zap.String("mac", r.MAC), zap.Error(err))
		return
	}
	rsrc := remoteSrcOrLocal(r.RemoteSrc, entry.SrcAddr)
	idx, ok := a.evpn.allocIndex(pk, func() uint16 { return a.fdbBd.FindFreeBdPeerIndex(bdID) })
	if !ok {
		a.logger.Error("EVPN bridge domain is full; cannot add peer",
			zap.Uint16("bd_id", bdID), zap.String("sid", r.SRv6SID))
		return
	}
	if err := a.fdbBd.CreateBdPeer(bdID, idx, entry, r.ESI, rsrc, true); err != nil {
		a.logger.Error("install EVPN bd_peer",
			zap.Uint16("bd_id", bdID), zap.Error(err))
		a.evpn.releaseIndex(pk)
		return
	}
	fdb := &bpf.FdbEntry{IsRemote: 1, PeerIndex: idx, BdId: bdID, Esi: r.ESI}
	if err := a.fdbBd.CreateFdb(bdID, mac, fdb); err != nil {
		a.logger.Error("install EVPN FDB", zap.String("mac", r.MAC), zap.Error(err))
		if rIdx, gone := a.evpn.releaseIndex(pk); gone {
			_ = a.fdbBd.DeleteBdPeer(bdID, rIdx)
		}
		return
	}
	a.evpn.fdb[fk] = evpnFdbState{bdID: bdID, mac: mac, peer: pk}
	a.logger.Info("EVPN MAC installed",
		zap.String("mac", r.MAC), zap.Uint16("bd_id", bdID), zap.String("sid", r.SRv6SID))
}

// withdrawEVPNMac removes the FDB entry recorded for fk and releases its peer
// reference, deleting the bd_peer when the last MAC stops referencing it. The
// caller holds the only goroutine that touches evpnTable.
func (a *Applier) withdrawEVPNMac(fk evpnFdbKey, st evpnFdbState) {
	if err := a.fdbBd.DeleteFdb(st.bdID, st.mac); err != nil {
		// The FDB entry is still in the map. Keep the reverse index so a
		// later retry can find and remove it; dropping it here would orphan
		// the map entry and the peer reference it holds.
		a.logger.Error("withdraw EVPN MAC",
			zap.String("mac", st.mac.String()), zap.Error(err))
		return
	}
	delete(a.evpn.fdb, fk)
	if idx, gone := a.evpn.releaseIndex(st.peer); gone {
		if err := a.fdbBd.DeleteBdPeer(st.bdID, idx); err != nil {
			// The bd_peer is still in the map but releaseIndex already
			// dropped it from the ledger. Re-pin the index (refs 0) so a
			// re-learn of this PE reuses the surviving entry instead of
			// allocating a duplicate and leaking the slot.
			a.evpn.peers[st.peer] = &evpnPeerState{index: idx, refs: 0}
			a.logger.Error("delete EVPN bd_peer",
				zap.Uint16("bd_id", st.bdID), zap.Uint16("index", idx), zap.Error(err))
		}
	}
}

// applyEVPNInclusiveMulticast installs (or withdraws) an RT3 Inclusive
// Multicast route as a BUM flood bd_peer toward the advertising PE's End.DT2M
// SID. The data-plane flood loop (tc_dispatch_bum_clones) replicates BUM
// frames to every bd_peer in the bridge domain, so adding the End.DT2M entry
// here is all the control plane has to do. One RT3 per PE maps to one
// flood bd_peer; no MAC/refcount bookkeeping is needed.
func (a *Applier) applyEVPNInclusiveMulticast(r *bgp.EVPNRoute, withdraw bool) {
	mk := evpnMcastKey{rd: r.RD, etag: r.EthernetTag}

	if withdraw {
		// A withdrawal may carry no route targets, so the bridge domain and
		// bd_peer index come from the reverse index. An unknown withdraw is a
		// no-op.
		if st, ok := a.evpn.mcast[mk]; ok {
			a.withdrawEVPNMcast(mk, st)
		}
		return
	}

	bdID, ok := a.matchEVPNBD(r.RTs)
	if !ok {
		a.logger.Warn("EVPN RT3 matches no bridge-domain binding; dropping",
			zap.String("rd", r.RD), zap.Strings("rts", r.RTs))
		return
	}
	if r.SRv6SID == "" {
		a.logger.Warn("EVPN RT3 has no SRv6 SID; skipping", zap.String("rd", r.RD))
		return
	}
	// The End.DT2M SID must be a routable IPv6 SID, same guard as RT2.
	if !isUsableSRv6SID(r.SRv6SID) {
		a.logger.Warn("EVPN RT3 SID is not a usable IPv6 SID; skipping",
			zap.String("rd", r.RD), zap.String("sid", r.SRv6SID))
		return
	}

	// Re-advertise: if nothing changed, leave the installed bd_peer untouched.
	// If the BD or SID moved, tear the old flood peer down before rebuilding.
	if prev, ok := a.evpn.mcast[mk]; ok {
		if prev.bdID == bdID && prev.sid == r.SRv6SID {
			return
		}
		a.withdrawEVPNMcast(mk, prev)
	}

	entry, err := a.buildL2HeadendEntry(r.SRv6SID, bdID, false)
	if err != nil {
		a.logger.Error("build EVPN RT3 headend entry",
			zap.String("rd", r.RD), zap.Error(err))
		return
	}
	idx := a.fdbBd.FindFreeBdPeerIndex(bdID)
	if idx >= bpf.MaxBumNexthops {
		a.logger.Error("EVPN bridge domain is full; cannot add BUM peer",
			zap.Uint16("bd_id", bdID), zap.String("sid", r.SRv6SID))
		return
	}
	// The RT3 BUM peer does NOT write bd_peer_reverse_map (writeReverse=false):
	// that index-less map identifies the remote PE for the End.DT2 RX path
	// (remote-MAC learning, Local-Bias split-horizon) and must hold the unicast
	// RT2 (End.DT2U) peer toward the same PE, not this flood peer. remoteSrc is
	// therefore unused here.
	var noRemoteSrc [bpf.IPv6AddrLen]byte
	if err := a.fdbBd.CreateBdPeer(bdID, idx, entry, r.ESI, noRemoteSrc, false); err != nil {
		a.logger.Error("install EVPN BUM bd_peer",
			zap.Uint16("bd_id", bdID), zap.Error(err))
		return
	}
	a.evpn.mcast[mk] = evpnMcastState{bdID: bdID, index: idx, sid: r.SRv6SID}
	a.logger.Info("EVPN inclusive multicast (BUM) peer installed",
		zap.String("rd", r.RD), zap.Uint16("bd_id", bdID), zap.String("sid", r.SRv6SID))
}

// withdrawEVPNMcast removes the BUM flood bd_peer recorded for mk. The ledger
// entry is kept if the map delete fails so a retry can still remove it.
func (a *Applier) withdrawEVPNMcast(mk evpnMcastKey, st evpnMcastState) {
	if err := a.fdbBd.DeleteBdPeer(st.bdID, st.index); err != nil {
		a.logger.Error("delete EVPN BUM bd_peer",
			zap.Uint16("bd_id", st.bdID), zap.Uint16("index", st.index), zap.Error(err))
		return
	}
	delete(a.evpn.mcast, mk)
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
