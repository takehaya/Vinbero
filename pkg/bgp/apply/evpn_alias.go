package apply

import (
	"cmp"
	"fmt"
	"net"
	"slices"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// EVPN aliasing (RFC 7432 §8.4) turns a multi-homed Ethernet Segment into an
// ECMP group: a MAC learned behind an all-active ES is reachable through
// every PE that attaches the segment, not only the one that advertised the
// RT2.
//
// The data-plane shape reuses the bd_peer escape: each {bridge domain, ESI}
// gets one synthetic "ES peer" -- a bd_peer entry parked above the BUM flood
// range whose headend_entry carries the group id -- and the FDB entry of
// every MAC on that segment points at it. l2_headend resolves the group per
// flow. The members are the per-EVI Ethernet A-D SIDs of the PEs whose
// per-ES A-D declares the segment all-active.
//
// Pointing the FDB at the segment rather than at one PE is also what fixes
// the shared-key withdraw defect: {bd, MAC} is one data-plane key however
// many PEs advertise the MAC, so with per-PE pointers the first withdrawal
// tore down an entry the surviving PEs still backed. Now a PE's withdrawal
// only shrinks the group, and the FDB entry lives until the last
// contribution is gone (see withdrawEVPNMac's survivor hand-off for the
// non-aliased remainder of that defect).

// Bounds against a peer that floods A-D routes, in the same spirit as
// maxTrackedESIs.
const (
	maxTrackedESADs  = maxTrackedESIs * maxMembersPerESI
	maxTrackedEviADs = 4096
	maxTrackedESDest = 1024
)

// esGroupIDBase partitions the ecmp group id space: EVPN segment groups
// allocate at and above it, the VPN prefix table allocates below it, and the
// two never have to share an allocator (they run on differently-locked
// paths; see vpnGroupTable's no-lock comment vs evpnMu).
const esGroupIDBase uint32 = 0x80000000

// esDestKey identifies one aliasing target: a multi-homed segment as seen
// from one bridge domain. The per-EVI A-D routes that feed it arrive under
// per-PE RDs and resolve to the bd through the import-RT filter, like RT2.
type esDestKey struct {
	bdID uint16
	esi  [bpf.ESILen]byte
}

// esDest is the programmed state for one {bd, ESI}: the ECMP group and the
// synthetic ES bd_peer fronting it. Members are not cached here -- they are
// re-derived from the eviAD table on every reconcile, so membership can
// never drift from the route state.
type esDest struct {
	groupID uint32
	peerIdx uint16
	// active reports that the group and ES peer are installed, so FDB
	// entries may point at peerIdx. It flips on the first successful
	// reconcile; formation repoints the segment's MACs exactly once.
	active bool
	// needRepoint remembers that some MAC could not be moved onto the ES
	// peer at formation, so a later reconcile re-runs the repoint (active
	// alone would skip it).
	needRepoint bool
	// programmed reports that map state (the group, and possibly the ES
	// peer) exists for this dest and must be torn down before the dest --
	// and its group id -- may be released. It outlives active: a failed
	// reconcile can leave a dest inactive but still programmed.
	programmed bool
	// installed is the member SID list last written (see memberFingerprint's
	// role in vpngroup.go).
	installed []string
}

// esNLRIKey is the stable identity of a per-ES Ethernet A-D NLRI
// ({RD, ESI}; the Ethernet Tag is fixed at MAX-ET).
type esNLRIKey struct {
	rd  string
	esi [bpf.ESILen]byte
}

// evpnEviADKey is the stable identity of a per-EVI Ethernet A-D NLRI
// ({RD, ESI, EthernetTag}), the reverse index a withdrawal -- which may
// carry no route targets -- recovers the bridge domain from.
type evpnEviADKey struct {
	rd   string
	esi  [bpf.ESILen]byte
	etag uint32
}

// eviADState records what one per-EVI A-D advertisement contributed.
type eviADState struct {
	bdID uint16
	pe   string
	sid  string
}

// macDPKey is the data-plane identity of an FDB entry: {bd, MAC}. Several
// RT2s (one per advertising PE, each under its own RD) can share it.
type macDPKey struct {
	bdID uint16
	mac  string
}

// esMember is one PE's aliasing contribution after eligibility filtering.
type esMember struct {
	pe  string
	sid string
}

// allocESGroupID hands out group ids in the EVPN partition. Caller holds
// evpnMu.
func (t *evpnTable) allocESGroupID() (uint32, error) {
	if n := len(t.freeGroupIDs); n > 0 {
		id := t.freeGroupIDs[n-1]
		t.freeGroupIDs = t.freeGroupIDs[:n-1]
		return id, nil
	}
	if t.nextGroupID == ^uint32(0) {
		return 0, fmt.Errorf("EVPN ecmp group id space exhausted")
	}
	if t.nextGroupID < esGroupIDBase {
		t.nextGroupID = esGroupIDBase
		return t.nextGroupID, nil
	}
	t.nextGroupID++
	return t.nextGroupID, nil
}

// esGroupOwner is the owner every segment group carries.
func (a *Applier) esGroupOwner() bpf.OwnerTag {
	return bpf.OwnerBGPEVPNGroup(a.localASN)
}

// resetEVPNGroups sweeps the segment groups a previous run left in the
// pinned maps and seeds id allocation above whatever high-partition ids
// survive, mirroring vpnGroupTable.reset for the EVPN owner. It runs from
// NewApplier before any route arrives -- and before vpnGroups.reset(), so
// the VPN table's own high-water seed is not inflated by EVPN ids this sweep
// is about to remove.
func (a *Applier) resetEVPNGroups() {
	// The synthetic ES peers live in an applier-exclusive index range (the
	// operator RPC allocates below EsPeerIndexBase), so every entry found
	// there is a previous run's leftover. Sweep them: under pinned maps a
	// restart would otherwise leak one slot per generation, and a stale
	// entry keeps referencing a group id this reset is about to delete and
	// re-hand out to a different segment.
	// FDB entries pointing into the ES range go first: with pinned maps
	// they too survive a restart, and a MAC that the replayed rib no
	// longer carries would keep aiming at an index a different segment may
	// be handed later.
	sweepOK := true
	if fdbs, err := a.fdbBd.ListFdb(); err != nil {
		a.logger.Error("list fdb; stale EVPN aliasing pointers may be left behind", zap.Error(err))
		sweepOK = false
	} else {
		for k, e := range fdbs {
			if e.IsRemote == 0 || e.PeerIndex < bpf.EsPeerIndexBase ||
				e.PeerIndex >= bpf.EsPeerIndexBase+bpf.MaxEsPeersPerBd {
				continue
			}
			if derr := a.fdbBd.DeleteFdb(k.BdId, net.HardwareAddr(k.Mac[:])); derr != nil {
				a.logger.Error("sweep stale EVPN aliasing FDB entry",
					zap.Uint16("bd_id", k.BdId), zap.Error(derr))
				sweepOK = false
			}
		}
	}

	// The ES peers come out only after every stale FDB pointer did: a
	// surviving FDB entry may aim at one of these peers, and removing the
	// peer would break that entry's forwarding from boot. Group deletion
	// below is gated the same way; id allocation still seeds above the
	// retained generation, so nothing collides.
	if !sweepOK {
		a.logger.Error("EVPN startup sweep incomplete; leaving previous run's ES peers and groups installed")
	} else if peers, err := a.fdbBd.ListBdPeers(); err != nil {
		a.logger.Error("list bd_peers; stale EVPN ES peers may be left behind", zap.Error(err))
		sweepOK = false
	} else {
		for k := range peers {
			// Only the reserved ES range: an index above it is not ours
			// (a future use, or something injected into the map directly)
			// and must survive the sweep.
			if k.Index < bpf.EsPeerIndexBase || k.Index >= bpf.EsPeerIndexBase+bpf.MaxEsPeersPerBd {
				continue
			}
			if derr := a.fdbBd.DeleteBdPeer(k.BdId, k.Index); derr != nil {
				a.logger.Error("sweep stale EVPN ES peer",
					zap.Uint16("bd_id", k.BdId), zap.Uint16("index", k.Index), zap.Error(derr))
				sweepOK = false
				continue
			}
			a.logger.Info("swept EVPN ES peer left by a previous run",
				zap.Uint16("bd_id", k.BdId), zap.Uint16("index", k.Index))
		}
	}

	owners, err := a.ecmp.ListEcmpGroupOwners()
	if err != nil {
		a.logger.Error("list ecmp group owners; stale EVPN groups may be left behind", zap.Error(err))
		owners = nil
	}
	mine := a.esGroupOwner()
	for id, owner := range owners {
		if owner != mine || !sweepOK {
			continue
		}
		if err := a.ecmp.DeleteEcmpGroup(id, mine); err != nil {
			a.logger.Error("sweep stale EVPN ecmp group", zap.Uint32("group_id", id), zap.Error(err))
			continue
		}
		a.logger.Info("swept EVPN ecmp group left by a previous run", zap.Uint32("group_id", id))
	}

	groups, err := a.ecmp.ListEcmpGroups()
	if err != nil {
		a.logger.Error("list ecmp groups; EVPN id allocation may collide with surviving groups", zap.Error(err))
		return
	}
	for id := range groups {
		if id >= esGroupIDBase && id > a.evpn.nextGroupID {
			a.evpn.nextGroupID = id
		}
	}
}

// applyEVPNPerESAD tracks a per-ES Ethernet A-D route. An advertisement
// declares the PE's attachment (and, through the ESI Label extended
// community, whether the segment may be aliased); a withdrawal is the mass
// withdraw of RFC 7432 §8.2.
//
// On withdrawal the segment's groups shrink first, so a MAC whose bridge
// domain still has a live aliasing group stays where it is -- forwarding
// converges onto the surviving PEs at group level, and the withdrawn PE's
// RT2 ledger entries drain as their own withdrawals arrive. Only a MAC with
// no surviving group left to cover it is torn down here, one route instead
// of thousands. Caller holds evpnMu.
func (a *Applier) applyEVPNPerESAD(r *bgp.EVPNRoute, withdraw bool) {
	var zeroESI [bpf.ESILen]byte
	if r.ESI == zeroESI || r.NextHop == "" {
		// Without both we cannot say whose contribution this is, and
		// guessing would tear down state that is still backed.
		return
	}
	k := esMemberKey{esi: r.ESI, pe: r.NextHop}
	nk := esNLRIKey{rd: r.RD, esi: r.ESI}

	if withdraw {
		delete(a.evpn.esADByNLRI, nk)
		// Not gated on having seen the advertisement: the segment's MACs
		// may all have been learned from RT2s alone (the per-ES route can
		// predate this process), and the withdrawal is a statement about
		// the segment either way.
		a.dropESContribution(k)
		return
	}

	// A re-advertisement of the same NLRI under a new next hop is an
	// implicit replace of the old PE's contribution -- the NLRI identity
	// carries no PE, so no withdrawal will ever name it.
	if oldPE, known := a.evpn.esADByNLRI[nk]; known && oldPE != r.NextHop {
		a.dropESContribution(esMemberKey{esi: r.ESI, pe: oldPE})
	}

	if _, known := a.evpn.esAD[k]; !known && len(a.evpn.esAD) >= maxTrackedESADs {
		a.logger.Warn("EVPN per-ES A-D table full; ignoring route",
			zap.String("pe", r.NextHop), zap.Int("max", maxTrackedESADs))
		return
	}
	// The NLRI ledger has its own bound: the aggregated esAD count above
	// does not grow when one {ESI, PE} is re-advertised under ever-new RDs,
	// but this ledger would.
	if _, known := a.evpn.esADByNLRI[nk]; !known && len(a.evpn.esADByNLRI) >= maxTrackedESADs {
		a.logger.Warn("EVPN per-ES A-D NLRI ledger full; ignoring route",
			zap.String("rd", r.RD), zap.Int("max", maxTrackedESADs))
		return
	}
	a.evpn.esADByNLRI[nk] = r.NextHop
	a.evpn.esAD[k] = r.SingleActive
	delete(a.evpn.esWithdrawn, k) // the segment is back on this PE
	a.reconcileESDestsForESI(r.ESI)
}

// dropESContribution runs the per-ES withdrawal semantics for one {ESI, PE}:
// the segment's groups shrink first, uncovered MACs are mass-withdrawn, and
// covered ones are marked for the sweep a later dissolve finishes.
func (a *Applier) dropESContribution(k esMemberKey) {
	delete(a.evpn.esAD, k)
	a.reconcileESDestsForESI(k.esi)
	a.massWithdrawUncovered(k)
	if len(a.evpn.macsByES[k]) > 0 {
		a.evpn.esWithdrawn[k] = struct{}{}
	}
}

// massWithdrawUncovered withdraws every MAC the departed PE taught on the
// segment whose bridge domain has no live aliasing group left to cover it.
func (a *Applier) massWithdrawUncovered(k esMemberKey) {
	macs := a.evpn.macsByES[k]
	if len(macs) == 0 {
		return
	}
	// withdrawEVPNMac deletes from this very map through unindexMACByES,
	// which Go permits during a range: an entry removed before it is reached
	// is simply not produced. A segment can hold thousands of MACs, so
	// copying the keys first would add an allocation proportional to the
	// convergence event for no benefit.
	n := 0
	for fk := range macs {
		st, ok := a.evpn.fdb[fk]
		if !ok {
			continue
		}
		// installed != nil: the group write is known good. A dest whose
		// last reconcile failed (installed cleared) may still list the
		// withdrawn PE, so it does not count as coverage -- tearing the
		// MAC down converges at MAC level, the pre-aliasing behavior.
		if d := a.evpn.esDests[esDestKey{bdID: st.bdID, esi: st.esi}]; d != nil && d.active && d.installed != nil {
			continue // the surviving PEs' group still forwards this MAC
		}
		a.withdrawEVPNMac(fk, st)
		n++
	}
	a.logger.Info("EVPN mass withdraw", zap.String("pe", k.pe), zap.Int("macs", n))
}

// applyEVPNPerEVIAD tracks a per-EVI Ethernet A-D route, the carrier of the
// aliasing SID (RFC 7432 §8.4). Caller holds evpnMu.
func (a *Applier) applyEVPNPerEVIAD(r *bgp.EVPNRoute, withdraw bool) {
	ak := evpnEviADKey{rd: r.RD, esi: r.ESI, etag: r.EthernetTag}

	if withdraw {
		// The bridge domain comes from the reverse index: a withdrawal may
		// carry no route targets. An unknown withdraw is a no-op.
		st, ok := a.evpn.eviAD[ak]
		if !ok {
			return
		}
		delete(a.evpn.eviAD, ak)
		a.reconcileESKey(esDestKey{bdID: st.bdID, esi: ak.esi})
		return
	}

	// dropTracked fails closed for an unusable re-advertisement of a
	// tracked NLRI: it is an implicit replace of the old path, so keeping
	// the old contribution would leave the PE in a group its route no
	// longer backs.
	dropTracked := func() {
		if old, known := a.evpn.eviAD[ak]; known {
			delete(a.evpn.eviAD, ak)
			a.reconcileESKey(esDestKey{bdID: old.bdID, esi: ak.esi})
		}
	}

	var zeroESI [bpf.ESILen]byte
	if r.ESI == zeroESI || r.NextHop == "" {
		dropTracked()
		a.logger.Warn("EVPN per-EVI A-D without ESI or next hop; skipping",
			zap.String("rd", r.RD))
		return
	}
	bdID, ok := a.matchEVPNBD(r.RTs)
	if !ok {
		dropTracked()
		a.logger.Warn("EVPN per-EVI A-D matches no bridge-domain binding; dropping",
			zap.String("rd", r.RD), zap.Strings("rts", r.RTs))
		return
	}
	if !isUsableSRv6SID(r.SRv6SID) {
		dropTracked()
		a.logger.Warn("EVPN per-EVI A-D SID is not a usable IPv6 SID; skipping",
			zap.String("rd", r.RD), zap.String("sid", r.SRv6SID))
		return
	}
	// The import surface can move an NLRI to another bridge domain (an RT
	// rebind replayed, or a re-advertisement under new RTs). That arrives
	// as an implicit replace with no withdraw for the old bd, so take the
	// contribution out of the old bd's group here.
	if old, known := a.evpn.eviAD[ak]; known && old.bdID != bdID {
		delete(a.evpn.eviAD, ak)
		a.reconcileESKey(esDestKey{bdID: old.bdID, esi: r.ESI})
	}
	if _, known := a.evpn.eviAD[ak]; !known && len(a.evpn.eviAD) >= maxTrackedEviADs {
		a.logger.Warn("EVPN per-EVI A-D table full; ignoring route",
			zap.String("rd", r.RD), zap.Int("max", maxTrackedEviADs))
		return
	}
	a.evpn.eviAD[ak] = eviADState{bdID: bdID, pe: r.NextHop, sid: r.SRv6SID}
	a.reconcileESKey(esDestKey{bdID: bdID, esi: r.ESI})
}

// collectESMembers derives the aliasing member set for one {bd, ESI} from
// the route state: every PE with a per-EVI A-D for it whose per-ES A-D
// declares the segment all-active. Deterministically ordered and deduped by
// SID (two PEs advertising one anycast SID are one forwarding outcome), then
// capped at what the data plane programs -- the same reasoning as
// vpnDest.members.
func (a *Applier) collectESMembers(dk esDestKey) []esMember {
	// A PE can hold several per-EVI ADs for one {bd, ESI} (one per RD); the
	// lowest SID represents it, deterministically.
	perPE := make(map[string]string)
	for ak, st := range a.evpn.eviAD {
		if ak.esi != dk.esi || st.bdID != dk.bdID {
			continue
		}
		single, attached := a.evpn.esAD[esMemberKey{esi: ak.esi, pe: st.pe}]
		if !attached || single {
			continue
		}
		if cur, ok := perPE[st.pe]; !ok || st.sid < cur {
			perPE[st.pe] = st.sid
		}
	}
	out := make([]esMember, 0, len(perPE))
	for pe, sid := range perPE {
		out = append(out, esMember{pe: pe, sid: sid})
	}
	slices.SortFunc(out, func(x, y esMember) int {
		if c := cmp.Compare(x.sid, y.sid); c != 0 {
			return c
		}
		return cmp.Compare(x.pe, y.pe)
	})
	out = slices.CompactFunc(out, func(x, y esMember) bool { return x.sid == y.sid })
	if len(out) > bpf.EcmpMaxPaths {
		out = out[:bpf.EcmpMaxPaths]
	}
	return out
}

// reconcileESDestsForESI re-reconciles every bridge domain that has per-EVI
// state for the segment: a per-ES A-D arriving or leaving changes member
// eligibility in all of them.
func (a *Applier) reconcileESDestsForESI(esi [bpf.ESILen]byte) {
	seen := make(map[uint16]struct{})
	for ak, st := range a.evpn.eviAD {
		if ak.esi != esi {
			continue
		}
		if _, dup := seen[st.bdID]; dup {
			continue
		}
		seen[st.bdID] = struct{}{}
		a.reconcileESKey(esDestKey{bdID: st.bdID, esi: esi})
	}
	// Also visit dests whose eviAD state is already gone: a dissolve that
	// had to stop halfway (sweep failure) survives with no per-EVI entry
	// left to find it, and this is its retry path.
	for dk := range a.evpn.esDests {
		if dk.esi != esi {
			continue
		}
		if _, dup := seen[dk.bdID]; dup {
			continue
		}
		seen[dk.bdID] = struct{}{}
		a.reconcileESKey(dk)
	}
}

// reconcileESKey brings one {bd, ESI}'s programmed state in line with the
// derived member set: group, ES peer, and -- on formation -- the FDB
// pointers of the MACs already learned on the segment. Caller holds evpnMu.
func (a *Applier) reconcileESKey(dk esDestKey) {
	members := a.collectESMembers(dk)
	d := a.evpn.esDests[dk]
	if len(members) == 0 {
		if d != nil {
			a.dissolveESDest(dk, d)
		}
		return
	}
	if d == nil {
		if len(a.evpn.esDests) >= maxTrackedESDest {
			a.logger.Warn("EVPN segment table full; not aliasing",
				zap.Uint16("bd_id", dk.bdID), zap.Int("max", maxTrackedESDest))
			return
		}
		id, err := a.evpn.allocESGroupID()
		if err != nil {
			a.logger.Error("allocate EVPN ecmp group id", zap.Error(err))
			return
		}
		idx := a.freeESPeerIndex(dk.bdID)
		if idx >= bpf.EsPeerIndexBase+bpf.MaxEsPeersPerBd {
			a.logger.Error("EVPN ES peer range full in bridge domain; not aliasing",
				zap.Uint16("bd_id", dk.bdID))
			a.evpn.freeGroupIDs = append(a.evpn.freeGroupIDs, id)
			return
		}
		d = &esDest{groupID: id, peerIdx: idx}
		a.evpn.esDests[dk] = d
	}

	fingerprint := make([]string, len(members))
	for i, m := range members {
		// The PE is part of it: with an anycast SID the surviving member's
		// probe destination changes even when the SID does not.
		fingerprint[i] = m.sid + ">" + m.pe
	}
	if d.active && slices.Equal(fingerprint, d.installed) {
		return
	}

	// fail unwinds a half-done reconcile back to per-PE forwarding. The
	// programmed state cannot be trusted after a failed write -- a failed
	// CreateBdPeer even removes the forward entry as its own rollback, so
	// an FDB entry left aimed at the ES peer might point at nothing. When
	// the teardown completes the dest is dropped and rebuilt from scratch
	// by the next event; while any of its state resists removal the dest
	// -- and its group id -- stay reserved (fingerprint cleared), so
	// nothing else can be handed its index or id in the meantime.
	fail := func() {
		d.active = false
		if !a.teardownESDest(dk, d) {
			d.installed = nil
			a.logger.Error("EVPN aliasing unwind incomplete; keeping dest for rebuild",
				zap.Uint16("bd_id", dk.bdID), zap.Uint32("group_id", d.groupID))
			return
		}
		a.prober.Unregister(d.groupID)
		delete(a.evpn.esDests, dk)
		a.evpn.freeGroupIDs = append(a.evpn.freeGroupIDs, d.groupID)
	}

	paths := make([]bpf.EcmpPath, 0, len(members))
	for _, m := range members {
		entry, err := a.buildL2HeadendEntry(m.sid, dk.bdID, true)
		if err != nil {
			a.logger.Error("build EVPN aliasing member",
				zap.Uint16("bd_id", dk.bdID), zap.String("sid", m.sid), zap.Error(err))
			fail()
			return
		}
		// Equal weights, like the VPN groups: BGP has no notion of relative
		// capacity between the PEs.
		paths = append(paths, bpf.EcmpPath{Entry: entry, Weight: 1})
	}
	if err := a.ecmp.PutEcmpGroup(d.groupID, paths, a.esGroupOwner()); err != nil {
		a.logger.Error("install EVPN aliasing group",
			zap.Uint16("bd_id", dk.bdID), zap.Uint32("group_id", d.groupID), zap.Error(err))
		fail()
		return
	}
	d.programmed = true

	// The ES peer mirrors the first member so the group-unresolvable
	// fallback forwards the way the first path would (same shape as the VPN
	// trigger entries). It is parked above the flood range and marked
	// flood-excluded, so BUM replication never sees it.
	trigger, err := a.buildL2HeadendEntry(members[0].sid, dk.bdID, true)
	if err != nil {
		a.logger.Error("build EVPN ES peer entry",
			zap.Uint16("bd_id", dk.bdID), zap.Error(err))
		fail()
		return
	}
	trigger.GroupId = d.groupID
	var noRemoteSrc [bpf.IPv6AddrLen]byte
	if err := a.fdbBd.CreateBdPeer(dk.bdID, d.peerIdx, trigger, dk.esi, noRemoteSrc, false); err != nil {
		a.logger.Error("install EVPN ES peer",
			zap.Uint16("bd_id", dk.bdID), zap.Uint16("index", d.peerIdx), zap.Error(err))
		fail()
		return
	}
	dsts := make([]string, len(members))
	for i, m := range members {
		dsts[i] = m.pe
	}
	a.prober.Register(d.groupID, probeTargets(paths, dsts))
	d.installed = fingerprint
	if !d.active || d.needRepoint {
		d.active = true
		// A MAC whose repoint failed still forwards through its per-PE
		// peer, so nothing is broken -- but remember the debt and clear
		// the fingerprint, so the next event for this key re-runs the
		// repoint instead of early-returning on an unchanged member set.
		d.needRepoint = !a.repointSegmentMacs(dk, d.peerIdx)
		if d.needRepoint {
			d.installed = nil
		}
	}
	a.logger.Info("EVPN segment aliased",
		zap.Uint16("bd_id", dk.bdID), zap.Uint32("group_id", d.groupID),
		zap.Int("members", len(members)))
}

// dissolveESDest tears one {bd, ESI} back down to per-PE forwarding: the
// segment's MACs get their terminal state (see sweepSegmentMacs), then the
// ES peer and the group go. While anything resists removal the dest -- and
// its group id -- stay reserved, so a later event retries the dissolve
// (reconcileESDestsForESI visits leftover dests exactly for this).
// Caller holds evpnMu.
func (a *Applier) dissolveESDest(dk esDestKey, d *esDest) {
	// Deactivate before the sweep: withdrawEVPNMac's survivor hand-off
	// re-installs shared FDB entries through fdbTargetIndex, which must
	// already resolve to the per-PE peers, not the ES peer being removed.
	d.active = false
	if !a.teardownESDest(dk, d) {
		d.installed = nil
		a.logger.Error("EVPN segment dissolve incomplete; keeping dest for retry",
			zap.Uint16("bd_id", dk.bdID), zap.Uint32("group_id", d.groupID))
		return
	}
	a.prober.Unregister(d.groupID)
	delete(a.evpn.esDests, dk)
	a.evpn.freeGroupIDs = append(a.evpn.freeGroupIDs, d.groupID)
	a.logger.Info("EVPN segment aliasing dissolved",
		zap.Uint16("bd_id", dk.bdID), zap.Uint32("group_id", d.groupID))
}

// teardownESDest removes whatever programmed state the dest still holds:
// the segment's MACs are swept off the ES peer, then the peer (if it still
// exists -- a failed CreateBdPeer rolls its own entry away) and the group
// go. Returns false when something could not be removed; the caller must
// then keep the dest so its index and group id stay reserved and a later
// call can finish the job. Caller holds evpnMu and has cleared d.active.
func (a *Applier) teardownESDest(dk esDestKey, d *esDest) bool {
	if !d.programmed {
		return true
	}
	if !a.sweepSegmentMacs(dk) {
		// Some FDB entry still aims at the ES peer; removing the peer now
		// would cut it over to nothing.
		return false
	}
	exists := true
	if peers, err := a.fdbBd.ListBdPeers(); err == nil {
		_, exists = peers[bpf.BdPeerKey{BdId: dk.bdID, Index: d.peerIdx}]
	}
	if exists {
		if err := a.fdbBd.DeleteBdPeer(dk.bdID, d.peerIdx); err != nil {
			a.logger.Error("delete EVPN ES peer",
				zap.Uint16("bd_id", dk.bdID), zap.Uint16("index", d.peerIdx), zap.Error(err))
			return false
		}
	}
	if err := a.ecmp.DeleteEcmpGroup(d.groupID, a.esGroupOwner()); err != nil {
		a.logger.Error("delete EVPN aliasing group",
			zap.Uint32("group_id", d.groupID), zap.Error(err))
		return false
	}
	d.programmed = false
	return true
}

// repointSegmentMacs points every learned MAC on {bd, ESI} at the ES peer.
// Runs at formation, so MACs that arrived before the A-D routes join the
// group; a MAC arriving after formation targets the ES peer directly in
// applyEVPNMacIP. Reports whether every write landed.
func (a *Applier) repointSegmentMacs(dk esDestKey, toIdx uint16) bool {
	ok := true
	a.forEachSegmentMac(dk, func(fk evpnFdbKey, st evpnFdbState) {
		fdb := &bpf.FdbEntry{IsRemote: 1, PeerIndex: toIdx, BdId: st.bdID, Esi: st.esi}
		if err := a.fdbBd.CreateFdb(st.bdID, st.mac, fdb); err != nil {
			a.logger.Error("repoint EVPN MAC to ES peer",
				zap.String("mac", st.mac.String()), zap.Error(err))
			ok = false
		}
	})
	return ok
}

// sweepSegmentMacs hands every learned MAC on a dissolving {bd, ESI} its
// terminal state. A MAC taught by a PE whose per-ES withdrawal was deferred
// (retained because the group still covered it) is withdrawn outright: the
// PE declared the segment gone, and pointing it back at the departed PE
// would re-create the blackhole the mass withdraw removed. Every other MAC
// falls back to its advertising PE's own bd_peer. Reports whether every MAC
// reached its terminal state -- a false return means some FDB entry still
// aims at the ES peer.
func (a *Applier) sweepSegmentMacs(dk esDestKey) bool {
	ok := true
	handled := make(map[macDPKey]struct{})
	a.forEachSegmentMac(dk, func(fk evpnFdbKey, st evpnFdbState) {
		if _, gone := a.evpn.esWithdrawn[esMemberKey{esi: st.esi, pe: st.pe}]; gone {
			a.withdrawEVPNMac(fk, st)
			if _, still := a.evpn.fdb[fk]; still {
				// The withdraw kept the ledger because a map write failed;
				// the shared entry may still point at the ES peer.
				ok = false
			}
			return
		}
		// The data-plane key is shared across the MAC's contributions;
		// write it once, from the deterministic representative, so the
		// post-dissolve target does not depend on map iteration order.
		mk := macDPKey{bdID: st.bdID, mac: st.mac.String()}
		if _, done := handled[mk]; done {
			return
		}
		handled[mk] = struct{}{}
		_, repSt, found := a.pickContrib(mk, func(_ evpnFdbKey, cst evpnFdbState) bool {
			_, w := a.evpn.esWithdrawn[esMemberKey{esi: cst.esi, pe: cst.pe}]
			return w
		})
		if !found {
			repSt = st
		}
		ps, resolvable := a.evpn.peers[repSt.peer]
		if !resolvable {
			// The per-PE peer should exist for as long as the fdb ledger
			// holds the MAC; a miss means the ledgers disagree.
			a.logger.Error("EVPN MAC has no per-PE peer to fall back to",
				zap.String("mac", repSt.mac.String()))
			ok = false
			return
		}
		fdb := &bpf.FdbEntry{IsRemote: 1, PeerIndex: ps.index, BdId: repSt.bdID, Esi: repSt.esi}
		if err := a.fdbBd.CreateFdb(repSt.bdID, repSt.mac, fdb); err != nil {
			a.logger.Error("repoint EVPN MAC to per-PE peer",
				zap.String("mac", repSt.mac.String()), zap.Error(err))
			ok = false
		}
	})
	return ok
}

// freeESPeerIndex picks the lowest ES-range bd_peer index that neither the
// real map nor the dest ledger holds for this bridge domain. The ledger
// matters because a dest kept for a rebuild after a failed reconcile may
// reserve an index whose map entry was rolled away -- a pure map scan would
// hand that slot to a second segment. Falls back to the map-only scan when
// the map cannot be listed.
func (a *Applier) freeESPeerIndex(bdID uint16) uint16 {
	used := make(map[uint16]struct{})
	for k, d := range a.evpn.esDests {
		if k.bdID == bdID {
			used[d.peerIdx] = struct{}{}
		}
	}
	peers, err := a.fdbBd.ListBdPeers()
	if err != nil {
		// Fail closed: a map-only scan cannot see a ledgered index whose
		// map entry was rolled away, and handing that slot out would let
		// two segments overwrite each other's ES peer on retry.
		a.logger.Error("list bd_peers for ES index allocation; deferring aliasing", zap.Error(err))
		return bpf.EsPeerIndexBase + bpf.MaxEsPeersPerBd
	}
	for k := range peers {
		if k.BdId == bdID {
			used[k.Index] = struct{}{}
		}
	}
	for i := uint16(bpf.EsPeerIndexBase); i < bpf.EsPeerIndexBase+bpf.MaxEsPeersPerBd; i++ {
		if _, taken := used[i]; !taken {
			return i
		}
	}
	return bpf.EsPeerIndexBase + bpf.MaxEsPeersPerBd
}

// pickContrib selects a contribution of the shared {bd, MAC} data-plane
// key, deterministically (lowest {rd, etag}) so every caller converges on
// the same one regardless of map iteration order. Contributions for which
// skip returns true are not considered.
func (a *Applier) pickContrib(mk macDPKey, skip func(evpnFdbKey, evpnFdbState) bool) (evpnFdbKey, evpnFdbState, bool) {
	var (
		best   evpnFdbKey
		bestSt evpnFdbState
		found  bool
	)
	for fk := range a.evpn.macContribs[mk] {
		st, ok := a.evpn.fdb[fk]
		if !ok || skip(fk, st) {
			continue
		}
		if !found || fk.rd < best.rd || (fk.rd == best.rd && fk.etag < best.etag) {
			best, bestSt, found = fk, st, true
		}
	}
	return best, bestSt, found
}

// survivingContrib picks the contribution that re-installs a shared {bd,
// MAC} FDB entry after another contribution withdraws.
func (a *Applier) survivingContrib(mk macDPKey, withdrawn evpnFdbKey) (evpnFdbKey, evpnFdbState, bool) {
	return a.pickContrib(mk, func(fk evpnFdbKey, _ evpnFdbState) bool { return fk == withdrawn })
}

// fdbTargetIndex resolves where a contribution's FDB entry should point: the
// segment's ES peer when its {bd, ESI} is aliased, else the advertising PE's
// own bd_peer.
func (a *Applier) fdbTargetIndex(st evpnFdbState) (uint16, bool) {
	if d := a.evpn.esDests[esDestKey{bdID: st.bdID, esi: st.esi}]; d != nil && d.active {
		return d.peerIdx, true
	}
	ps, ok := a.evpn.peers[st.peer]
	if !ok {
		return 0, false
	}
	return ps.index, true
}

// forEachSegmentMac visits every fdb-ledger MAC learned on {bd, ESI},
// across all the PEs that taught it.
func (a *Applier) forEachSegmentMac(dk esDestKey, visit func(evpnFdbKey, evpnFdbState)) {
	for k, macs := range a.evpn.macsByES {
		if k.esi != dk.esi {
			continue
		}
		for fk := range macs {
			st, ok := a.evpn.fdb[fk]
			if !ok || st.bdID != dk.bdID {
				continue
			}
			visit(fk, st)
		}
	}
}
