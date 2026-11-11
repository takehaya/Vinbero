package apply

import (
	"fmt"
	"net/netip"
	"slices"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// Bounds on what one node will track and program. Tracking is deliberately
// wider than programming: the data plane picks 8 paths, but keeping the
// runners-up means a withdraw promotes one instead of leaving the prefix a
// path short until the next advertisement. Both are caps against a peer
// that floods paths, in the same spirit as maxTrackedESIs.
const (
	maxTrackedVPNDests = 4096
	maxPathsPerDest    = 32
)

// vpnDestKey is what paths aggregate onto: one ECMP group per {VRF, family,
// prefix}. The same prefix in two VRFs is two groups, so paths that two
// tenants import never mix. RD is NOT part of it. Each PE advertising a
// prefix uses its own RD, so keying by RD is what makes the second PE's path
// a separate entry that overwrites the first instead of joining it.
type vpnDestKey struct {
	vrf    uint32
	family bgp.Family
	prefix string
}

// vpnRouteKey identifies one received path whatever VRFs it is placed in.
// A withdraw carries no route targets, so the VRFs it has to leave are
// recorded against this key (vpnGroupTable.placed) when the path is placed.
type vpnRouteKey struct {
	family bgp.Family
	prefix string
	path   vpnPathKey
}

// dest is the destination the route has in vrfID.
func (rk vpnRouteKey) dest(vrfID uint32) vpnDestKey {
	return vpnDestKey{vrf: vrfID, family: rk.family, prefix: rk.prefix}
}

// vpnPathKey identifies one contributing path. RD distinguishes the PEs and
// PathSource distinguishes paths within a peer, so two PEs advertising one
// prefix, or one peer sending several paths under ADD-PATH, both land on
// distinct keys.
type vpnPathKey struct {
	rd     string
	source bgp.PathSource
}

// vpnPath is one path's contribution: the service SID to encapsulate to,
// and the SR Policy reference it holds (nil when the path is not steered).
// The reference lives here rather than in a separate reverse index because
// a withdraw carries no color or next hop, so the only way to release the
// right policy is to have recorded it against the path that took it.
type vpnPath struct {
	sid string
	// reduced marks a NEXT-C-SID service SID (the peer's SID Structure
	// was uSID-shaped): the encap uses H.Encaps.Red, which emits no SRH
	// for the single-SID case.
	reduced bool
	steer   *policyKey
	// nh is the advertising PE's BGP next hop, the destination the
	// liveness prober terminates this path's probe at.
	nh string
}

type vpnDest struct {
	groupID uint32
	paths   map[vpnPathKey]*vpnPath
	// installed is the member SID list last written, used to skip
	// reconciles that would rewrite an unchanged group.
	installed []string // groupFingerprint of the last write
	// src is the encapsulation source the group's members carry, set when
	// the group is written (hasSrc) and kept while the group may still be
	// in the data plane, including after a failed trigger write or a failed
	// retirement. While the source locator is missing a change to the group
	// is written with it, so the rewrite uses the source that is in the
	// data plane and the group never mixes two sources.
	src    [16]byte
	hasSrc bool
	// awaitingSource records that the group could not be written for lack
	// of the source locator and that this was logged, so a replay does not
	// log it again for every such prefix.
	awaitingSource bool
	// probed reports whether the prober currently holds a registration
	// that matches the group's actual data-plane layout. It turns false
	// when a group write fails (reconcile unregisters and the group is
	// fail-open over mixed-generation slots) and true again only after a
	// successful write + Register. reprobeSRPolicy keys on it: a non-nil
	// `installed` alone only says a write once succeeded, and re-imposing
	// a bitmap over a group whose last write failed would break fail-open.
	probed bool
}

// ecmpOps is the subset of bpf.MapOperations the VPN group path needs.
type ecmpOps interface {
	PutEcmpGroup(groupID uint32, paths []bpf.EcmpPath, owner bpf.OwnerTag) error
	DeleteEcmpGroup(groupID uint32, requester bpf.OwnerTag) error
	ListEcmpGroups() (map[uint32]*bpf.EcmpGroupInfo, error)
	ListEcmpGroupOwners() (map[uint32]bpf.OwnerTag, error)
}

// vpnGroupTable aggregates the paths learned for each VPN prefix into one
// ECMP group.
//
// Before this existed a prefix was written straight to the headend map
// keyed by prefix under an RD-scoped owner, so a second PE advertising the
// same prefix did not merely lose the race -- its write failed the
// cross-owner check and the path was dropped. Worse, once the first PE
// withdrew, the surviving PE's path was never retried, so the prefix went
// dark until something re-advertised it.
//
// All of it is touched from the single GoBGP RouteHandler goroutine, plus
// reset() before any route arrives, so it needs no lock of its own; the
// srPolicyTable it references is separately mutex-guarded for the
// concurrent RPC path.
type vpnGroupTable struct {
	dests map[vpnDestKey]*vpnDest
	// placed is, for each received path, the VRFs whose destination holds
	// it, in ascending order. stuck indexes the records kept only because
	// the path's removal from that destination failed: when the tracked
	// pass retires the destination, they are dropped with it.
	placed map[vpnRouteKey][]uint32
	stuck  map[vpnDestKey]map[vpnRouteKey]struct{}
	ecmp   ecmpOps
	logger *zap.Logger

	localASN uint32
	nextID   uint32
	freeIDs  []uint32
}

func newVPNGroupTable(ecmp ecmpOps, localASN uint32, logger *zap.Logger) *vpnGroupTable {
	return &vpnGroupTable{
		dests:    make(map[vpnDestKey]*vpnDest),
		placed:   make(map[vpnRouteKey][]uint32),
		stuck:    make(map[vpnDestKey]map[vpnRouteKey]struct{}),
		ecmp:     ecmp,
		logger:   logger.Named("vpngroup"),
		localASN: localASN,
	}
}

// setPlaced records the VRFs that hold rk's path.
func (t *vpnGroupTable) setPlaced(rk vpnRouteKey, vrfs []uint32) {
	if len(vrfs) == 0 {
		delete(t.placed, rk)
		return
	}
	t.placed[rk] = slices.Sorted(slices.Values(vrfs))
}

// stick records that rk stays placed in dk only to retry its removal.
func (t *vpnGroupTable) stick(dk vpnDestKey, rk vpnRouteKey) {
	if t.stuck[dk] == nil {
		t.stuck[dk] = map[vpnRouteKey]struct{}{}
	}
	t.stuck[dk][rk] = struct{}{}
}

// unstick forgets that: rk's removal from dk succeeded, or rk was placed
// in dk again.
func (t *vpnGroupTable) unstick(dk vpnDestKey, rk vpnRouteKey) {
	delete(t.stuck[dk], rk)
	if len(t.stuck[dk]) == 0 {
		delete(t.stuck, dk)
	}
}

// retired drops the records kept to retry a removal from dk, now that dk is
// gone.
func (t *vpnGroupTable) retired(dk vpnDestKey) {
	for rk := range t.stuck[dk] {
		t.setPlaced(rk, slices.DeleteFunc(slices.Clone(t.placed[rk]), func(v uint32) bool { return v == dk.vrf }))
	}
	delete(t.stuck, dk)
}

// groupOwner is the owner every group this table writes carries. It is
// shared by all prefixes on purpose (see OwnerBGPVPNGroup).
func (t *vpnGroupTable) groupOwner() bpf.OwnerTag {
	return bpf.OwnerBGPVPNGroup(t.localASN)
}

// reset clears state left by a previous process and seeds id allocation.
//
// ecmp_group_map and its owner table are pinned, so a restart finds the
// previous run's groups still installed. Their ids cannot be resumed: the
// owner tag deliberately does not name the prefix (it would overflow the
// tag buffer), so there is no way to tell which group belonged to which
// prefix. Delete the ones this node owns instead of leaving a new
// generation of orphans behind on every restart, and start allocating above
// whatever ids remain so a group owned by someone else -- an RPC-installed
// one, say -- is never overwritten.
//
// The pinned trigger entries keep forwarding meanwhile: each carries
// fallback segments, so a group that has just been deleted resolves to
// single-path forwarding rather than a drop, until BGP re-advertises and
// the group is rebuilt.
func (t *vpnGroupTable) reset() {
	owners, err := t.ecmp.ListEcmpGroupOwners()
	if err != nil {
		t.logger.Error("list ecmp group owners; stale groups may be left behind", zap.Error(err))
		owners = nil
	}
	mine := t.groupOwner()
	for id, owner := range owners {
		if owner != mine {
			continue
		}
		if err := t.ecmp.DeleteEcmpGroup(id, mine); err != nil {
			t.logger.Error("sweep stale ecmp group", zap.Uint32("group_id", id), zap.Error(err))
			continue
		}
		t.logger.Info("swept ecmp group left by a previous run", zap.Uint32("group_id", id))
	}

	groups, err := t.ecmp.ListEcmpGroups()
	if err != nil {
		t.logger.Error("list ecmp groups; id allocation may collide with surviving groups", zap.Error(err))
		return
	}
	for id := range groups {
		// The partition at esGroupIDBase belongs to the EVPN segment groups
		// (see evpn_alias.go); a survivor there must not drag this
		// allocator into it, or the two would collide on their next ids.
		if id >= esGroupIDBase {
			continue
		}
		if id > t.nextID {
			t.nextID = id
		}
	}
	if t.nextID > 0 {
		t.logger.Info("resuming ecmp group id allocation above surviving groups",
			zap.Uint32("highest_in_use", t.nextID))
	}
}

func (t *vpnGroupTable) allocID() (uint32, error) {
	if n := len(t.freeIDs); n > 0 {
		id := t.freeIDs[n-1]
		t.freeIDs = t.freeIDs[:n-1]
		return id, nil
	}
	if t.nextID+1 >= esGroupIDBase {
		// The ids at and above esGroupIDBase belong to the EVPN segment
		// groups; crossing over would collide with their allocator.
		return 0, fmt.Errorf("ecmp group id space exhausted")
	}
	t.nextID++
	return t.nextID, nil
}

// upsert records one path for a prefix and returns the destination to
// reconcile. ok is false when the path was refused by a bound.
func (t *vpnGroupTable) upsert(dk vpnDestKey, pk vpnPathKey, p *vpnPath) (*vpnDest, bool) {
	d, ok := t.dests[dk]
	if !ok {
		if len(t.dests) >= maxTrackedVPNDests {
			t.logger.Warn("VPN destination table full; dropping prefix",
				zap.Uint32("vrf_id", dk.vrf), zap.String("prefix", dk.prefix),
				zap.Int("limit", maxTrackedVPNDests))
			return nil, false
		}
		id, err := t.allocID()
		if err != nil {
			t.logger.Error("allocate ecmp group id",
				zap.Uint32("vrf_id", dk.vrf), zap.String("prefix", dk.prefix), zap.Error(err))
			return nil, false
		}
		d = &vpnDest{groupID: id, paths: make(map[vpnPathKey]*vpnPath)}
		t.dests[dk] = d
	}
	if _, exists := d.paths[pk]; !exists && len(d.paths) >= maxPathsPerDest {
		t.logger.Warn("path table full for prefix; dropping path",
			zap.Uint32("vrf_id", dk.vrf), zap.String("prefix", dk.prefix), zap.String("source", pk.source.String()),
			zap.Int("limit", maxPathsPerDest))
		return nil, false
	}
	d.paths[pk] = p
	return d, true
}

// remove drops one path. It returns the destination when one still exists,
// along with the steering reference the removed path held so the caller can
// release it.
func (t *vpnGroupTable) remove(dk vpnDestKey, pk vpnPathKey) (*vpnDest, *policyKey) {
	d, ok := t.dests[dk]
	if !ok {
		return nil, nil
	}
	old := d.paths[pk]
	delete(d.paths, pk)
	var released *policyKey
	if old != nil {
		released = old.steer
	}
	return d, released
}

func (d *vpnDest) members() []*vpnPath {
	return selectVPNMembers(d.paths)
}

// reconcileVPNGroup writes the destination's current member set to the data
// plane: the ECMP group holding one headend entry per member, and the
// trigger entry the dispatcher matches on.
//
// The trigger carries the first member's segments as well as the group id.
// The data plane falls back to a trigger's own segments when a group cannot
// be resolved, so this turns the two windows where that happens -- a
// reconcile mid-update, and the gap after a restart sweeps the old groups
// -- into single-path forwarding instead of a drop.
//
// It reports false when a data-plane write failed, which a later reconcile
// can fix; a group waiting for the source locator, or one whose entries
// cannot be built at all, reports true.
func (a *Applier) reconcileVPNGroup(dk vpnDestKey, d *vpnDest) bool {
	ms := d.members()
	if len(ms) == 0 {
		return a.retireVPNGroup(dk, d)
	}
	// One source for the whole write, so the fingerprint records the
	// source the entries actually carry.
	src, err := a.encapSource()
	switch {
	case err == nil:
	case d.hasSrc:
		// Without the source locator a group in the data plane keeps the
		// source it has (deleting the locator logs that once), and a
		// change to it is written with that source: a withdrawn path must
		// not stay in the group until the locator is back. That holds for a
		// group whose last trigger write or retirement failed too.
		src = d.src
	default:
		// One never written waits, logged once, and ReconcileTracked writes
		// it when the locator is back.
		if !d.awaitingSource {
			d.awaitingSource = true
			a.logger.Warn("VPN prefix not installed until the source locator is registered",
				zap.Uint32("vrf_id", dk.vrf), zap.String("prefix", dk.prefix), zap.Error(err))
		}
		return true
	}
	d.awaitingSource = false
	fingerprint := groupFingerprint(ms, src)
	// Unchanged only if the prober also still holds the group: a failed
	// write or an SR Policy change it could not follow unregisters it, and
	// only a rewrite registers it again.
	if slices.Equal(fingerprint, d.installed) && d.probed {
		return true
	}

	// Resolve each member's steering id before building anything: the id is
	// stamped into the member's own encap entry, so paths steered onto
	// different SR Policies stay steered after aggregation.
	paths := make([]bpf.EcmpPath, 0, len(ms))
	for _, m := range ms {
		entry, err := buildHeadendEntryFrom(src, m.sid, m.reduced)
		if err != nil {
			a.logger.Error("build ECMP member",
				zap.Uint32("vrf_id", dk.vrf), zap.String("prefix", dk.prefix), zap.String("sid", m.sid), zap.Error(err))
			return true
		}
		if m.steer != nil {
			entry.PolicyId = a.srPolicy.idOf(m.steer.color, m.steer.endpoint)
		}
		// Equal weights: BGP multipath has no notion of relative capacity,
		// so every path carries the same share until something (a weighted
		// SR Policy, a prober) says otherwise.
		paths = append(paths, bpf.EcmpPath{Entry: entry, Weight: 1})
	}
	owner := a.vpnGroups.groupOwner()
	if err := a.vpnGroups.ecmp.PutEcmpGroup(d.groupID, paths, owner); err != nil {
		a.logger.Error("install ECMP group",
			zap.Uint32("vrf_id", dk.vrf), zap.String("prefix", dk.prefix), zap.Uint32("group_id", d.groupID), zap.Error(err))
		// A failed replace can leave mixed-generation path slots behind (the
		// bpf layer does not roll back). The prober's registration -- and any
		// bitmap it wrote -- describes the OLD layout; over mixed slots its
		// bit positions mask the wrong members. Unregister drops the bitmap
		// and returns the group to fail-open until a retry rebuilds it.
		a.prober.Unregister(d.groupID)
		d.probed = false
		return a.vpnFailed()
	}
	// Registered immediately after the group write: PutEcmpGroup resets the
	// liveness bitmap (bit positions refer to the new member set), and this
	// Register -- with per-target state carried over -- is what re-imposes
	// the known down-states, so the fail-open window is these few
	// statements, not a probe interval.
	dsts := make([]string, len(ms))
	for i, m := range ms {
		dsts[i] = m.nh
	}
	a.prober.Register(d.groupID, a.probeTargets(paths, dsts))
	d.probed = true
	d.src, d.hasSrc = src, true

	// The trigger mirrors the first member so the fallback forwards the same
	// way the group's first path would, steering included.
	trigger, err := buildHeadendEntryFrom(src, ms[0].sid, ms[0].reduced)
	if err != nil {
		a.logger.Error("build ECMP trigger",
			zap.Uint32("vrf_id", dk.vrf), zap.String("prefix", dk.prefix), zap.Error(err))
		return true
	}
	if ms[0].steer != nil {
		trigger.PolicyId = a.srPolicy.idOf(ms[0].steer.color, ms[0].steer.endpoint)
	}
	trigger.GroupId = d.groupID
	if err := a.createTrigger(dk.vrf, dk.family, dk.prefix, trigger); err != nil {
		a.logger.Error("install ECMP trigger",
			zap.Uint32("vrf_id", dk.vrf), zap.String("prefix", dk.prefix), zap.Error(err))
		return a.vpnFailed()
	}
	d.installed = fingerprint
	a.logger.Info("VPN prefix programmed",
		zap.Uint32("vrf_id", dk.vrf), zap.String("prefix", dk.prefix), zap.Int("paths", len(ms)),
		zap.Uint32("group_id", d.groupID))
	return true
}

// groupFingerprint is what reconcileVPNGroup records as installed: the
// member set, plus the encapsulation source src every entry was written
// with. With the source in it, a source locator re-registered under another
// prefix rewrites each group on the next reconcile instead of matching the
// old write and keeping the stale source.
func groupFingerprint(ms []*vpnPath, src [16]byte) []string {
	return append(memberFingerprint(ms), "src="+netip.AddrFrom16(src).String())
}

// ReconcileTracked writes again every VPN prefix and MUP session the
// applier tracks whose data plane does not match it, and leaves the others
// alone. A route received while the source locator was missing is tracked
// but not written, and nothing else would deliver it again; one written
// earlier takes the locator's new prefix if it changed, and so do the EVPN
// peers and aliasing groups (an EVPN route that could not be written is not
// tracked, so the caller replays the EVPN loc-rib for those); a write or
// removal that failed is retried. Without the source locator the work that
// needs no source still runs: removals, dissolves, GTP4-embed downlinks and
// membership changes of entries already written (with the source they
// carry). It returns a *TrackedWriteError when some write still failed, so
// the caller can run it again later. Safe to call from RPC goroutines.
func (a *Applier) ReconcileTracked() error {
	var vpnFailed, mupFailed, evpnFailed int
	a.vpnMu.Lock()
	release := a.vrfBindings.VRF().HoldIDs()
	for dk, d := range a.vpnGroups.dests {
		if !a.reconcileVPNGroup(dk, d) {
			vpnFailed++
		}
	}
	// Reported by the return value; nothing for flushTrackedFailure.
	a.vpnWriteFailed = false
	release()
	a.vpnMu.Unlock()

	a.mupMu.Lock()
	release = a.vrfBindings.VRF().HoldIDs()
	mupFailed += a.retryMUPT1STStale() + a.payMUPGateDebt()
	for k := range a.mupT1ST {
		if !a.reconcileMUPT1ST(k) {
			mupFailed++
		}
	}
	for k := range a.mupT2ST {
		if !a.reconcileMUPT2ST(k) {
			mupFailed++
		}
	}
	a.mupWriteFailed = false
	release()
	a.mupMu.Unlock()

	a.evpnMu.Lock()
	evpnFailed = a.reconcileEVPNSource()
	a.evpn.writeFailed = false
	a.evpnMu.Unlock()
	if vpnFailed+mupFailed+evpnFailed > 0 {
		return &TrackedWriteError{VPN: vpnFailed, MUP: mupFailed, EVPN: evpnFailed}
	}
	return nil
}

// retireVPNGroup tears down a destination whose last path went away and
// returns its group id for reuse. It reports false when a delete failed.
func (a *Applier) retireVPNGroup(dk vpnDestKey, d *vpnDest) bool {
	owner := a.vpnGroups.groupOwner()
	// A failed retirement can remove the trigger or part of the group. An
	// unchanged re-advertisement must rebuild both instead of taking the
	// installed-fingerprint shortcut over that partially removed state.
	d.installed = nil
	if err := a.deleteTrigger(dk.vrf, dk.family, dk.prefix); err != nil {
		a.logger.Error("withdraw VPN trigger",
			zap.Uint32("vrf_id", dk.vrf), zap.String("prefix", dk.prefix), zap.Error(err))
		// The old trigger still may reference this ID. Keep the group and
		// its tracking until a later withdrawal or replacement can retry;
		// reusing its ID for another prefix would redirect the old traffic.
		return a.vpnFailed()
	}
	// The trigger goes first: while the group still exists a stale trigger
	// forwards correctly, whereas deleting the group first would leave the
	// trigger resolving to its fallback segments for no reason. The prober
	// registration outlives the group delete attempt: if the delete fails
	// the group keeps forwarding, and it should keep its liveness guard.
	if err := a.vpnGroups.ecmp.DeleteEcmpGroup(d.groupID, owner); err != nil {
		a.logger.Error("delete ECMP group",
			zap.Uint32("vrf_id", dk.vrf), zap.String("prefix", dk.prefix), zap.Uint32("group_id", d.groupID), zap.Error(err))
		return a.vpnFailed()
	}
	a.prober.Unregister(d.groupID)
	delete(a.vpnGroups.dests, dk)
	a.vpnGroups.retired(dk)
	a.vpnGroups.freeIDs = append(a.vpnGroups.freeIDs, d.groupID)
	a.logger.Info("VPN prefix withdrawn",
		zap.Uint32("vrf_id", dk.vrf), zap.String("prefix", dk.prefix), zap.Uint32("group_id", d.groupID))
	return true
}

// createTrigger writes the trigger entry of vrfID.
func (a *Applier) createTrigger(vrfID uint32, fam bgp.Family, prefix string, entry *bpf.HeadendEntry) error {
	return a.createHeadend(vrfID, fam, prefix, entry, bpf.OwnerBGPVPN(a.localASN, ""))
}

// deleteTrigger removes the trigger entry of vrfID.
func (a *Applier) deleteTrigger(vrfID uint32, fam bgp.Family, prefix string) error {
	return a.deleteHeadend(vrfID, fam, prefix, bpf.OwnerBGPVPN(a.localASN, ""))
}
