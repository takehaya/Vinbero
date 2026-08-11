package apply

import (
	"cmp"
	"errors"
	"fmt"
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

// vpnDestKey is what paths aggregate onto: one ECMP group per {family,
// prefix}. RD is NOT part of it. Each PE advertising a prefix uses its own
// RD, so keying by RD is what makes the second PE's path a separate entry
// that overwrites the first instead of joining it.
type vpnDestKey struct {
	family bgp.Family
	prefix string
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
	sid   string
	steer *policyKey
}

type vpnDest struct {
	groupID uint32
	paths   map[vpnPathKey]*vpnPath
	// installed is the member SID list last written, used to skip
	// reconciles that would rewrite an unchanged group.
	installed []string // memberFingerprint of the last write
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
	dests  map[vpnDestKey]*vpnDest
	ecmp   ecmpOps
	logger *zap.Logger

	localASN uint32
	nextID   uint32
	freeIDs  []uint32
}

func newVPNGroupTable(ecmp ecmpOps, localASN uint32, logger *zap.Logger) *vpnGroupTable {
	return &vpnGroupTable{
		dests:    make(map[vpnDestKey]*vpnDest),
		ecmp:     ecmp,
		logger:   logger.Named("vpngroup"),
		localASN: localASN,
	}
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
				zap.String("prefix", dk.prefix), zap.Int("limit", maxTrackedVPNDests))
			return nil, false
		}
		id, err := t.allocID()
		if err != nil {
			t.logger.Error("allocate ecmp group id",
				zap.String("prefix", dk.prefix), zap.Error(err))
			return nil, false
		}
		d = &vpnDest{groupID: id, paths: make(map[vpnPathKey]*vpnPath)}
		t.dests[dk] = d
	}
	if _, exists := d.paths[pk]; !exists && len(d.paths) >= maxPathsPerDest {
		t.logger.Warn("path table full for prefix; dropping path",
			zap.String("prefix", dk.prefix), zap.String("source", pk.source.String()),
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

// members picks the paths to program, in a deterministic order.
//
// Sorting matters beyond tidiness: the data plane selects by hash modulo
// the member list, so if the order depended on Go's map iteration the same
// set of paths would spread flows differently on every reconcile and every
// restart. Sorting by SID pins it.
//
// Two paths that resolve to the same SID are the same forwarding outcome
// (typically one PE re-advertised under a second RD), so they are deduped:
// programming both would silently double that PE's share of the traffic.
func (d *vpnDest) members() []*vpnPath {
	type keyed struct {
		key vpnPathKey
		p   *vpnPath
	}
	all := make([]keyed, 0, len(d.paths))
	for k, p := range d.paths {
		all = append(all, keyed{k, p})
	}
	// SID orders the members, but SortFunc is not stable and two paths can
	// share a SID, so the key breaks the tie. Without it the survivor of the
	// dedupe below would depend on map iteration order -- and since the paths
	// sharing a SID can carry different colors, the programmed policy id
	// would flip between reconciles and defeat the unchanged-set skip.
	slices.SortFunc(all, func(a, b keyed) int {
		if c := cmp.Compare(a.p.sid, b.p.sid); c != 0 {
			return c
		}
		if c := cmp.Compare(a.key.rd, b.key.rd); c != 0 {
			return c
		}
		if c := cmp.Compare(a.key.source.Peer.String(), b.key.source.Peer.String()); c != 0 {
			return c
		}
		return cmp.Compare(a.key.source.PathID, b.key.source.PathID)
	})
	out := make([]*vpnPath, 0, len(all))
	for _, k := range all {
		out = append(out, k.p)
	}
	out = slices.CompactFunc(out, func(a, b *vpnPath) bool { return a.sid == b.sid })
	if len(out) > bpf.EcmpMaxPaths {
		out = out[:bpf.EcmpMaxPaths]
	}
	return out
}

// memberFingerprint renders the programmed member set so an unchanged
// reconcile can be skipped. The steering target is part of it: a path whose
// color changed keeps its SID but must be rewritten with a new policy id.
func memberFingerprint(ms []*vpnPath) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		if m.steer == nil {
			out[i] = m.sid
			continue
		}
		out[i] = fmt.Sprintf("%s@%d/%s", m.sid, m.steer.color, m.steer.endpoint)
	}
	return out
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
func (a *Applier) reconcileVPNGroup(dk vpnDestKey, d *vpnDest) {
	ms := d.members()
	if len(ms) == 0 {
		a.retireVPNGroup(dk, d)
		return
	}
	fingerprint := memberFingerprint(ms)
	if slices.Equal(fingerprint, d.installed) {
		return
	}

	// Resolve each member's steering id before building anything: the id is
	// stamped into the member's own encap entry, so paths steered onto
	// different SR Policies stay steered after aggregation.
	paths := make([]bpf.EcmpPath, 0, len(ms))
	for _, m := range ms {
		entry, err := a.buildHeadendEntry(m.sid)
		if err != nil {
			a.logger.Error("build ECMP member",
				zap.String("prefix", dk.prefix), zap.String("sid", m.sid), zap.Error(err))
			return
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
			zap.String("prefix", dk.prefix), zap.Uint32("group_id", d.groupID), zap.Error(err))
		return
	}

	// The trigger mirrors the first member so the fallback forwards the same
	// way the group's first path would, steering included.
	trigger, err := a.buildHeadendEntry(ms[0].sid)
	if err != nil {
		a.logger.Error("build ECMP trigger",
			zap.String("prefix", dk.prefix), zap.Error(err))
		return
	}
	if ms[0].steer != nil {
		trigger.PolicyId = a.srPolicy.idOf(ms[0].steer.color, ms[0].steer.endpoint)
	}
	trigger.GroupId = d.groupID
	if err := a.createTrigger(dk.family, dk.prefix, trigger); err != nil {
		a.logger.Error("install ECMP trigger",
			zap.String("prefix", dk.prefix), zap.Error(err))
		return
	}
	d.installed = fingerprint
	a.logger.Info("VPN prefix programmed",
		zap.String("prefix", dk.prefix), zap.Int("paths", len(ms)),
		zap.Uint32("group_id", d.groupID))
}

// retireVPNGroup tears down a destination whose last path went away and
// returns its group id for reuse.
func (a *Applier) retireVPNGroup(dk vpnDestKey, d *vpnDest) {
	owner := a.vpnGroups.groupOwner()
	if err := a.deleteTrigger(dk.family, dk.prefix); err != nil {
		a.logger.Error("withdraw VPN trigger",
			zap.String("prefix", dk.prefix), zap.Error(err))
	}
	// The trigger goes first: while the group still exists a stale trigger
	// forwards correctly, whereas deleting the group first would leave the
	// trigger resolving to its fallback segments for no reason.
	if err := a.vpnGroups.ecmp.DeleteEcmpGroup(d.groupID, owner); err != nil {
		a.logger.Error("delete ECMP group",
			zap.String("prefix", dk.prefix), zap.Uint32("group_id", d.groupID), zap.Error(err))
		return
	}
	delete(a.vpnGroups.dests, dk)
	a.vpnGroups.freeIDs = append(a.vpnGroups.freeIDs, d.groupID)
	a.logger.Info("VPN prefix withdrawn",
		zap.String("prefix", dk.prefix), zap.Uint32("group_id", d.groupID))
}

// clearLegacyVPNHeadend removes a trigger left by the pre-aggregation
// writer, which owned each prefix per RD.
//
// Those entries survive in the pinned headend maps across an upgrade, and
// the aggregating writer's owner is RD-independent, so without this every
// previously installed prefix fails the cross-owner check and never comes
// back -- and a withdraw arriving for one cannot remove it either.
//
// The owner is read first and force-deleted only when it is this node's own
// legacy shape. An unconditional force would also destroy an entry an
// operator installed for the same prefix over RPC.
//
// Reports whether anything was cleared, so the caller knows a retry is
// worth attempting.
func (a *Applier) clearLegacyVPNHeadend(fam bgp.Family, prefix string) bool {
	var (
		owner bpf.OwnerTag
		found bool
		err   error
	)
	switch fam {
	case bgp.FamilyVPNv4:
		owner, found, err = a.headend.GetHeadendV4Owner(prefix)
	case bgp.FamilyVPNv6:
		owner, found, err = a.headend.GetHeadendV6Owner(prefix)
	default:
		return false
	}
	if err != nil || !found || !bpf.IsLegacyBGPVPNOwner(a.localASN, owner) {
		return false
	}
	switch fam {
	case bgp.FamilyVPNv4:
		err = a.headend.ForceDeleteHeadendV4(prefix)
	case bgp.FamilyVPNv6:
		err = a.headend.ForceDeleteHeadendV6(prefix)
	}
	if err != nil {
		a.logger.Error("clear pre-aggregation VPN trigger",
			zap.String("prefix", prefix), zap.String("owner", string(owner)), zap.Error(err))
		return false
	}
	a.logger.Info("cleared pre-aggregation VPN trigger",
		zap.String("prefix", prefix), zap.String("owner", string(owner)))
	return true
}

// createTrigger writes the trigger entry, migrating off a pre-aggregation
// owner if one is in the way.
func (a *Applier) createTrigger(fam bgp.Family, prefix string, entry *bpf.HeadendEntry) error {
	owner := bpf.OwnerBGPVPN(a.localASN, "")
	err := a.createHeadend(fam, prefix, entry, owner)
	if !errors.Is(err, bpf.ErrEntryOwnerMismatch) {
		return err
	}
	if !a.clearLegacyVPNHeadend(fam, prefix) {
		return err
	}
	return a.createHeadend(fam, prefix, entry, owner)
}

// deleteTrigger removes the trigger entry, including one left by the
// pre-aggregation writer.
func (a *Applier) deleteTrigger(fam bgp.Family, prefix string) error {
	err := a.deleteHeadend(fam, prefix, bpf.OwnerBGPVPN(a.localASN, ""))
	if !errors.Is(err, bpf.ErrEntryOwnerMismatch) {
		return err
	}
	if a.clearLegacyVPNHeadend(fam, prefix) {
		return nil
	}
	return err
}
