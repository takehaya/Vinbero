package bpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	MaxSegments    = 10
	IPv4AddrLen    = 4
	IPv6AddrLen    = 16
	MaxBumNexthops = 8 // Must match MAX_BUM_NEXTHOPS in xdp_prog.h
)

// Type aliases for BPF generated types
type (
	LpmKeyV4         = BpfLpmKeyV4
	LpmKeyV6         = BpfLpmKeyV6
	HeadendL2Key     = BpfHeadendL2Key
	SidFunctionEntry = BpfSidFunctionEntry
	SidAuxEntry      = BpfSidAuxEntry
	HeadendEntry     = BpfHeadendEntry
	FdbKey           = BpfFdbKey
	FdbEntry         = BpfFdbEntry
	BdPeerKey        = BpfBdPeerKey
	BdPeerReverseKey = BpfBdPeerReverseKey
	BdPeerReverseVal = BpfBdPeerReverseVal
	Dx2vKey          = BpfDx2vKey
	Dx2vEntry        = BpfDx2vEntry
	EsiKey           = BpfEsiKey
	EsiEntry         = BpfEsiEntry
	MupUplinkV4Key   = BpfMupUplinkV4Key
	MupUplinkV6Key   = BpfMupUplinkV6Key
)

// MupArgsOffsetNone is the headend_entry.args_offset sentinel meaning "do not
// patch Args.Mob.Session" on the F-TEID uplink path (mirrors
// MUP_ARGS_OFFSET_NONE in src/core/xdp_prog.h). A plain direct (End.DT4) SID
// uses it so the TEID stays a lookup key only; a real offset (0..7) re-enables
// Args.Mob.Session patching for the End.M.GTP4.E-to-UPF variant.
const MupArgsOffsetNone uint8 = 0xFF

// ESILen is the fixed length of RFC 7432 Ethernet Segment Identifier.
const ESILen = 10

// MapOperator interface for testability
type MapOperator interface {
	Put(key, value any) error
	Delete(key any) error
	Lookup(key, valueOut any) error
	Iterate() *ebpf.MapIterator
}

// MapOperations provides operations for BPF maps
type MapOperations struct {
	objs     *BpfObjects
	auxAlloc *indexAllocator
	// Per-entry owner tracking for the main LPM maps. Paired HASH maps
	// (key matches the corresponding main map) record the OwnerTag that
	// wrote each entry; Create/Delete/Flush consult them to detect cross-
	// owner mutation. Nil when the BPF handle is unavailable (e.g. test
	// fixtures that load a subset of the program), in which case all
	// owner checks short-circuit to "no recorded owner".
	sidFunctionOwners *entryOwnerMap
	headendV4Owners   *entryOwnerMap
	headendV6Owners   *entryOwnerMap
}

// NewMapOperations creates a new MapOperations instance.
// The aux index allocator capacity is derived from the actual sid_aux_map MaxEntries.
// When the BPF AuxOwnerMap is available it is wired into the allocator so
// owner tags persist across daemon restarts via aux_owner_map; a nil
// AuxOwnerMap leaves the allocator in-memory-only.
func NewMapOperations(objs *BpfObjects) *MapOperations {
	auxMax := uint32(512) // fallback
	if info, err := objs.SidAuxMap.Info(); err == nil {
		auxMax = info.MaxEntries
	}
	alloc := newIndexAllocator(auxMax)
	alloc.ownerMap = newAuxOwnerMap(objs.AuxOwnerMap)
	return &MapOperations{
		objs:              objs,
		auxAlloc:          alloc,
		sidFunctionOwners: newEntryOwnerMap(objs.SidFunctionOwnerMap),
		headendV4Owners:   newEntryOwnerMap(objs.HeadendV4OwnerMap),
		headendV6Owners:   newEntryOwnerMap(objs.HeadendV6OwnerMap),
	}
}

// checkEntryOwner validates that caller is allowed to write or delete the
// entry at key. It rejects an empty caller (which would silently match the
// "no recorded owner" sentinel) and surfaces ErrEntryOwnerMismatch for
// cross-owner attempts. alreadyOwned=true means the entry is already
// owned by caller and Create can skip re-writing the owner map. A nil
// owners argument means owner tracking is disabled for this handle, so
// the call is allowed but always reports "fresh ownership" (caller must
// still write the owner map -- it just becomes a no-op).
func checkEntryOwner(owners *entryOwnerMap, key any, caller OwnerTag) (alreadyOwned bool, err error) {
	if caller == "" {
		return false, ErrEmptyOwner
	}
	if owners == nil {
		return false, nil
	}
	existing, ok, lookupErr := owners.Lookup(key)
	if lookupErr != nil {
		return false, fmt.Errorf("lookup entry owner: %w", lookupErr)
	}
	if !ok {
		return false, nil
	}
	if existing == caller {
		return true, nil
	}
	return false, fmt.Errorf("%w: existing %q, caller %q", ErrEntryOwnerMismatch, existing, caller)
}

// deleteMapKey removes key from m, treating a missing key as success so
// callers can delete idempotently. A double withdraw or a delete
// replayed after a restart must not surface as an error.
func deleteMapKey(m *ebpf.Map, key any) error {
	if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// putMainAndOwner writes value to the main map and, when not already
// owned, mirrors the owner to the paired owner map. A failure on the
// owner write rolls the main write back so the invariant "main entry =>
// owner entry (or alreadyOwned)" holds. cleanup runs only when the
// rollback is taken; pass nil if there is no extra teardown.
func putMainAndOwner[K, V any](
	main *ebpf.Map,
	owners *entryOwnerMap,
	key K,
	value *V,
	owner OwnerTag,
	alreadyOwned bool,
	label string,
	cleanup func(),
) error {
	if err := main.Put(key, value); err != nil {
		if cleanup != nil {
			cleanup()
		}
		return fmt.Errorf("failed to put %s entry: %w", label, err)
	}
	if alreadyOwned {
		return nil
	}
	if err := owners.Put(key, owner); err != nil {
		_ = main.Delete(key)
		if cleanup != nil {
			cleanup()
		}
		return fmt.Errorf("failed to put %s owner: %w", label, err)
	}
	return nil
}

// AuxOwnerVersion is bumped when the owner tag format changes. Tags
// written by older versions are accepted by ParseAuxOwnerTag for forward
// migration; tags newly minted by AuxOwnerPluginTag / AuxOwnerBuiltin use
// the current version.
const AuxOwnerVersion = "v1"

// AuxOwnerBuiltin tags aux indices that belong to vinbero-managed SID
// behaviors (End.X / End.DT2 / End.B6 / etc.). Plugin-owned indices use
// AuxOwnerPluginTag with (mapType, slot). The same string is used for
// in-memory comparisons and for persistence in aux_owner_map.
const AuxOwnerBuiltin = "builtin:" + AuxOwnerVersion

// AuxOwnerPluginTag returns the persisted plugin owner tag. Format is
// "plugin:<version>:<mapType>:<slot>". ParseAuxOwnerTag also accepts the
// unversioned legacy form "plugin:<mapType>:<slot>" so older pins
// remain readable.
func AuxOwnerPluginTag(mapType string, slot uint32) string {
	return fmt.Sprintf("plugin:%s:%s:%d", AuxOwnerVersion, mapType, slot)
}

// AuxOwnerKind values returned by ParseAuxOwnerTag.
const (
	AuxOwnerKindBuiltin = "builtin"
	AuxOwnerKindPlugin  = "plugin"
)

// ParseAuxOwnerTag splits a persisted tag into its components. Accepts
// both the legacy ("plugin:endpoint:32" / "builtin") form and the
// version-stamped ("plugin:v1:endpoint:32" / "builtin:v1") form so
// reading an older pin is loss-less. The parsed result always carries
// the current version semantics -- callers that re-persist a parsed tag
// should re-render via AuxOwnerPluginTag / AuxOwnerBuiltin.
//
// Returns:
//   - kind: "builtin" or "plugin"
//   - mapType: the owning plugin map type (empty for builtin)
//   - slot: the plugin PROG_ARRAY slot (zero for builtin)
//   - err: non-nil if the tag does not match a recognized layout
func ParseAuxOwnerTag(tag string) (kind, mapType string, slot uint32, err error) {
	if tag == "" {
		return "", "", 0, fmt.Errorf("empty owner tag")
	}
	parts := strings.Split(tag, ":")
	switch parts[0] {
	case AuxOwnerKindBuiltin:
		// Accept both "builtin" (legacy) and "builtin:v1" (versioned).
		if len(parts) == 1 {
			return AuxOwnerKindBuiltin, "", 0, nil
		}
		if len(parts) == 2 && strings.HasPrefix(parts[1], "v") {
			return AuxOwnerKindBuiltin, "", 0, nil
		}
		return "", "", 0, fmt.Errorf("malformed builtin owner tag %q", tag)
	case AuxOwnerKindPlugin:
		// Versioned form: plugin:v1:<mapType>:<slot> -> 4 segments.
		// Legacy form:    plugin:<mapType>:<slot>    -> 3 segments.
		var mt, slotStr string
		switch len(parts) {
		case 4:
			if !strings.HasPrefix(parts[1], "v") {
				return "", "", 0, fmt.Errorf("malformed plugin owner tag %q (expected version prefix)", tag)
			}
			mt = parts[2]
			slotStr = parts[3]
		case 3:
			mt = parts[1]
			slotStr = parts[2]
		default:
			return "", "", 0, fmt.Errorf("malformed plugin owner tag %q", tag)
		}
		n, perr := strconv.ParseUint(slotStr, 10, 32)
		if perr != nil {
			return "", "", 0, fmt.Errorf("plugin owner tag %q: bad slot: %w", tag, perr)
		}
		return AuxOwnerKindPlugin, mt, uint32(n), nil
	default:
		return "", "", 0, fmt.Errorf("unknown owner tag scheme %q", tag)
	}
}

// ErrOwnerMismatch is returned when FreeOwner / PutPluginAux / GetPluginAux
// / FreePluginAux are called with an owner tag that does not match the tag
// recorded at Alloc time. Guards against a plugin freeing another plugin's
// aux index or a builtin path accidentally stepping on plugin state.
var ErrOwnerMismatch = errors.New("aux owner mismatch")

// ErrAuxPayloadTooLarge is returned by PutPluginAux when the caller's raw
// payload exceeds SidAuxPluginRawMax. Surfaced as a sentinel so the RPC
// layer can map this caller-side mistake to InvalidArgument instead of the
// generic Internal that other write failures use.
var ErrAuxPayloadTooLarge = errors.New("plugin aux payload exceeds SidAuxPluginRawMax")

// auxOwnerMap is the persistence backing for indexAllocator.owners.
// A nil receiver means pinning is disabled (or AuxOwnerMap was never
// loaded); Put/Delete become no-ops in that case so the allocator
// falls back to in-memory-only behavior.
type auxOwnerMap struct {
	m *ebpf.Map
}

// auxOwnerTagBytes is the wire size of struct aux_owner.tag in
// src/core/srv6.h. ARRAY map values are fixed-width, so the userspace
// side mirrors the C layout exactly.
const auxOwnerTagBytes = 64

// newAuxOwnerMap wraps an ebpf.Map for aux_owner_map persistence. Returns
// nil when m is nil so callers can pass through "pinning disabled" without
// an extra branch.
func newAuxOwnerMap(m *ebpf.Map) *auxOwnerMap {
	if m == nil {
		return nil
	}
	return &auxOwnerMap{m: m}
}

// Put writes tag to aux_owner_map[idx]. AuxOwnerPluginTag fits well
// within the 63-byte limit; longer format changes would be truncated by
// encodeOwnerTag.
func (a *auxOwnerMap) Put(idx uint32, tag string) error {
	if a == nil {
		return nil
	}
	v := encodeOwnerTag(tag)
	return a.m.Put(idx, v)
}

// Delete clears aux_owner_map[idx]. ARRAY maps have no real Delete, so we
// zero-write the slot; subsequent Iterate calls treat zero entries as
// "unused".
func (a *auxOwnerMap) Delete(idx uint32) error {
	if a == nil {
		return nil
	}
	var zero [auxOwnerTagBytes]byte
	return a.m.Put(idx, zero)
}

// Iterate returns every non-empty (idx, tag) pair currently in
// aux_owner_map. Index 0 is the "no aux" sentinel and is never returned.
// Zero-valued slots (fresh load or post-Delete) are skipped so the
// allocator does not re-populate them with empty owners.
func (a *auxOwnerMap) Iterate() (map[uint32]string, error) {
	out := make(map[uint32]string)
	if a == nil {
		return out, nil
	}
	var idx uint32
	var v [auxOwnerTagBytes]byte
	iter := a.m.Iterate()
	for iter.Next(&idx, &v) {
		if idx == 0 {
			continue
		}
		if s, ok := decodeOwnerTag(v[:]); ok {
			out[idx] = s
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate aux_owner_map: %w", err)
	}
	return out, nil
}

// indexAllocator manages a pool of uint32 indices with a free-list and an
// owner tag per live index. Index 0 is reserved as the "no aux" sentinel
// used by sid_function_entry.
type indexAllocator struct {
	mu       sync.Mutex
	freeList []uint32
	maxIndex uint32
	nextNew  uint32
	owners   map[uint32]string
	// ownerMap is the optional BPF-side persistence of owners. When non-nil,
	// AllocOwner / freeOwnerLocked mirror their in-memory updates here so
	// owner identity survives daemon restart. Nil means in-memory-only
	// — typically because pin_maps is disabled or the aux_owner_map
	// handle is not available.
	ownerMap *auxOwnerMap
}

func newIndexAllocator(max uint32) *indexAllocator {
	// sid_function_entry.aux_index is uint16 on the BPF side, so any index
	// above math.MaxUint16 would silently truncate when stored. Clamp the
	// allocator capacity to keep the storable range as a hard ceiling
	// regardless of operator-configured sid_aux_map capacity.
	if max > math.MaxUint16+1 {
		max = math.MaxUint16 + 1
	}
	return &indexAllocator{
		maxIndex: max,
		nextNew:  1,
		owners:   make(map[uint32]string),
	}
}

// allocLocked is the core allocation primitive; callers must hold a.mu.
func (a *indexAllocator) allocLocked() (uint32, error) {
	if len(a.freeList) > 0 {
		idx := a.freeList[len(a.freeList)-1]
		a.freeList = a.freeList[:len(a.freeList)-1]
		return idx, nil
	}
	if a.nextNew >= a.maxIndex {
		return 0, fmt.Errorf("aux index pool exhausted (max %d)", a.maxIndex)
	}
	idx := a.nextNew
	a.nextNew++
	return idx, nil
}

// AllocOwner hands out the next free aux index and records owner as the
// allocator of that index. owner must be non-empty; use AuxOwnerBuiltin
// for vinbero-managed allocations and AuxOwnerPluginTag for plugin ones.
//
// When ownerMap is non-nil the persisted tag is also written to
// aux_owner_map[idx] before returning. A failed write rolls the idx back
// to the free list so the allocator state matches the on-disk pin --
// otherwise an in-memory entry could outlive a restart with no
// corresponding pin record.
func (a *indexAllocator) AllocOwner(owner string) (uint32, error) {
	if owner == "" {
		return 0, fmt.Errorf("aux owner tag must be non-empty")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	idx, err := a.allocLocked()
	if err != nil {
		return 0, err
	}
	if err := a.ownerMap.Put(idx, owner); err != nil {
		// Roll back: return idx to the free list so a retry can reissue
		// it. We cannot leave it in a.owners because the on-wire pin has
		// no record of it.
		a.freeList = append(a.freeList, idx)
		return 0, fmt.Errorf("persist aux owner tag: %w", err)
	}
	a.owners[idx] = owner
	return idx, nil
}

// verifyOwnerLocked checks idx is allocated and owned by owner. Callers
// must hold a.mu.
func (a *indexAllocator) verifyOwnerLocked(idx uint32, owner string) error {
	got, ok := a.owners[idx]
	if !ok {
		return fmt.Errorf("%w: index %d is not allocated", ErrOwnerMismatch, idx)
	}
	if got != owner {
		return fmt.Errorf("%w: index %d owned by %q, caller %q",
			ErrOwnerMismatch, idx, got, owner)
	}
	return nil
}

// freeOwnerLocked is the lockless core of FreeOwner. Callers must have
// already verified ownership and hold a.mu. BPF map clear failures are
// best-effort: in-memory state advances regardless because blocking the
// allocator on a transient kernel error would create an ABA hazard for
// PluginAuxFree -> PluginAuxAlloc retries.
func (a *indexAllocator) freeOwnerLocked(idx uint32) {
	delete(a.owners, idx)
	_ = a.ownerMap.Delete(idx)
	a.freeList = append(a.freeList, idx)
}

// FreeOwner releases idx only if owner matches the tag recorded at Alloc
// time. Mismatched owners return ErrOwnerMismatch and leave the allocator
// state untouched. Freeing an already-free index is also ErrOwnerMismatch.
func (a *indexAllocator) FreeOwner(idx uint32, owner string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.verifyOwnerLocked(idx, owner); err != nil {
		return err
	}
	a.freeOwnerLocked(idx)
	return nil
}

// WithOwnerLocked verifies idx is owned by owner and runs fn while holding
// the allocator lock so a concurrent Free / Alloc cannot reassign idx
// underneath fn. fn should be short (typically one BPF map op) to avoid
// blocking other aux operations.
func (a *indexAllocator) WithOwnerLocked(idx uint32, owner string, fn func() error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.verifyOwnerLocked(idx, owner); err != nil {
		return err
	}
	return fn()
}

// OwnerOf returns the owner tag registered for idx, or "" if idx is free.
// Advisory: the returned value may be stale by the time the caller acts on
// it. For operations that must be atomic with the owner check (map puts,
// sid_function binding), use WithOwnerLocked instead.
func (a *indexAllocator) OwnerOf(idx uint32) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.owners[idx]
}

// RecoverWithOwners rebuilds allocator state from a map of live indices to
// owner tags. Gaps between used indices are added to the free list for
// reuse. Indices >= maxIndex are silently ignored (stale data after config
// change).
func (a *indexAllocator) RecoverWithOwners(owners map[uint32]string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.owners = make(map[uint32]string)
	a.freeList = nil

	if len(owners) == 0 {
		a.nextNew = 1
		return
	}

	maxUsed := uint32(0)
	for idx, owner := range owners {
		if idx >= a.maxIndex {
			continue
		}
		a.owners[idx] = owner
		if idx >= maxUsed {
			maxUsed = idx
		}
	}

	if len(a.owners) == 0 {
		a.nextNew = 1
		return
	}

	a.nextNew = max(maxUsed+1, 1)
	for i := uint32(1); i < a.nextNew; i++ {
		if _, used := a.owners[i]; !used {
			a.freeList = append(a.freeList, i)
		}
	}
}

// RecoverAuxIndices rebuilds the in-memory allocator state at startup.
//
// Persisted path (preferred): when aux_owner_map carries tags, iterate
// it and feed RecoverWithOwners directly. Stand-alone PluginAuxAlloc
// indices that are not yet bound to a SID function are recovered too —
// something the sid_function_map walk below cannot do.
//
// SID-function reconstruction fallback: when aux_owner_map is empty
// (fresh pin path, or pin_maps disabled), rebuild owners from
// sid_function_map by looking at each entry's action — actions below
// EndpointPluginBase are vinbero-managed (AuxOwnerBuiltin), the rest
// are plugin-owned at the endpoint PROG_ARRAY slot indicated by action.
// If persistence is on, recovered tags are then written back into
// aux_owner_map so subsequent restarts take the persisted path.
//
// Entries whose action is in the plugin range but >= EndpointProgMax are
// considered corrupt (no AllocPluginAux path can produce them today; they
// would come from a manual bpftool edit or a kernel-side bug). They are
// skipped -- the idx is left unowned so a fresh alloc can reuse it after
// the operator cleans up the SID entry.
func (m *MapOperations) RecoverAuxIndices() error {
	// Persisted path: try aux_owner_map first when present.
	if m.auxAlloc.ownerMap != nil {
		owners, err := m.auxAlloc.ownerMap.Iterate()
		if err != nil {
			return fmt.Errorf("read aux_owner_map: %w", err)
		}
		if len(owners) > 0 {
			// Translate the persisted tags into the in-memory canonical
			// form used by AllocOwner / FreeOwner.
			inMem := make(map[uint32]string, len(owners))
			for idx, tag := range owners {
				kind, mt, slot, perr := ParseAuxOwnerTag(tag)
				if perr != nil {
					// Corrupt persisted tag: drop the idx so a fresh
					// alloc can reuse it. The unused slot is harmless.
					continue
				}
				switch kind {
				case AuxOwnerKindBuiltin:
					inMem[idx] = AuxOwnerBuiltin
				case AuxOwnerKindPlugin:
					inMem[idx] = AuxOwnerPluginTag(mt, slot)
				}
			}
			m.auxAlloc.RecoverWithOwners(inMem)
			return nil
		}
		// owner_map empty -> fall through to v1 reconstruction + back-fill.
	}

	var key LpmKeyV6
	var entry SidFunctionEntry
	iter := m.objs.SidFunctionMap.Iterate()

	owners := make(map[uint32]string)
	for iter.Next(&key, &entry) {
		if entry.AuxIndex == 0 {
			continue
		}
		idx := uint32(entry.AuxIndex)
		action := uint32(entry.Action)
		if action >= EndpointPluginBase {
			if action >= EndpointProgMax {
				// Out-of-range plugin action: skip recovery so the idx isn't
				// claimed by a tag no live plugin can ever match.
				continue
			}
			// endpoint PROG_ARRAY slot == action for plugin behaviors
			owners[idx] = AuxOwnerPluginTag(MapTypeEndpoint, action)
		} else {
			owners[idx] = AuxOwnerBuiltin
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to iterate SID function map for recovery: %w", err)
	}

	m.auxAlloc.RecoverWithOwners(owners)

	// legacy -> v1 forward migration: write the recovered tags back into
	// aux_owner_map so subsequent restarts take the persisted path.
	// Best-effort: a transient failure here just means the next start
	// re-runs the legacy reconstruction from sid_function_map.
	if m.auxAlloc.ownerMap != nil {
		for idx, tag := range owners {
			_ = m.auxAlloc.ownerMap.Put(idx, tag)
		}
	}
	return nil
}

// FreeAllByOwner releases every index whose owner tag equals ownerTag,
// clearing both the in-memory allocator and aux_owner_map. Used by tests
// that exercise allocator semantics without a BPF map; production purge
// callers go through MapOperations.FreeAllByOwner so each freed index
// also gets a sid_aux_map zero-write.
func (a *indexAllocator) FreeAllByOwner(ownerTag string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	var idxs []uint32
	for idx, owner := range a.owners {
		if owner == ownerTag {
			idxs = append(idxs, idx)
		}
	}
	for _, idx := range idxs {
		a.freeOwnerLocked(idx)
	}
	return len(idxs)
}

// AuxIndexInfo is one entry returned by ListAuxByOwner. Owner uses the
// persisted (version-stamped) form so callers can feed it straight back
// into PluginAuxList responses without an extra rewrite step.
type AuxIndexInfo struct {
	Index uint32
	Owner string
}

// ListAuxByOwner returns every live aux index, optionally filtered by
// owner kind. mapTypeFilter == "" returns all indices regardless of
// owner. Otherwise only plugin-owned indices matching mapTypeFilter (and
// slotFilter when matchSlot is true) are returned. Output is sorted by
// idx so callers get stable ordering for diff / snapshot.
func (m *MapOperations) ListAuxByOwner(mapTypeFilter string, slotFilter uint32, matchSlot bool) []AuxIndexInfo {
	return m.auxAlloc.listByOwner(mapTypeFilter, slotFilter, matchSlot)
}

func (a *indexAllocator) listByOwner(mapTypeFilter string, slotFilter uint32, matchSlot bool) []AuxIndexInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AuxIndexInfo, 0, len(a.owners))
	for idx, tag := range a.owners {
		if mapTypeFilter == "" {
			out = append(out, AuxIndexInfo{Index: idx, Owner: tag})
			continue
		}
		kind, mt, slot, err := ParseAuxOwnerTag(tag)
		if err != nil || kind != AuxOwnerKindPlugin {
			continue
		}
		if mt != mapTypeFilter {
			continue
		}
		if matchSlot && slot != slotFilter {
			continue
		}
		out = append(out, AuxIndexInfo{Index: idx, Owner: tag})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

// ===== SID Aux Entry Constructors =====
// BpfSidAuxEntry is a Go representation of a C union.
// bpf2go exposes only the first union member (nexthop).
// These helpers construct the entry for each variant using raw byte layout.

// NewSidAuxNexthop creates an aux entry for End.X / End.DX2
func NewSidAuxNexthop(nexthop [IPv6AddrLen]uint8) *SidAuxEntry {
	entry := &SidAuxEntry{}
	entry.Nexthop.Nexthop = nexthop
	return entry
}

// NewSidAuxL2 creates an aux entry for End.DT2
func NewSidAuxL2(bdID uint16, bridgeIfindex uint32) *SidAuxEntry {
	entry := &SidAuxEntry{}
	// C layout: bd_id(u16) + _pad(u16) + bridge_ifindex(u32) at union offset 0
	binary.NativeEndian.PutUint16(entry.Nexthop.Nexthop[0:2], bdID)
	binary.NativeEndian.PutUint32(entry.Nexthop.Nexthop[4:8], bridgeIfindex)
	return entry
}

// NewSidAuxDx2v creates an aux entry for End.DX2V
func NewSidAuxDx2v(tableID uint16) *SidAuxEntry {
	entry := &SidAuxEntry{}
	// C layout: table_id(u16) + _pad(u16) at union offset 0
	binary.NativeEndian.PutUint16(entry.Nexthop.Nexthop[0:2], tableID)
	return entry
}

// SidAuxDx2vData extracts DX2V variant fields from a SidAuxEntry
func SidAuxDx2vData(entry *SidAuxEntry) uint16 {
	return binary.NativeEndian.Uint16(entry.Nexthop.Nexthop[0:2])
}

// NewSidAuxGtp4e creates an aux entry for End.M.GTP4.E. When v4srcFromOuter
// is set the data plane extracts the GTP-U IPv4 source from the outer IPv6
// source address at bit v4srcPosition (RFC 9433 §6.6) and gtpV4SrcAddr is
// ignored; otherwise the static gtpV4SrcAddr is used. A separate flag byte
// (not a zero sentinel) keeps position 0 expressible.
func NewSidAuxGtp4e(argsOffset uint8, gtpV4SrcAddr [IPv4AddrLen]uint8, v4srcFromOuter bool, v4srcPosition uint8) *SidAuxEntry {
	entry := &SidAuxEntry{}
	entry.Nexthop.Nexthop[0] = argsOffset
	copy(entry.Nexthop.Nexthop[1:5], gtpV4SrcAddr[:])
	if v4srcFromOuter {
		entry.Nexthop.Nexthop[5] = 1
	}
	entry.Nexthop.Nexthop[6] = v4srcPosition
	return entry
}

// NewSidAuxGtp6d creates an aux entry for End.M.GTP6.D
func NewSidAuxGtp6d(argsOffset uint8) *SidAuxEntry {
	entry := &SidAuxEntry{}
	entry.Nexthop.Nexthop[0] = argsOffset
	return entry
}

// NewSidAuxGtp6e creates an aux entry for End.M.GTP6.E
// Uses unsafe.Pointer to write into the anonymous padding field of the Go struct,
// which corresponds to the C union's gtp6e variant (bytes 16-39).
func NewSidAuxGtp6e(argsOffset uint8, srcAddr, dstAddr [IPv6AddrLen]uint8) *SidAuxEntry {
	entry := &SidAuxEntry{}
	raw := (*[40]byte)(unsafe.Pointer(entry))
	raw[0] = argsOffset
	copy(raw[8:24], srcAddr[:])
	copy(raw[24:40], dstAddr[:])
	return entry
}

// NewSidAuxL3Vrf creates an aux entry for End.T/DT4/DT6/DT46 carrying the
// resolved VRF ifindex in the l3vrf variant.
func NewSidAuxL3Vrf(vrfIfindex uint32) *SidAuxEntry {
	entry := &SidAuxEntry{}
	binary.NativeEndian.PutUint32(entry.Nexthop.Nexthop[0:4], vrfIfindex)
	return entry
}

// SidAuxL3VrfData extracts the VRF ifindex from the l3vrf variant.
func SidAuxL3VrfData(entry *SidAuxEntry) uint32 {
	return binary.NativeEndian.Uint32(entry.Nexthop.Nexthop[0:4])
}

// SidAuxPluginRawMax is the capacity of the plugin_raw variant in
// sid_aux_entry and the pinned size of the union. Writes longer than this
// are rejected at the RPC layer so we never overflow the kernel-side union.
// Must match SID_AUX_PLUGIN_RAW_MAX in src/core/xdp_prog.h.
const SidAuxPluginRawMax = 256

// NewSidAuxPluginRaw creates an aux entry from a plugin-defined byte payload.
// raw may be shorter than SidAuxPluginRawMax; remaining bytes are zero.
// Callers (the RPC handler) must enforce len(raw) <= SidAuxPluginRawMax.
func NewSidAuxPluginRaw(raw []byte) *SidAuxEntry {
	entry := &SidAuxEntry{}
	dst := (*[SidAuxPluginRawMax]byte)(unsafe.Pointer(entry))[:]
	copy(dst, raw)
	return entry
}

// NewSidAuxB6Policy creates an aux entry for End.B6/End.B6.Encaps
// Stores a full HeadendEntry in the b6_policy union variant.
func NewSidAuxB6Policy(policy *HeadendEntry) *SidAuxEntry {
	entry := &SidAuxEntry{}
	n := unsafe.Sizeof(*policy)
	src := (*[256]byte)(unsafe.Pointer(policy))[:n]
	dst := (*[256]byte)(unsafe.Pointer(entry))[:n]
	copy(dst, src)
	return entry
}

// SidAuxB6PolicyData extracts End.B6 policy from a SidAuxEntry
func SidAuxB6PolicyData(entry *SidAuxEntry) *HeadendEntry {
	result := &HeadendEntry{}
	n := unsafe.Sizeof(*result)
	src := (*[256]byte)(unsafe.Pointer(entry))[:n]
	dst := (*[256]byte)(unsafe.Pointer(result))[:n]
	copy(dst, src)
	return result
}

// SidAuxGtp6eData extracts GTP6.E variant fields from a SidAuxEntry
func SidAuxGtp6eData(entry *SidAuxEntry) (argsOffset uint8, srcAddr, dstAddr [IPv6AddrLen]uint8) {
	raw := (*[200]byte)(unsafe.Pointer(entry))
	argsOffset = raw[0]
	copy(srcAddr[:], raw[8:24])
	copy(dstAddr[:], raw[24:40])
	return
}

// SidAuxL2Data extracts L2 variant fields from a SidAuxEntry
func SidAuxL2Data(entry *SidAuxEntry) (bdID uint16, bridgeIfindex uint32) {
	bdID = binary.NativeEndian.Uint16(entry.Nexthop.Nexthop[0:2])
	bridgeIfindex = binary.NativeEndian.Uint32(entry.Nexthop.Nexthop[4:8])
	return
}

// SidAuxGtp4eData extracts GTP4.E variant fields from a SidAuxEntry
func SidAuxGtp4eData(entry *SidAuxEntry) (argsOffset uint8, gtpV4SrcAddr [IPv4AddrLen]uint8, v4srcFromOuter bool, v4srcPosition uint8) {
	argsOffset = entry.Nexthop.Nexthop[0]
	copy(gtpV4SrcAddr[:], entry.Nexthop.Nexthop[1:5])
	v4srcFromOuter = entry.Nexthop.Nexthop[5] != 0
	v4srcPosition = entry.Nexthop.Nexthop[6]
	return
}

// ParseCIDR parses a CIDR string and returns the IP and prefix length
func ParseCIDR(cidr string) (net.IP, int, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try parsing as a single IP address
		ip := net.ParseIP(cidr)
		if ip == nil {
			return nil, 0, fmt.Errorf("invalid CIDR or IP address: %s", cidr)
		}
		if ip.To4() != nil {
			return ip.To4(), 32, nil
		}
		return ip.To16(), 128, nil
	}
	ones, _ := ipnet.Mask.Size()
	return ipnet.IP, ones, nil
}

// ParseIPv6 parses an IPv6 address string
func ParseIPv6(addr string) ([IPv6AddrLen]uint8, error) {
	var result [IPv6AddrLen]uint8
	if addr == "" {
		return result, nil
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return result, fmt.Errorf("invalid IPv6 address: %s", addr)
	}
	ip = ip.To16()
	if ip == nil {
		return result, fmt.Errorf("invalid IPv6 address: %s", addr)
	}
	copy(result[:], ip)
	return result, nil
}

// ===== SID Function Map Operations =====

// allocAndPutBuiltinAux reserves an aux index under the builtin owner tag,
// writes aux to sid_aux_map at that index, and stamps entry.AuxIndex so
// the caller can chain a sid_function_map write. On failure the slot is
// released so the allocator never leaks. Used only from CreateSidFunction
// (aux != nil); CreateSidFunctionWithAuxIndex consumes an aux index that
// is already owned by a plugin.
func (m *MapOperations) allocAndPutBuiltinAux(entry *SidFunctionEntry, aux *SidAuxEntry) error {
	idx, err := m.auxAlloc.AllocOwner(AuxOwnerBuiltin)
	if err != nil {
		return fmt.Errorf("failed to allocate aux index: %w", err)
	}
	// sid_function_entry.aux_index is u16; allocator capacity can in
	// principle exceed 65535 if the operator raised sid_aux_map size,
	// which would silently truncate. Reject before storing the truncated
	// value.
	if idx > math.MaxUint16 {
		_ = m.auxAlloc.FreeOwner(idx, AuxOwnerBuiltin)
		return fmt.Errorf("aux index %d exceeds uint16 range; reduce sid_aux_map capacity below %d",
			idx, math.MaxUint16+1)
	}
	entry.AuxIndex = uint16(idx)
	if err := m.objs.SidAuxMap.Put(idx, aux); err != nil {
		_ = m.auxAlloc.FreeOwner(idx, AuxOwnerBuiltin)
		return fmt.Errorf("failed to put SID aux entry: %w", err)
	}
	return nil
}

// CreateSidFunction adds a SID function entry and optional aux data.
// owner is persisted to sid_function_owner_map so cross-owner mutation
// is rejected (see ErrEntryOwnerMismatch). An empty owner is rejected
// up front (see ErrEmptyOwner).
func (m *MapOperations) CreateSidFunction(triggerPrefix string, entry *SidFunctionEntry, aux *SidAuxEntry, owner OwnerTag) error {
	key, err := buildLpmKeyV6(triggerPrefix)
	if err != nil {
		return fmt.Errorf("failed to build LPM key: %w", err)
	}
	alreadyOwned, err := checkEntryOwner(m.sidFunctionOwners, key, owner)
	if err != nil {
		return err
	}
	if aux != nil {
		if err := m.allocAndPutBuiltinAux(entry, aux); err != nil {
			return err
		}
	}
	auxCleanup := func() {
		if aux != nil {
			_ = m.auxAlloc.FreeOwner(uint32(entry.AuxIndex), AuxOwnerBuiltin)
		}
	}
	return putMainAndOwner(m.objs.SidFunctionMap, m.sidFunctionOwners, key, entry, owner, alreadyOwned, "SID function", auxCleanup)
}

// CreateSidFunctionWithAuxIndex binds a SID function entry to an aux index
// already allocated by PluginAuxAlloc. The allocator lock is held across
// the owner verification and the sid_function_map write so a concurrent
// PluginAuxFree cannot reassign the index. expectedAuxOwner is the tag
// the caller believes owns the aux index (typically
// AuxOwnerPluginTag(mapType, slot)); mismatch returns ErrOwnerMismatch.
// entryOwner is the OwnerTag persisted to sid_function_owner_map so the
// entry itself participates in the same ownership scheme as builtin SIDs.
func (m *MapOperations) CreateSidFunctionWithAuxIndex(triggerPrefix string, entry *SidFunctionEntry, expectedAuxOwner string, entryOwner OwnerTag) error {
	if entry.AuxIndex == 0 {
		return fmt.Errorf("aux_index must be non-zero")
	}
	// Caller-side guard so the WithOwnerLocked verify does not surface as
	// a confusing "owned by X, caller \"\"" error.
	if expectedAuxOwner == "" {
		return fmt.Errorf("expectedAuxOwner must be non-empty")
	}
	key, err := buildLpmKeyV6(triggerPrefix)
	if err != nil {
		return fmt.Errorf("failed to build LPM key: %w", err)
	}
	alreadyOwned, err := checkEntryOwner(m.sidFunctionOwners, key, entryOwner)
	if err != nil {
		return err
	}
	return m.auxAlloc.WithOwnerLocked(uint32(entry.AuxIndex), expectedAuxOwner, func() error {
		return putMainAndOwner(m.objs.SidFunctionMap, m.sidFunctionOwners, key, entry, entryOwner, alreadyOwned, "SID function", nil)
	})
}

// AllocPluginAux reserves an index in the plugin_raw variant of sid_aux_map
// and tags it with owner. The caller must then write content via
// PutPluginAux; allocating and writing are split so a JSON-encode error
// leaves no half-populated entry behind.
func (m *MapOperations) AllocPluginAux(owner string) (uint32, error) {
	idx, err := m.auxAlloc.AllocOwner(owner)
	if err != nil {
		return 0, err
	}
	// Defense in depth: newIndexAllocator already clamps maxIndex to the
	// uint16 range, so this branch is unreachable today. Keep the explicit
	// guard so SidFunctionEntry.AuxIndex (uint16) can never silently
	// truncate the value we hand back to the caller.
	if idx > math.MaxUint16 {
		_ = m.auxAlloc.FreeOwner(idx, owner)
		return 0, fmt.Errorf("aux index %d exceeds uint16 range", idx)
	}
	return idx, nil
}

// PutPluginAux writes raw into sid_aux_map[idx] atomically w.r.t. the owner
// check: a racing Free cannot reassign idx between check and write. raw must
// be <= SidAuxPluginRawMax; shorter payloads are zero-padded on the wire.
func (m *MapOperations) PutPluginAux(idx uint32, raw []byte, owner string) error {
	if len(raw) > SidAuxPluginRawMax {
		return fmt.Errorf("%w: %d > %d", ErrAuxPayloadTooLarge, len(raw), SidAuxPluginRawMax)
	}
	return m.auxAlloc.WithOwnerLocked(idx, owner, func() error {
		entry := NewSidAuxPluginRaw(raw)
		if err := m.objs.SidAuxMap.Put(idx, entry); err != nil {
			return fmt.Errorf("failed to put plugin aux entry: %w", err)
		}
		return nil
	})
}

// GetPluginAux returns the raw bytes stored at idx after verifying owner,
// holding the allocator lock across the lookup so a racing Free cannot
// reassign idx mid-read. Returned slice length is SidAuxPluginRawMax.
func (m *MapOperations) GetPluginAux(idx uint32, owner string) ([]byte, error) {
	var raw []byte
	err := m.auxAlloc.WithOwnerLocked(idx, owner, func() error {
		var entry SidAuxEntry
		if err := m.objs.SidAuxMap.Lookup(idx, &entry); err != nil {
			return fmt.Errorf("failed to look up plugin aux entry: %w", err)
		}
		raw = make([]byte, SidAuxPluginRawMax)
		src := (*[SidAuxPluginRawMax]byte)(unsafe.Pointer(&entry))[:]
		copy(raw, src)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// FreePluginAux zeroes sid_aux_map[idx] and releases the allocator slot in a
// single critical section: the idx cannot be re-allocated between the zero-
// write and the slot release.
func (m *MapOperations) FreePluginAux(idx uint32, owner string) error {
	return m.auxAlloc.WithOwnerLocked(idx, owner, func() error {
		var zero SidAuxEntry
		if err := m.objs.SidAuxMap.Put(idx, &zero); err != nil {
			return fmt.Errorf("failed to zero plugin aux entry: %w", err)
		}
		m.auxAlloc.freeOwnerLocked(idx)
		return nil
	})
}

// DeleteSidFunction removes a SID function entry after verifying that
// requester owns it. Cross-owner deletes return ErrEntryOwnerMismatch.
// Use ForceDeleteSidFunction for migration / force-override paths.
func (m *MapOperations) DeleteSidFunction(triggerPrefix string, requester OwnerTag) error {
	return m.deleteSidFunctionInternal(triggerPrefix, requester, false)
}

// ForceDeleteSidFunction removes a SID function entry regardless of
// recorded owner. Reserved for operator escape hatches and the implicit
// scope=all flush path; everyday RPC/BGP paths should use DeleteSidFunction.
func (m *MapOperations) ForceDeleteSidFunction(triggerPrefix string) error {
	return m.deleteSidFunctionInternal(triggerPrefix, "", true)
}

func (m *MapOperations) deleteSidFunctionInternal(triggerPrefix string, requester OwnerTag, force bool) error {
	key, err := buildLpmKeyV6(triggerPrefix)
	if err != nil {
		return fmt.Errorf("failed to build LPM key: %w", err)
	}
	if !force {
		if _, err := checkEntryOwner(m.sidFunctionOwners, key, requester); err != nil {
			return err
		}
	}

	// Read entry first so aux can be cleaned up after successful delete.
	var entry SidFunctionEntry
	hasEntry := m.objs.SidFunctionMap.Lookup(key, &entry) == nil

	if err := deleteMapKey(m.objs.SidFunctionMap, key); err != nil {
		return fmt.Errorf("failed to delete SID function entry: %w", err)
	}
	if err := m.sidFunctionOwners.Delete(key); err != nil {
		return fmt.Errorf("failed to delete SID function owner: %w", err)
	}

	// Plugin-owned aux is NOT freed here — the plugin path (PluginAuxFree
	// RPC) owns that lifecycle, so SID delete just unbinds the reference.
	// Builtin aux is freed in lockstep with the zero-write so a racing
	// PluginAuxFree → PluginAuxAlloc cannot reassign idx between the
	// owner check and the map op.
	if hasEntry && entry.AuxIndex != 0 {
		idx := uint32(entry.AuxIndex)
		_ = m.auxAlloc.WithOwnerLocked(idx, AuxOwnerBuiltin, func() error {
			var zero SidAuxEntry
			_ = m.objs.SidAuxMap.Put(idx, &zero)
			m.auxAlloc.freeOwnerLocked(idx)
			return nil
		})
	}
	return nil
}

// GetSidFunction retrieves a SID function entry from the map
func (m *MapOperations) GetSidFunction(triggerPrefix string) (*SidFunctionEntry, error) {
	key, err := buildLpmKeyV6(triggerPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to build LPM key: %w", err)
	}

	var entry SidFunctionEntry
	if err := m.objs.SidFunctionMap.Lookup(key, &entry); err != nil {
		return nil, fmt.Errorf("failed to lookup SID function entry: %w", err)
	}
	return &entry, nil
}

// GetSidAux retrieves a SID aux entry by index
func (m *MapOperations) GetSidAux(index uint32) (*SidAuxEntry, error) {
	var aux SidAuxEntry
	if err := m.objs.SidAuxMap.Lookup(index, &aux); err != nil {
		return nil, fmt.Errorf("failed to lookup SID aux entry: %w", err)
	}
	return &aux, nil
}

// ListSidFunctions returns all SID function entries
func (m *MapOperations) ListSidFunctions() (map[string]*SidFunctionEntry, error) {
	result := make(map[string]*SidFunctionEntry)

	var key LpmKeyV6
	var entry SidFunctionEntry
	iter := m.objs.SidFunctionMap.Iterate()

	for iter.Next(&key, &entry) {
		prefix := lpmKeyV6ToString(&key)
		entryCopy := entry
		result[prefix] = &entryCopy
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate SID function map: %w", err)
	}
	return result, nil
}

// ===== Stats Map Operations =====

const StatsMax = 8

var StatsCounterName = [StatsMax]string{
	"RX_PACKETS", "PASS", "DROP", "REDIRECT", "ABORTED",
	"SPLIT_HORIZON_TX", "SPLIT_HORIZON_RX", "NON_DF_DROP",
}

type AggregatedStats struct {
	Name    string
	Packets uint64
	Bytes   uint64
}

// aggregatePerCPUMap iterates keys 0..max-1 of a PERCPU_ARRAY whose value
// type is BpfStatsEntry, aggregates the per-CPU packets/bytes per key, and
// invokes emit(key, packets, bytes) for each. Shared by stats_map and
// slot_stats_* reads.
func aggregatePerCPUMap(m *ebpf.Map, max uint32, emit func(key, packets, bytes uint64)) error {
	for i := uint32(0); i < max; i++ {
		var perCPU []BpfStatsEntry
		if err := m.Lookup(i, &perCPU); err != nil {
			return fmt.Errorf("slot %d: %w", i, err)
		}
		var p, b uint64
		for _, c := range perCPU {
			p += c.Packets
			b += c.Bytes
		}
		emit(uint64(i), p, b)
	}
	return nil
}

// resetPerCPUMap zeros all per-CPU entries of a PERCPU_ARRAY stats map.
func resetPerCPUMap(m *ebpf.Map, max uint32) error {
	numCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("failed to get CPU count: %w", err)
	}
	zeros := make([]BpfStatsEntry, numCPUs)
	for i := uint32(0); i < max; i++ {
		if err := m.Put(i, zeros); err != nil {
			return fmt.Errorf("slot %d: %w", i, err)
		}
	}
	return nil
}

// ReadStats reads the PERCPU_ARRAY stats_map and aggregates per-CPU values
func (m *MapOperations) ReadStats() ([]AggregatedStats, error) {
	result := make([]AggregatedStats, StatsMax)
	err := aggregatePerCPUMap(m.objs.StatsMap, StatsMax, func(i, p, b uint64) {
		result[i] = AggregatedStats{Name: StatsCounterName[i], Packets: p, Bytes: b}
	})
	if err != nil {
		return nil, fmt.Errorf("stats_map: %w", err)
	}
	return result, nil
}

// ResetStats zeros all per-CPU stats counters.
func (m *MapOperations) ResetStats() error {
	if err := resetPerCPUMap(m.objs.StatsMap, StatsMax); err != nil {
		return fmt.Errorf("stats_map: %w", err)
	}
	return nil
}

// ===== Per-slot Stats Map Operations =====

// SlotStatsEndpointMax / SlotStatsHeadendMax mirror the BPF-side maps in
// src/core/xdp_stats.h. Must match the C constants.
const (
	SlotStatsEndpointMax = 64
	SlotStatsHeadendMax  = 32
)

// SlotStatsEntry is a per-slot invocation counter record.
type SlotStatsEntry struct {
	MapType string
	Slot    uint32
	Packets uint64
	Bytes   uint64
}

func (m *MapOperations) slotStatsTarget(mapType string) (ebpfMap *ebpf.Map, max uint32, err error) {
	switch mapType {
	case MapTypeEndpoint:
		return m.objs.SlotStatsEndpoint, SlotStatsEndpointMax, nil
	case MapTypeHeadendV4:
		return m.objs.SlotStatsHeadendV4, SlotStatsHeadendMax, nil
	case MapTypeHeadendV6:
		return m.objs.SlotStatsHeadendV6, SlotStatsHeadendMax, nil
	default:
		return nil, 0, fmt.Errorf("unknown slot stats map type: %s", mapType)
	}
}

// ReadSlotStats reads one of the slot_stats_* PERCPU_ARRAYs and aggregates
// each slot's per-CPU values.
func (m *MapOperations) ReadSlotStats(mapType string) ([]SlotStatsEntry, error) {
	ebpfMap, max, err := m.slotStatsTarget(mapType)
	if err != nil {
		return nil, err
	}
	out := make([]SlotStatsEntry, 0, max)
	err = aggregatePerCPUMap(ebpfMap, max, func(i, p, b uint64) {
		out = append(out, SlotStatsEntry{
			MapType: mapType,
			Slot:    uint32(i),
			Packets: p,
			Bytes:   b,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", mapType, err)
	}
	return out, nil
}

// ResetSlotStats zeros all per-CPU entries of a single slot stats map.
func (m *MapOperations) ResetSlotStats(mapType string) error {
	ebpfMap, max, err := m.slotStatsTarget(mapType)
	if err != nil {
		return err
	}
	if err := resetPerCPUMap(ebpfMap, max); err != nil {
		return fmt.Errorf("%s: %w", mapType, err)
	}
	return nil
}

// ===== Headend V4 Map Operations =====

// CreateHeadendV4 adds a headend v4 entry. owner is persisted to
// headend_v4_owner_map; empty owner returns ErrEmptyOwner, cross-owner
// write returns ErrEntryOwnerMismatch.
func (m *MapOperations) CreateHeadendV4(triggerPrefix string, entry *HeadendEntry, owner OwnerTag) error {
	key, err := buildLpmKeyV4(triggerPrefix)
	if err != nil {
		return fmt.Errorf("failed to build LPM key: %w", err)
	}
	alreadyOwned, err := checkEntryOwner(m.headendV4Owners, key, owner)
	if err != nil {
		return err
	}
	return putMainAndOwner(m.objs.HeadendV4Map, m.headendV4Owners, key, entry, owner, alreadyOwned, "headend v4", nil)
}

// DeleteHeadendV4 removes a headend v4 entry after verifying the caller
// owns it. Cross-owner deletes return ErrEntryOwnerMismatch. Use
// ForceDeleteHeadendV4 for migration / force-override paths.
func (m *MapOperations) DeleteHeadendV4(triggerPrefix string, requester OwnerTag) error {
	return m.deleteHeadendV4Internal(triggerPrefix, requester, false)
}

// ForceDeleteHeadendV4 removes a headend v4 entry regardless of recorded
// owner.
func (m *MapOperations) ForceDeleteHeadendV4(triggerPrefix string) error {
	return m.deleteHeadendV4Internal(triggerPrefix, "", true)
}

func (m *MapOperations) deleteHeadendV4Internal(triggerPrefix string, requester OwnerTag, force bool) error {
	key, err := buildLpmKeyV4(triggerPrefix)
	if err != nil {
		return fmt.Errorf("failed to build LPM key: %w", err)
	}
	if !force {
		if _, err := checkEntryOwner(m.headendV4Owners, key, requester); err != nil {
			return err
		}
	}
	if err := deleteMapKey(m.objs.HeadendV4Map, key); err != nil {
		return fmt.Errorf("failed to delete headend v4 entry: %w", err)
	}
	if err := m.headendV4Owners.Delete(key); err != nil {
		return fmt.Errorf("failed to delete headend v4 owner: %w", err)
	}
	return nil
}

// GetHeadendV4 retrieves a headend v4 entry from the map
func (m *MapOperations) GetHeadendV4(triggerPrefix string) (*HeadendEntry, error) {
	key, err := buildLpmKeyV4(triggerPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to build LPM key: %w", err)
	}

	var entry HeadendEntry
	if err := m.objs.HeadendV4Map.Lookup(key, &entry); err != nil {
		return nil, fmt.Errorf("failed to lookup headend v4 entry: %w", err)
	}
	return &entry, nil
}

// ListHeadendV4 returns all headend v4 entries
func (m *MapOperations) ListHeadendV4() (map[string]*HeadendEntry, error) {
	result := make(map[string]*HeadendEntry)

	var key LpmKeyV4
	var entry HeadendEntry
	iter := m.objs.HeadendV4Map.Iterate()

	for iter.Next(&key, &entry) {
		prefix := lpmKeyV4ToString(&key)
		entryCopy := entry
		result[prefix] = &entryCopy
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate headend v4 map: %w", err)
	}
	return result, nil
}

// ===== MUP Uplink V4 Map Operations (BGP MUP T2ST / F-TEID) =====

// buildMupUplinkV4Key assembles the LPM_TRIE key for mup_uplink_v4_map.
// instance is the uplink service instance the session belongs to (0 = the
// default instance; the data plane resolves it from the packet's ingress
// ifindex via mup_ifindex_instance_map), stored big-endian and always fully
// matched. endpoint is the GTP-U outer destination (the N3/UPF endpoint,
// always a full /32); teid is the GTP-U TEID and teidPrefixBits (0..32) is how
// many of its high-order bits are significant — BGP MUP T2ST carries the TEID
// as a variable-length prefix, so teidPrefixBits == EndpointAddressLength - 32.
// prefixlen = 64 + teidPrefixBits. teid is stored network byte order and masked
// to the prefix so the insert/delete key is canonical.
func buildMupUplinkV4Key(instance uint32, endpoint string, teid uint32, teidPrefixBits uint8) (*MupUplinkV4Key, error) {
	if teidPrefixBits > 32 {
		return nil, fmt.Errorf("mup uplink teid prefix bits %d exceeds 32", teidPrefixBits)
	}
	ep, err := ParseIPv4Optional(endpoint)
	if err != nil {
		return nil, fmt.Errorf("mup uplink endpoint: %w", err)
	}
	if ep == ([IPv4AddrLen]uint8{}) {
		return nil, fmt.Errorf("mup uplink endpoint is required")
	}
	key := &MupUplinkV4Key{Prefixlen: 64 + uint32(teidPrefixBits)}
	binary.BigEndian.PutUint32(key.Instance[:], instance)
	copy(key.Endpoint[:], ep[:])
	// Mask the TEID to its prefix bits so the insert/delete key is canonical.
	// Go shift semantics fold the edge cases into one expression: a shift count
	// >= width yields 0 (teidPrefixBits == 0) and a count of 0 is a no-op
	// (teidPrefixBits == 32). teidPrefixBits > 32 is rejected above.
	masked := teid & (^uint32(0) << (32 - teidPrefixBits))
	binary.BigEndian.PutUint32(key.Teid[:], masked)
	return key, nil
}

// CreateMupUplinkV4 installs an F-TEID uplink session entry (BGP MUP T2ST,
// draft-mpmz-bess-mup-safi): GTP-U whose {endpoint, TEID-prefix} matches is
// transformed by the H.M.GTP4.D_TEID behavior into SRv6 toward entry's segment
// list (the direct SID). teidPrefixBits is the significant TEID prefix length
// (32 = exact session, 0 = every TEID toward endpoint). entry is a plain
// H.Encaps headend_entry; set entry.ArgsOffset = MupArgsOffsetNone for a direct
// (End.DT4) target so Args.Mob.Session is not patched into the outgoing SID.
func (m *MapOperations) CreateMupUplinkV4(instance uint32, endpoint string, teid uint32, teidPrefixBits uint8, entry *HeadendEntry) error {
	key, err := buildMupUplinkV4Key(instance, endpoint, teid, teidPrefixBits)
	if err != nil {
		return err
	}
	if err := m.objs.MupUplinkV4Map.Put(key, entry); err != nil {
		return fmt.Errorf("failed to put mup uplink v4 entry: %w", err)
	}
	return nil
}

// DeleteMupUplinkV4 removes an F-TEID uplink session entry. The {endpoint, teid,
// teidPrefixBits} tuple must match an installed prefix. A missing key is treated
// as success so a double withdraw is idempotent.
func (m *MapOperations) DeleteMupUplinkV4(instance uint32, endpoint string, teid uint32, teidPrefixBits uint8) error {
	key, err := buildMupUplinkV4Key(instance, endpoint, teid, teidPrefixBits)
	if err != nil {
		return err
	}
	if err := deleteMapKey(m.objs.MupUplinkV4Map, key); err != nil {
		return fmt.Errorf("failed to delete mup uplink v4 entry: %w", err)
	}
	return nil
}

// buildMupUplinkV6Key assembles the LPM_TRIE key for mup_uplink_v6_map: the
// IPv6 counterpart of buildMupUplinkV4Key. instance is the uplink service
// instance (0 = default, big-endian, always fully matched); endpoint is the
// GTP-U/IPv6 outer destination (full /128); teidPrefixBits (0..32) is the
// significant TEID prefix length, so prefixlen = 160 + teidPrefixBits. teid is
// stored network byte order and masked to the prefix so the insert/delete key
// is canonical.
func buildMupUplinkV6Key(instance uint32, endpoint string, teid uint32, teidPrefixBits uint8) (*MupUplinkV6Key, error) {
	if teidPrefixBits > 32 {
		return nil, fmt.Errorf("mup uplink teid prefix bits %d exceeds 32", teidPrefixBits)
	}
	ep, err := ParseIPv6(endpoint)
	if err != nil {
		return nil, fmt.Errorf("mup uplink v6 endpoint: %w", err)
	}
	// ParseIPv6 maps an empty string to the unspecified address rather than an
	// error, so reject it explicitly (matching the V4 path); an empty / "::"
	// endpoint must not become a real F-TEID entry.
	if ep == ([IPv6AddrLen]uint8{}) {
		return nil, fmt.Errorf("mup uplink v6 endpoint is required")
	}
	key := &MupUplinkV6Key{Prefixlen: 160 + uint32(teidPrefixBits)}
	binary.BigEndian.PutUint32(key.Instance[:], instance)
	copy(key.Endpoint[:], ep[:])
	masked := teid & (^uint32(0) << (32 - teidPrefixBits))
	binary.BigEndian.PutUint32(key.Teid[:], masked)
	return key, nil
}

// CreateMupUplinkV6 installs an F-TEID uplink session entry over GTP6 (BGP MUP
// T2ST, IPv6 endpoint): the IPv6 counterpart of CreateMupUplinkV4, read by the
// H.M.GTP6.D_TEID behavior. See CreateMupUplinkV4 for the entry semantics.
func (m *MapOperations) CreateMupUplinkV6(instance uint32, endpoint string, teid uint32, teidPrefixBits uint8, entry *HeadendEntry) error {
	key, err := buildMupUplinkV6Key(instance, endpoint, teid, teidPrefixBits)
	if err != nil {
		return err
	}
	if err := m.objs.MupUplinkV6Map.Put(key, entry); err != nil {
		return fmt.Errorf("failed to put mup uplink v6 entry: %w", err)
	}
	return nil
}

// DeleteMupUplinkV6 removes an F-TEID uplink session entry over GTP6. A missing
// key is treated as success so a double withdraw is idempotent.
func (m *MapOperations) DeleteMupUplinkV6(instance uint32, endpoint string, teid uint32, teidPrefixBits uint8) error {
	key, err := buildMupUplinkV6Key(instance, endpoint, teid, teidPrefixBits)
	if err != nil {
		return err
	}
	if err := deleteMapKey(m.objs.MupUplinkV6Map, key); err != nil {
		return fmt.Errorf("failed to delete mup uplink v6 entry: %w", err)
	}
	return nil
}

// ===== MUP Uplink Instance Map Operations =====

// SetMupUplinkInstances replaces the ingress-ifindex -> uplink-instance
// mapping (mup_ifindex_instance_map) with the given one: stale keys are
// removed, new and changed ones written. The data plane resolves a packet's
// uplink instance from this map (miss = default instance 0), so the rewrite
// is what re-scopes traffic after a VRF binding's mup_uplink_interfaces
// change.
func (m *MapOperations) SetMupUplinkInstances(mapping map[uint32]uint32) error {
	var (
		key  uint32
		val  uint32
		dead []uint32
	)
	iter := m.objs.MupIfindexInstanceMap.Iterate()
	for iter.Next(&key, &val) {
		if _, keep := mapping[key]; !keep {
			dead = append(dead, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to iterate mup ifindex instance map: %w", err)
	}
	for _, k := range dead {
		if err := deleteMapKey(m.objs.MupIfindexInstanceMap, &k); err != nil {
			return fmt.Errorf("failed to delete mup ifindex instance entry: %w", err)
		}
	}
	for k, v := range mapping {
		if err := m.objs.MupIfindexInstanceMap.Put(&k, &v); err != nil {
			return fmt.Errorf("failed to put mup ifindex instance entry: %w", err)
		}
	}
	return nil
}

// ===== Headend V6 Map Operations =====

// CreateHeadendV6 adds a headend v6 entry. owner is persisted to
// headend_v6_owner_map; empty owner returns ErrEmptyOwner, cross-owner
// write returns ErrEntryOwnerMismatch.
func (m *MapOperations) CreateHeadendV6(triggerPrefix string, entry *HeadendEntry, owner OwnerTag) error {
	key, err := buildLpmKeyV6(triggerPrefix)
	if err != nil {
		return fmt.Errorf("failed to build LPM key: %w", err)
	}
	alreadyOwned, err := checkEntryOwner(m.headendV6Owners, key, owner)
	if err != nil {
		return err
	}
	return putMainAndOwner(m.objs.HeadendV6Map, m.headendV6Owners, key, entry, owner, alreadyOwned, "headend v6", nil)
}

// DeleteHeadendV6 removes a headend v6 entry after verifying the caller
// owns it. Cross-owner deletes return ErrEntryOwnerMismatch. Use
// ForceDeleteHeadendV6 for migration / force-override paths.
func (m *MapOperations) DeleteHeadendV6(triggerPrefix string, requester OwnerTag) error {
	return m.deleteHeadendV6Internal(triggerPrefix, requester, false)
}

// ForceDeleteHeadendV6 removes a headend v6 entry regardless of recorded
// owner.
func (m *MapOperations) ForceDeleteHeadendV6(triggerPrefix string) error {
	return m.deleteHeadendV6Internal(triggerPrefix, "", true)
}

func (m *MapOperations) deleteHeadendV6Internal(triggerPrefix string, requester OwnerTag, force bool) error {
	key, err := buildLpmKeyV6(triggerPrefix)
	if err != nil {
		return fmt.Errorf("failed to build LPM key: %w", err)
	}
	if !force {
		if _, err := checkEntryOwner(m.headendV6Owners, key, requester); err != nil {
			return err
		}
	}
	if err := deleteMapKey(m.objs.HeadendV6Map, key); err != nil {
		return fmt.Errorf("failed to delete headend v6 entry: %w", err)
	}
	if err := m.headendV6Owners.Delete(key); err != nil {
		return fmt.Errorf("failed to delete headend v6 owner: %w", err)
	}
	return nil
}

// GetHeadendV6 retrieves a headend v6 entry from the map
func (m *MapOperations) GetHeadendV6(triggerPrefix string) (*HeadendEntry, error) {
	key, err := buildLpmKeyV6(triggerPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to build LPM key: %w", err)
	}

	var entry HeadendEntry
	if err := m.objs.HeadendV6Map.Lookup(key, &entry); err != nil {
		return nil, fmt.Errorf("failed to lookup headend v6 entry: %w", err)
	}
	return &entry, nil
}

// ListHeadendV6 returns all headend v6 entries
func (m *MapOperations) ListHeadendV6() (map[string]*HeadendEntry, error) {
	result := make(map[string]*HeadendEntry)

	var key LpmKeyV6
	var entry HeadendEntry
	iter := m.objs.HeadendV6Map.Iterate()

	for iter.Next(&key, &entry) {
		prefix := lpmKeyV6ToString(&key)
		entryCopy := entry
		result[prefix] = &entryCopy
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate headend v6 map: %w", err)
	}
	return result, nil
}

// ===== SR Policy Map Operations =====

// UpsertSRPolicy installs (or atomically replaces) the transport SID list
// shared by every headend entry whose policy_id == policyID. The XDP
// headend prepends these SIDs to each route's own service SID. The write
// is value-atomic, so a policy change never exposes a torn segment list,
// and it is O(1) regardless of how many routes steer onto the policy.
func (m *MapOperations) UpsertSRPolicy(policyID uint32, transport []netip.Addr) error {
	// policy_id 0 is the "no steering" sentinel in the headend entry, so the
	// XDP program never looks it up; an sr_policy_map[0] entry would be dead.
	// Reject it to catch a caller that handed out 0 (e.g. an exhausted id).
	if policyID == 0 {
		return fmt.Errorf("sr_policy: policy_id 0 is reserved (no steering)")
	}
	// Cap at MaxSegments-1: the XDP headend composes the route's service SID
	// onto the tail, so a transport of MaxSegments would always overflow the
	// SRH and silently fall back. Reject it at write time instead.
	if len(transport) < 1 || len(transport) >= MaxSegments {
		return fmt.Errorf("sr_policy %d: transport length %d out of range 1..%d",
			policyID, len(transport), MaxSegments-1)
	}
	var val BpfSrPolicyValue
	val.Len = uint8(len(transport))
	for i, sid := range transport {
		// Is6 already covers IPv4-mapped IPv6 (Is4In6 implies Is6), so this
		// single check rejects only genuine IPv4 SIDs, matching the decode
		// and RPC-boundary validation.
		if !sid.Is6() {
			return fmt.Errorf("sr_policy %d: segment %d (%s) is not an IPv6 SID", policyID, i, sid)
		}
		val.Segs[i] = sid.As16()
	}
	if err := m.objs.SrPolicyMap.Put(policyID, &val); err != nil {
		return fmt.Errorf("put sr_policy_map[%d]: %w", policyID, err)
	}
	return nil
}

// DeleteSRPolicy removes a policy's transport list. Referencing routes
// then miss the lookup in XDP and fall back to their bare service SID.
// A missing entry is not an error (idempotent withdraw).
func (m *MapOperations) DeleteSRPolicy(policyID uint32) error {
	if err := m.objs.SrPolicyMap.Delete(policyID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete sr_policy_map[%d]: %w", policyID, err)
	}
	return nil
}

// GetSRPolicy returns the transport SID list installed for policyID, or
// nil when no entry exists. Intended for tests and introspection.
func (m *MapOperations) GetSRPolicy(policyID uint32) ([]net.IP, error) {
	var val BpfSrPolicyValue
	if err := m.objs.SrPolicyMap.Lookup(policyID, &val); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("lookup sr_policy_map[%d]: %w", policyID, err)
	}
	n := int(val.Len)
	if n > MaxSegments {
		n = MaxSegments
	}
	out := make([]net.IP, n)
	for i := 0; i < n; i++ {
		out[i] = net.IP(append([]byte(nil), val.Segs[i][:]...))
	}
	return out, nil
}

// ===== Headend L2 Map Operations =====

// CreateHeadendL2 adds a headend L2 entry to the map (keyed by port + VLAN).
// esi is the 10-byte RFC 7432 ESI of this local AC; all-zero means
// single-homing and skips the side-table write. If entry.BdId is non-zero
// and esi is set, bd_local_esi_map is also populated for the DT2M DF check.
func (m *MapOperations) CreateHeadendL2(ifindex uint32, vlanID uint16, entry *HeadendEntry, esi [ESILen]byte) error {
	key := buildHeadendL2Key(ifindex, vlanID)
	if err := m.objs.HeadendL2Map.Put(key, entry); err != nil {
		return fmt.Errorf("failed to put headend L2 entry: %w", err)
	}

	var zero [ESILen]byte
	if esi != zero {
		if err := m.objs.HeadendL2ExtMap.Put(key, &BpfHeadendL2ExtVal{Esi: esi}); err != nil {
			return fmt.Errorf("failed to put headend L2 ESI ext: %w", err)
		}
		if entry.BdId != 0 {
			bdKey := uint32(entry.BdId)
			if err := m.objs.BdLocalEsiMap.Put(&bdKey, &BpfBdLocalEsiVal{Esi: esi}); err != nil {
				return fmt.Errorf("failed to put bd_local_esi entry: %w", err)
			}
		}
	} else {
		_ = m.objs.HeadendL2ExtMap.Delete(key)
		if entry.BdId != 0 {
			bdKey := uint32(entry.BdId)
			_ = m.objs.BdLocalEsiMap.Delete(&bdKey)
		}
	}
	return nil
}

// DeleteHeadendL2 removes a headend L2 entry from the map
func (m *MapOperations) DeleteHeadendL2(ifindex uint32, vlanID uint16) error {
	key := buildHeadendL2Key(ifindex, vlanID)
	var prev HeadendEntry
	hadEntry := m.objs.HeadendL2Map.Lookup(key, &prev) == nil
	if err := m.objs.HeadendL2Map.Delete(key); err != nil {
		return fmt.Errorf("failed to delete headend L2 entry: %w", err)
	}
	_ = m.objs.HeadendL2ExtMap.Delete(key)
	if hadEntry && prev.BdId != 0 {
		bdKey := uint32(prev.BdId)
		_ = m.objs.BdLocalEsiMap.Delete(&bdKey)
	}
	return nil
}

// GetHeadendL2Esi looks up the side-table ESI for a given (ifindex, vlan).
// Returns zero ESI if the entry is missing (single-homing).
func (m *MapOperations) GetHeadendL2Esi(ifindex uint32, vlanID uint16) ([ESILen]byte, error) {
	var out [ESILen]byte
	key := buildHeadendL2Key(ifindex, vlanID)
	var ext BpfHeadendL2ExtVal
	if err := m.objs.HeadendL2ExtMap.Lookup(key, &ext); err != nil {
		return out, nil // missing entry == single-homing
	}
	return ext.Esi, nil
}

// GetHeadendL2 retrieves a headend L2 entry from the map
func (m *MapOperations) GetHeadendL2(ifindex uint32, vlanID uint16) (*HeadendEntry, error) {
	key := buildHeadendL2Key(ifindex, vlanID)
	var entry HeadendEntry
	if err := m.objs.HeadendL2Map.Lookup(key, &entry); err != nil {
		return nil, fmt.Errorf("failed to lookup headend L2 entry: %w", err)
	}
	return &entry, nil
}

// ListHeadendL2 returns all headend L2 entries
func (m *MapOperations) ListHeadendL2() (map[HeadendL2Key]*HeadendEntry, error) {
	result := make(map[HeadendL2Key]*HeadendEntry)
	var key HeadendL2Key
	var entry HeadendEntry
	iter := m.objs.HeadendL2Map.Iterate()
	for iter.Next(&key, &entry) {
		entryCopy := entry
		result[key] = &entryCopy
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate headend L2 map: %w", err)
	}
	return result, nil
}

// ===== FDB Map Operations (for End.DT2) =====

// CreateFdb adds an FDB entry to the map
func (m *MapOperations) CreateFdb(bdID uint16, mac net.HardwareAddr, entry *FdbEntry) error {
	key := buildFdbKey(bdID, mac)
	if err := m.objs.FdbMap.Put(key, entry); err != nil {
		return fmt.Errorf("failed to put fdb entry: %w", err)
	}
	return nil
}

// DeleteFdb removes an FDB entry from the map
func (m *MapOperations) DeleteFdb(bdID uint16, mac net.HardwareAddr) error {
	key := buildFdbKey(bdID, mac)
	if err := m.objs.FdbMap.Delete(key); err != nil {
		return fmt.Errorf("failed to delete fdb entry: %w", err)
	}
	return nil
}

// GetFdb retrieves an FDB entry from the map
func (m *MapOperations) GetFdb(bdID uint16, mac net.HardwareAddr) (*FdbEntry, error) {
	key := buildFdbKey(bdID, mac)
	var entry FdbEntry
	if err := m.objs.FdbMap.Lookup(key, &entry); err != nil {
		return nil, fmt.Errorf("failed to lookup fdb entry: %w", err)
	}
	return &entry, nil
}

// ListFdb returns all FDB entries
func (m *MapOperations) ListFdb() (map[FdbKey]*FdbEntry, error) {
	result := make(map[FdbKey]*FdbEntry)
	var key FdbKey
	var entry FdbEntry
	iter := m.objs.FdbMap.Iterate()
	for iter.Next(&key, &entry) {
		entryCopy := entry
		result[key] = &entryCopy
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate fdb map: %w", err)
	}
	return result, nil
}

// ===== VLAN Cross-Connect (DX2V) Map Operations =====

// CreateDx2vVlan creates a VLAN cross-connect entry in dx2v_map
func (m *MapOperations) CreateDx2vVlan(tableID, vlanID uint16, oif uint32) error {
	key := &Dx2vKey{TableId: tableID, VlanId: vlanID}
	entry := &Dx2vEntry{Oif: oif}
	if err := m.objs.Dx2vMap.Put(key, entry); err != nil {
		return fmt.Errorf("failed to put dx2v entry: %w", err)
	}
	return nil
}

// DeleteDx2vVlan deletes a VLAN cross-connect entry from dx2v_map
func (m *MapOperations) DeleteDx2vVlan(tableID, vlanID uint16) error {
	key := &Dx2vKey{TableId: tableID, VlanId: vlanID}
	if err := m.objs.Dx2vMap.Delete(key); err != nil {
		return fmt.Errorf("failed to delete dx2v entry: %w", err)
	}
	return nil
}

// ListDx2vVlan lists all VLAN cross-connect entries
func (m *MapOperations) ListDx2vVlan() (map[Dx2vKey]*Dx2vEntry, error) {
	result := make(map[Dx2vKey]*Dx2vEntry)
	var key Dx2vKey
	var entry Dx2vEntry
	iter := m.objs.Dx2vMap.Iterate()
	for iter.Next(&key, &entry) {
		entryCopy := entry
		result[key] = &entryCopy
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate dx2v map: %w", err)
	}
	return result, nil
}

// AgedFdbEntry identifies an FDB entry the ager removed, so the EVPN
// auto-advertise path can withdraw its RT2. IsRemote distinguishes a
// locally-learned MAC (advertised as RT2) from an EVPN-received one (never
// advertised), so the caller only withdraws what it originated.
type AgedFdbEntry struct {
	BDID     uint16
	MAC      net.HardwareAddr
	IsRemote bool
}

// AgeFdbEntries deletes dynamic FDB entries older than maxAgeNs nanoseconds.
// Static entries (is_static=1) and entries with last_seen=0 are never aged out.
// It returns the entries actually deleted so the caller can withdraw their RT2
// advertisements; len() is the number deleted.
func (m *MapOperations) AgeFdbEntries(maxAgeNs uint64) ([]AgedFdbEntry, error) {
	var key FdbKey
	var entry FdbEntry
	iter := m.objs.FdbMap.Iterate()

	now := currentKtimeNs()
	type candidate struct {
		key      FdbKey
		isRemote bool
	}
	var toDelete []candidate
	for iter.Next(&key, &entry) {
		if entry.IsStatic != 0 || entry.LastSeen == 0 {
			continue
		}
		if entry.LastSeen > now {
			continue // clock skew or corruption
		}
		age := now - entry.LastSeen
		if age > maxAgeNs {
			toDelete = append(toDelete, candidate{key: key, isRemote: entry.IsRemote != 0})
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate fdb map: %w", err)
	}

	deleted := make([]AgedFdbEntry, 0, len(toDelete))
	for _, c := range toDelete {
		k := c.key
		if err := m.objs.FdbMap.Delete(&k); err == nil {
			deleted = append(deleted, AgedFdbEntry{
				BDID:     k.BdId,
				MAC:      net.HardwareAddr(append([]byte(nil), k.Mac[:]...)),
				IsRemote: c.isRemote,
			})
		}
	}
	return deleted, nil
}

// currentKtimeNs reads CLOCK_MONOTONIC to match bpf_ktime_get_ns()
func currentKtimeNs() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}

// ===== BD Peer Map Operations (for P2MP BUM flooding) =====

// CreateBdPeer adds a BD peer entry for BUM flooding. It also populates
// bd_peer_l2_ext_map (TX split-horizon path) and, when writeReverse is true,
// bd_peer_reverse_map (RX split-horizon + remote-MAC learning).
//
// esi is the 10-byte RFC 7432 Ethernet Segment Identifier; all-zero means
// single-homing. remoteSrc is the advertising PE's encap source -- the outer
// IPv6 source on its transmitted packets -- which is what the End.DT2 RX path
// keys the reverse map on; it differs from entry.SrcAddr (THIS PE's local TX
// source). writeReverse must be true only for the unicast peer toward a remote
// PE (RT2 End.DT2U and operator-created peers): the reverse map is index-less,
// so one PE maps to one reverse entry, and the RT3 End.DT2M BUM peer toward the
// same PE must pass false so it does not clobber that entry (the RX path needs
// the unicast peer).
func (m *MapOperations) CreateBdPeer(bdID, index uint16, entry *HeadendEntry, esi [ESILen]byte, remoteSrc [IPv6AddrLen]byte, writeReverse bool) error {
	key := &BdPeerKey{BdId: bdID, Index: index}
	if err := m.objs.BdPeerMap.Put(key, entry); err != nil {
		return fmt.Errorf("failed to put bd peer entry: %w", err)
	}

	var rKey *BdPeerReverseKey
	if writeReverse {
		rKey = &BdPeerReverseKey{BdId: bdID}
		copy(rKey.SrcAddr[:], remoteSrc[:])
		rVal := &BdPeerReverseVal{Index: index, Esi: esi}
		if err := m.objs.BdPeerReverseMap.Put(rKey, rVal); err != nil {
			// Roll back the forward entry: a half-installed peer would orphan a
			// bd_peer slot (FindFreeBdPeerIndex skips it forever) and leave the
			// map inconsistent with the applier ledger.
			_ = m.objs.BdPeerMap.Delete(key)
			return fmt.Errorf("failed to put bd peer reverse entry: %w", err)
		}
	}

	var zero [ESILen]byte
	extKey := &BpfBdPeerL2ExtKey{BdId: bdID, Index: index}
	if esi != zero {
		ext := &BpfBdPeerL2ExtVal{Esi: esi}
		if err := m.objs.BdPeerL2ExtMap.Put(extKey, ext); err != nil {
			// Roll back the forward (and reverse, if written) entries so the
			// slot is not orphaned by a partial install.
			_ = m.objs.BdPeerMap.Delete(key)
			if rKey != nil {
				_ = m.objs.BdPeerReverseMap.Delete(rKey)
			}
			return fmt.Errorf("failed to put bd peer L2 ESI ext: %w", err)
		}
	} else {
		_ = m.objs.BdPeerL2ExtMap.Delete(extKey)
	}

	return nil
}

// DeleteBdPeer removes a BD peer entry and its reverse-map entry. The reverse
// map is keyed by the remote PE source (not the index), and the forward entry
// no longer carries it, so the matching reverse entry is found by scanning for
// the one pointing at this index (a BD holds at most MAX_BUM_NEXTHOPS peers).
// Deletes the forward map first to avoid inconsistency if reverse delete fails.
func (m *MapOperations) DeleteBdPeer(bdID, index uint16) error {
	key := &BdPeerKey{BdId: bdID, Index: index}
	if err := m.objs.BdPeerMap.Delete(key); err != nil {
		return fmt.Errorf("failed to delete bd peer entry: %w", err)
	}

	// Find and delete the matching reverse entry. The reverse map is keyed by
	// the remote PE source, not the index, so it is scanned for the one pointing
	// at this index (a BD holds at most MAX_BUM_NEXTHOPS peers, so the scan is
	// bounded). iter.Err() is checked so a truncated scan -- which could leave a
	// stale reverse entry that misroutes the RX split-horizon -- surfaces instead
	// of being silently swallowed.
	var rKey BdPeerReverseKey
	var rVal BdPeerReverseVal
	iter := m.objs.BdPeerReverseMap.Iterate()
	for iter.Next(&rKey, &rVal) {
		if rKey.BdId == bdID && rVal.Index == index {
			k := rKey
			_ = m.objs.BdPeerReverseMap.Delete(&k)
			break
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("scan bd peer reverse map for {bd %d, index %d}: %w", bdID, index, err)
	}
	_ = m.objs.BdPeerL2ExtMap.Delete(&BpfBdPeerL2ExtKey{BdId: bdID, Index: index})
	return nil
}

// GetBdPeer retrieves a BD peer entry
func (m *MapOperations) GetBdPeer(bdID, index uint16) (*HeadendEntry, error) {
	key := &BdPeerKey{BdId: bdID, Index: index}
	var entry HeadendEntry
	if err := m.objs.BdPeerMap.Lookup(key, &entry); err != nil {
		return nil, fmt.Errorf("failed to lookup bd peer entry: %w", err)
	}
	return &entry, nil
}

// FindFreeBdPeerIndex probes indexes 0..MaxBumNexthops-1 for a given BD
// and returns the first unused index. Returns MaxBumNexthops if all slots are occupied.
// This avoids iterating the entire bd_peer_map (ListBdPeers) on every create request.
func (m *MapOperations) FindFreeBdPeerIndex(bdID uint16) uint16 {
	var entry HeadendEntry
	for i := uint16(0); i < MaxBumNexthops; i++ {
		key := &BdPeerKey{BdId: bdID, Index: i}
		if err := m.objs.BdPeerMap.Lookup(key, &entry); err != nil {
			return i
		}
	}
	return MaxBumNexthops
}

// ListBdPeers returns all BD peer entries
func (m *MapOperations) ListBdPeers() (map[BdPeerKey]*HeadendEntry, error) {
	result := make(map[BdPeerKey]*HeadendEntry)
	var key BdPeerKey
	var entry HeadendEntry
	iter := m.objs.BdPeerMap.Iterate()
	for iter.Next(&key, &entry) {
		entryCopy := entry
		result[key] = &entryCopy
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate bd peer map: %w", err)
	}
	return result, nil
}

// ===== Flush Operations =====
//
// Each Flush* method removes every entry from its target map in a single
// operation. The two-phase pattern (collect keys then delete) avoids
// mutating the map while iterating, which kernel BPF map iterators do
// not guarantee safety for. Partial failures return the count of
// entries already deleted plus an error so the caller can log progress.

// flushKeys deletes the listed prefixes from one of the main LPM maps.
// When scope is non-empty, entries whose recorded owner differs are
// skipped (owner-scoped flush). When scope is empty every entry is
// deleted with force=true to bypass the owner check; this is the
// "drop everything" mode kept for migrations and operator escape hatches.
// The two-pass shape (list, then delete) mirrors the existing
// non-owner-aware flush and keeps the kernel BPF iterator from observing
// mutations mid-traversal.
// flushScoped deletes only the prefixes recorded under scope.
// Cross-owner entries surface as ErrEntryOwnerMismatch from deleteOne and
// are treated as skips; any other error halts the flush and returns the
// partial count so the caller can log progress.
func flushScoped[E any](
	entries map[string]*E,
	scope OwnerTag,
	deleteOne func(prefix string, requester OwnerTag) error,
	label string,
) (uint32, error) {
	var count uint32
	for prefix := range entries {
		if err := deleteOne(prefix, scope); err != nil {
			if errors.Is(err, ErrEntryOwnerMismatch) {
				continue
			}
			return count, fmt.Errorf("flush %s: delete %q: %w", label, prefix, err)
		}
		count++
	}
	return count, nil
}

// flushForce deletes every prefix unconditionally. Any error halts and
// returns the partial count.
func flushForce[E any](
	entries map[string]*E,
	deleteOne func(prefix string) error,
	label string,
) (uint32, error) {
	var count uint32
	for prefix := range entries {
		if err := deleteOne(prefix); err != nil {
			return count, fmt.Errorf("flush %s: delete %q: %w", label, prefix, err)
		}
		count++
	}
	return count, nil
}

// FlushSidFunctions removes SID function entries whose owner matches
// scope. scope must be non-empty; use ForceFlushSidFunctions to drop
// every entry regardless of owner.
func (m *MapOperations) FlushSidFunctions(scope OwnerTag) (uint32, error) {
	if scope == "" {
		return 0, fmt.Errorf("FlushSidFunctions: scope must be non-empty; use ForceFlushSidFunctions for unconditional flush")
	}
	entries, err := m.ListSidFunctions()
	if err != nil {
		return 0, err
	}
	return flushScoped(entries, scope, m.DeleteSidFunction, "sid_function")
}

// ForceFlushSidFunctions removes every SID function entry regardless of
// owner. Reserved for operator escape hatches; the everyday flush path
// (RPC and BGP) scopes by owner via FlushSidFunctions.
func (m *MapOperations) ForceFlushSidFunctions() (uint32, error) {
	entries, err := m.ListSidFunctions()
	if err != nil {
		return 0, err
	}
	return flushForce(entries, m.ForceDeleteSidFunction, "sid_function")
}

// FlushHeadendV4 removes headend_v4 entries whose owner matches scope.
// scope must be non-empty; use ForceFlushHeadendV4 to drop every entry.
func (m *MapOperations) FlushHeadendV4(scope OwnerTag) (uint32, error) {
	if scope == "" {
		return 0, fmt.Errorf("FlushHeadendV4: scope must be non-empty; use ForceFlushHeadendV4 for unconditional flush")
	}
	entries, err := m.ListHeadendV4()
	if err != nil {
		return 0, err
	}
	return flushScoped(entries, scope, m.DeleteHeadendV4, "headend_v4")
}

// ForceFlushHeadendV4 removes every headend_v4 entry regardless of owner.
func (m *MapOperations) ForceFlushHeadendV4() (uint32, error) {
	entries, err := m.ListHeadendV4()
	if err != nil {
		return 0, err
	}
	return flushForce(entries, m.ForceDeleteHeadendV4, "headend_v4")
}

// FlushHeadendV6 removes headend_v6 entries whose owner matches scope.
// scope must be non-empty; use ForceFlushHeadendV6 to drop every entry.
func (m *MapOperations) FlushHeadendV6(scope OwnerTag) (uint32, error) {
	if scope == "" {
		return 0, fmt.Errorf("FlushHeadendV6: scope must be non-empty; use ForceFlushHeadendV6 for unconditional flush")
	}
	entries, err := m.ListHeadendV6()
	if err != nil {
		return 0, err
	}
	return flushScoped(entries, scope, m.DeleteHeadendV6, "headend_v6")
}

// ForceFlushHeadendV6 removes every headend_v6 entry regardless of owner.
func (m *MapOperations) ForceFlushHeadendV6() (uint32, error) {
	entries, err := m.ListHeadendV6()
	if err != nil {
		return 0, err
	}
	return flushForce(entries, m.ForceDeleteHeadendV6, "headend_v6")
}

// FlushHeadendL2 removes every headend_l2 entry.
func (m *MapOperations) FlushHeadendL2() (uint32, error) {
	entries, err := m.ListHeadendL2()
	if err != nil {
		return 0, err
	}
	var count uint32
	for key := range entries {
		if err := m.DeleteHeadendL2(key.Ifindex, key.VlanId); err != nil {
			return count, fmt.Errorf("flush headend_l2: delete ifindex=%d vlan=%d: %w",
				key.Ifindex, key.VlanId, err)
		}
		count++
	}
	return count, nil
}

// FlushFdb removes FDB entries, optionally scoped to a single BD and
// optionally keeping user-configured static entries. bdID == 0 means
// all BDs; keepStatic == true skips entries with IsStatic != 0.
func (m *MapOperations) FlushFdb(bdID uint16, keepStatic bool) (uint32, error) {
	entries, err := m.ListFdb()
	if err != nil {
		return 0, err
	}
	var count uint32
	for key, entry := range entries {
		if bdID != 0 && key.BdId != bdID {
			continue
		}
		if keepStatic && entry.IsStatic != 0 {
			continue
		}
		mac := net.HardwareAddr(key.Mac[:])
		if err := m.DeleteFdb(key.BdId, mac); err != nil {
			return count, fmt.Errorf("flush fdb: delete bd=%d mac=%s: %w",
				key.BdId, mac, err)
		}
		count++
	}
	return count, nil
}

// FlushBdPeers removes BD peer entries, optionally scoped to a single BD.
// bdID == 0 means all BDs. The companion reverse-map entries are cleaned
// up transitively via DeleteBdPeer.
func (m *MapOperations) FlushBdPeers(bdID uint16) (uint32, error) {
	entries, err := m.ListBdPeers()
	if err != nil {
		return 0, err
	}
	var count uint32
	for key := range entries {
		if bdID != 0 && key.BdId != bdID {
			continue
		}
		if err := m.DeleteBdPeer(key.BdId, key.Index); err != nil {
			return count, fmt.Errorf("flush bd_peer: delete bd=%d idx=%d: %w",
				key.BdId, key.Index, err)
		}
		count++
	}
	return count, nil
}

// FlushVlanTable removes dx2v entries, optionally scoped to a single
// table. tableID == 0 means all tables.
func (m *MapOperations) FlushVlanTable(tableID uint16) (uint32, error) {
	entries, err := m.ListDx2vVlan()
	if err != nil {
		return 0, err
	}
	var count uint32
	for key := range entries {
		if tableID != 0 && key.TableId != tableID {
			continue
		}
		if err := m.DeleteDx2vVlan(key.TableId, key.VlanId); err != nil {
			return count, fmt.Errorf("flush dx2v: delete table=%d vlan=%d: %w",
				key.TableId, key.VlanId, err)
		}
		count++
	}
	return count, nil
}

// ===== Helper Functions =====

func buildLpmKeyV4(cidr string) (*LpmKeyV4, error) {
	ip, prefixLen, err := ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("not an IPv4 address: %s", cidr)
	}

	key := &LpmKeyV4{
		Prefixlen: uint32(prefixLen),
	}
	copy(key.Addr[:], ip4)
	return key, nil
}

func buildLpmKeyV6(cidr string) (*LpmKeyV6, error) {
	ip, prefixLen, err := ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ip6 := ip.To16()
	if ip6 == nil {
		return nil, fmt.Errorf("not an IPv6 address: %s", cidr)
	}

	key := &LpmKeyV6{
		Prefixlen: uint32(prefixLen),
	}
	copy(key.Addr[:], ip6)
	return key, nil
}

func lpmKeyV4ToString(key *LpmKeyV4) string {
	ip := net.IP(key.Addr[:])
	return fmt.Sprintf("%s/%d", ip.String(), key.Prefixlen)
}

func lpmKeyV6ToString(key *LpmKeyV6) string {
	ip := net.IP(key.Addr[:])
	return fmt.Sprintf("%s/%d", ip.String(), key.Prefixlen)
}

func buildHeadendL2Key(ifindex uint32, vlanID uint16) *HeadendL2Key {
	return &HeadendL2Key{
		Ifindex: ifindex,
		VlanId:  vlanID,
	}
}

func buildFdbKey(bdID uint16, mac net.HardwareAddr) *FdbKey {
	key := &FdbKey{BdId: bdID}
	copy(key.Mac[:], mac)
	return key
}

// ParseSegments parses a list of segment strings into the Segments array
func ParseSegments(segments []string) ([MaxSegments][IPv6AddrLen]uint8, uint8, error) {
	var result [MaxSegments][IPv6AddrLen]uint8

	if len(segments) > MaxSegments {
		return result, 0, fmt.Errorf("too many segments: %d (max %d)", len(segments), MaxSegments)
	}

	for i, seg := range segments {
		addr, err := ParseIPv6(seg)
		if err != nil {
			return result, 0, fmt.Errorf("invalid segment %d: %w", i, err)
		}
		result[i] = addr
	}

	return result, uint8(len(segments)), nil
}

// FormatIPv6 formats a byte array as an IPv6 address string
func FormatIPv6(addr [IPv6AddrLen]uint8) string {
	ip := net.IP(addr[:])
	return ip.String()
}

// ParseIPv4Optional parses an IPv4 address string into a 4-byte array.
// Returns zero array if addr is empty (optional field).
func ParseIPv4Optional(addr string) ([IPv4AddrLen]uint8, error) {
	var result [IPv4AddrLen]uint8
	if addr == "" {
		return result, nil
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return result, fmt.Errorf("invalid IPv4 address: %s", addr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return result, fmt.Errorf("not an IPv4 address: %s", addr)
	}
	copy(result[:], ip4)
	return result, nil
}

// FormatIPv4Optional formats a 4-byte array as an IPv4 address string.
// Returns empty string if all bytes are zero.
func FormatIPv4Optional(addr [IPv4AddrLen]uint8) string {
	if addr == [IPv4AddrLen]uint8{} {
		return ""
	}
	return net.IP(addr[:]).String()
}

// FormatSegments formats the segments array as a string slice
func FormatSegments(segments [MaxSegments][IPv6AddrLen]uint8, numSegments uint8) []string {
	result := make([]string, 0, numSegments)
	for i := uint8(0); i < numSegments; i++ {
		result = append(result, FormatIPv6(segments[i]))
	}
	return result
}

// GetSharedReadOnlyMaps returns BPF maps that vinbero manages and plugins may
// only read. Writes from a plugin into one of these maps will be flagged by the
// validator escalates these into a load-time error when ro_enforce is on;
// otherwise the violation is logged and the load proceeds.
func (m *MapOperations) GetSharedReadOnlyMaps() map[string]*ebpf.Map {
	return map[string]*ebpf.Map{
		"sid_function_map":         m.objs.SidFunctionMap,
		"sid_aux_map":              m.objs.SidAuxMap,
		"headend_v4_map":           m.objs.HeadendV4Map,
		"headend_v6_map":           m.objs.HeadendV6Map,
		"mup_uplink_v4_map":        m.objs.MupUplinkV4Map,
		"mup_uplink_v6_map":        m.objs.MupUplinkV6Map,
		"mup_ifindex_instance_map": m.objs.MupIfindexInstanceMap,
		"headend_l2_map":           m.objs.HeadendL2Map,
		"fdb_map":                  m.objs.FdbMap,
		"bd_peer_map":              m.objs.BdPeerMap,
		"bd_peer_reverse_map":      m.objs.BdPeerReverseMap,
		"esi_map":                  m.objs.EsiMap,
		"bd_peer_l2_ext_map":       m.objs.BdPeerL2ExtMap,
		"headend_l2_ext_map":       m.objs.HeadendL2ExtMap,
		"bd_local_esi_map":         m.objs.BdLocalEsiMap,
		"dx2v_map":                 m.objs.Dx2vMap,
		"tailcall_ctx_map":         m.objs.TailcallCtxMap,
	}
}

// GetSharedReadWriteMaps returns BPF maps plugins may write to (or that are
// logically vinbero-managed but the kernel verifier requires write access for
// normal operation — stats counters, scratch buffers, PROG_ARRAY dispatch).
// slot_stats_* are written from tailcall_epilogue on behalf of the plugin, so
// they need to appear writable to the plugin ELF at verification time.
func (m *MapOperations) GetSharedReadWriteMaps() map[string]*ebpf.Map {
	return map[string]*ebpf.Map{
		"scratch_map":           m.objs.ScratchMap,
		"stats_map":             m.objs.StatsMap,
		"slot_stats_endpoint":   m.objs.SlotStatsEndpoint,
		"slot_stats_headend_v4": m.objs.SlotStatsHeadendV4,
		"slot_stats_headend_v6": m.objs.SlotStatsHeadendV6,
		"slot_stats_headend_l2": m.objs.SlotStatsHeadendL2,
		MapNameSidEndpointProgs: m.objs.SidEndpointProgs,
		MapNameHeadendV4Progs:   m.objs.HeadendV4Progs,
		MapNameHeadendV6Progs:   m.objs.HeadendV6Progs,
		MapNameHeadendL2Progs:   m.objs.HeadendL2Progs,
	}
}

// SharedReadOnlyMapNames returns the names of every shared map that vinbero
// treats as plugin-readable but not plugin-writable. The list mirrors
// GetSharedReadOnlyMaps; TestSharedMapPartitioning enforces the invariant
// so the asm-level RO write enforcer in the validator keeps in sync with
// the runtime classification.
//
// Used by callers (notably `vbctl plugin validate`) that want the RO set
// without instantiating MapOperations against a live BPF object.
func SharedReadOnlyMapNames() []string {
	return []string{
		"sid_function_map",
		"sid_aux_map",
		"headend_v4_map",
		"headend_v6_map",
		"mup_uplink_v4_map",
		"mup_uplink_v6_map",
		"mup_ifindex_instance_map",
		"headend_l2_map",
		"fdb_map",
		"bd_peer_map",
		"bd_peer_reverse_map",
		"esi_map",
		"bd_peer_l2_ext_map",
		"headend_l2_ext_map",
		"bd_local_esi_map",
		"dx2v_map",
		"tailcall_ctx_map",
	}
}

// SharedReadWriteMapNames returns the names of every shared map plugins may
// write to (or that the kernel verifier needs writable for normal operation).
// Mirrors GetSharedReadWriteMaps; same partitioning invariant applies.
func SharedReadWriteMapNames() []string {
	return []string{
		"scratch_map",
		"stats_map",
		"slot_stats_endpoint",
		"slot_stats_headend_v4",
		"slot_stats_headend_v6",
		"slot_stats_headend_l2",
		MapNameSidEndpointProgs,
		MapNameHeadendV4Progs,
		MapNameHeadendV6Progs,
		MapNameHeadendL2Progs,
	}
}

// SharedReadOnlyMapNamesSet returns SharedReadOnlyMapNames in set form so
// the validator can do O(1) membership tests without rebuilding a map per
// plugin.
func SharedReadOnlyMapNamesSet() map[string]struct{} {
	out := make(map[string]struct{}, 16)
	for _, n := range SharedReadOnlyMapNames() {
		out[n] = struct{}{}
	}
	return out
}

// ========== Plugin Registration ==========

const (
	EndpointPluginBase = 32
	EndpointProgMax    = 64
	HeadendPluginBase  = 16
	HeadendProgMax     = 32
)

// PluginMapType identifiers accepted by RegisterPlugin / UnregisterPlugin.
const (
	MapTypeEndpoint  = "endpoint"
	MapTypeHeadendV4 = "headend_v4"
	MapTypeHeadendV6 = "headend_v6"
	MapTypeHeadendL2 = "headend_l2"
)

// BPF map names for vinbero-managed PROG_ARRAYs. Referenced by the shared-map
// getters, resolvePluginMap, and the plugin validator's tail-call whitelist.
const (
	MapNameSidEndpointProgs = "sid_endpoint_progs"
	MapNameHeadendV4Progs   = "headend_v4_progs"
	MapNameHeadendV6Progs   = "headend_v6_progs"
	MapNameHeadendL2Progs   = "headend_l2_progs"
)

var (
	ErrReservedSlot = fmt.Errorf("cannot register plugin in reserved slot")
	ErrIndexTooHigh = fmt.Errorf("plugin index exceeds PROG_ARRAY capacity")
)

// PluginSlotRange returns the [base, max) plugin slot range for the given
// map_type, or an error if map_type is unknown. Single source of truth for
// "what counts as a plugin slot" — RegisterPlugin / UnregisterPlugin and the
// PluginAux RPC validators all derive from this.
func PluginSlotRange(mapType string) (base, max uint32, err error) {
	switch mapType {
	case MapTypeEndpoint:
		return EndpointPluginBase, EndpointProgMax, nil
	case MapTypeHeadendV4, MapTypeHeadendV6, MapTypeHeadendL2:
		return HeadendPluginBase, HeadendProgMax, nil
	default:
		return 0, 0, fmt.Errorf("unknown map_type %q (expected endpoint / headend_v4 / headend_v6 / headend_l2)", mapType)
	}
}

// ValidatePluginSlot rejects (map_type, slot) pairs that fall outside a plugin
// PROG_ARRAY range. Errors wrap ErrReservedSlot (slot below base, would step on
// builtin behaviors) or ErrIndexTooHigh (slot at or above the array capacity).
func ValidatePluginSlot(mapType string, slot uint32) error {
	base, max, err := PluginSlotRange(mapType)
	if err != nil {
		return err
	}
	if slot < base {
		return fmt.Errorf("%w: index %d < base %d for %s", ErrReservedSlot, slot, base, mapType)
	}
	if slot >= max {
		return fmt.Errorf("%w: index %d >= max %d for %s", ErrIndexTooHigh, slot, max, mapType)
	}
	return nil
}

// RegisterPlugin registers an external BPF program into a PROG_ARRAY slot.
// Only plugin-range indices are allowed (built-in slots are protected).
func (m *MapOperations) RegisterPlugin(mapType string, index uint32, progFD int) error {
	if err := ValidatePluginSlot(mapType, index); err != nil {
		return err
	}
	targetMap, _, _, err := m.resolvePluginMap(mapType)
	if err != nil {
		return err
	}
	return targetMap.Update(index, uint32(progFD), ebpf.UpdateAny)
}

// UnregisterPlugin removes a plugin from a PROG_ARRAY slot.
func (m *MapOperations) UnregisterPlugin(mapType string, index uint32) error {
	if err := ValidatePluginSlot(mapType, index); err != nil {
		return err
	}
	targetMap, _, _, err := m.resolvePluginMap(mapType)
	if err != nil {
		return err
	}
	return targetMap.Delete(index)
}

func (m *MapOperations) resolvePluginMap(mapType string) (*ebpf.Map, uint32, uint32, error) {
	switch mapType {
	case MapTypeEndpoint:
		return m.objs.SidEndpointProgs, EndpointPluginBase, EndpointProgMax, nil
	case MapTypeHeadendV4:
		return m.objs.HeadendV4Progs, HeadendPluginBase, HeadendProgMax, nil
	case MapTypeHeadendV6:
		return m.objs.HeadendV6Progs, HeadendPluginBase, HeadendProgMax, nil
	case MapTypeHeadendL2:
		return m.objs.HeadendL2Progs, HeadendPluginBase, HeadendProgMax, nil
	default:
		return nil, 0, 0, fmt.Errorf("unknown plugin map type: %s", mapType)
	}
}

// BdPeerEsiKey identifies a (BD, src_addr) pair for the caller-side
// ESI lookup table returned by ListBdPeerEsi.
type BdPeerEsiKey struct {
	BdId    uint16
	SrcAddr [IPv6AddrLen]uint8
}

// ListBdPeerEsi returns a per-peer ESI table built from bd_peer_reverse_map.
func (m *MapOperations) ListBdPeerEsi() (map[BdPeerEsiKey][ESILen]byte, error) {
	result := make(map[BdPeerEsiKey][ESILen]byte)
	var key BdPeerReverseKey
	var val BdPeerReverseVal
	iter := m.objs.BdPeerReverseMap.Iterate()
	for iter.Next(&key, &val) {
		k := BdPeerEsiKey{BdId: key.BdId}
		copy(k.SrcAddr[:], key.SrcAddr[:])
		result[k] = val.Esi
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate bd_peer_reverse_map: %w", err)
	}
	return result, nil
}

// ===== Ethernet Segment (ESI) Map Operations =====

// EsiConfig is the user-facing description of an Ethernet Segment. NewEsiEntry
// packs it into the BPF-side EsiEntry (handling the bool→uint8 flag).
type EsiConfig struct {
	LocalAttached  bool
	RedundancyMode uint8 // zero = UNSPECIFIED
	LocalPeSrcAddr [IPv6AddrLen]byte
	DfPeSrcAddr    [IPv6AddrLen]byte
}

// NewEsiEntry builds an EsiEntry from user-facing fields.
func NewEsiEntry(cfg EsiConfig) *EsiEntry {
	e := &EsiEntry{RedundancyMode: cfg.RedundancyMode}
	if cfg.LocalAttached {
		e.LocalAttached = 1
	}
	e.DfPeSrcAddr = cfg.DfPeSrcAddr
	e.LocalPeSrcAddr = cfg.LocalPeSrcAddr
	return e
}

// IsLocalAttached reports whether this PE attaches to the ES.
func (e *EsiEntry) IsLocalAttached() bool { return e.LocalAttached != 0 }

// ParseESI decodes a colon-separated 10-byte ESI string (e.g., "00:11:22:33:44:55:66:77:88:99")
// into a fixed-size array. Empty string returns all-zero ESI (single-homing sentinel),
// which is accepted by BdPeer callers but rejected by CreateEsi.
func ParseESI(s string) ([ESILen]byte, error) {
	var out [ESILen]byte
	if s == "" {
		return out, nil
	}
	// net.ParseMAC only accepts 6/8/20-byte MACs, so roll our own fixed-width parser.
	hw, err := parseColonHex(s, ESILen)
	if err != nil {
		return out, fmt.Errorf("ESI: %w", err)
	}
	copy(out[:], hw)
	return out, nil
}

// FormatESI encodes a 10-byte ESI as colon-separated hex. All-zero returns ""
// so BdPeer/FdbEntry proto responses surface the "single-homing" case as empty.
func FormatESI(esi [ESILen]byte) string {
	var zero [ESILen]byte
	if esi == zero {
		return ""
	}
	return net.HardwareAddr(esi[:]).String()
}

// parseColonHex decodes a "xx:xx:..." colon-separated hex string of exactly
// n bytes. A small generalisation point so ESI and any future colon-hex
// identifiers can share it.
func parseColonHex(s string, n int) ([]byte, error) {
	parts := strings.Split(s, ":")
	if len(parts) != n {
		return nil, fmt.Errorf("must have %d colon-separated bytes, got %d", n, len(parts))
	}
	out := make([]byte, n)
	for i, p := range parts {
		if len(p) == 0 || len(p) > 2 {
			return nil, fmt.Errorf("byte[%d]=%q: invalid length", i, p)
		}
		var b byte
		for _, c := range p {
			var nib byte
			switch {
			case c >= '0' && c <= '9':
				nib = byte(c - '0')
			case c >= 'a' && c <= 'f':
				nib = byte(c-'a') + 10
			case c >= 'A' && c <= 'F':
				nib = byte(c-'A') + 10
			default:
				return nil, fmt.Errorf("byte[%d]=%q: non-hex character", i, p)
			}
			b = b<<4 | nib
		}
		out[i] = b
	}
	return out, nil
}

// CreateEsi upserts an Ethernet Segment entry into esi_map.
// All-zero ESI is rejected — it is reserved as the single-homing sentinel.
func (m *MapOperations) CreateEsi(esi [ESILen]byte, entry *EsiEntry) error {
	var zero [ESILen]byte
	if esi == zero {
		return fmt.Errorf("all-zero ESI is reserved as single-homing sentinel")
	}
	key := &EsiKey{Esi: esi}
	if err := m.objs.EsiMap.Put(key, entry); err != nil {
		return fmt.Errorf("failed to put esi entry: %w", err)
	}
	return nil
}

// DeleteEsi removes an Ethernet Segment entry by ESI.
func (m *MapOperations) DeleteEsi(esi [ESILen]byte) error {
	key := &EsiKey{Esi: esi}
	if err := m.objs.EsiMap.Delete(key); err != nil {
		return fmt.Errorf("failed to delete esi entry: %w", err)
	}
	return nil
}

// GetEsi looks up an Ethernet Segment entry.
func (m *MapOperations) GetEsi(esi [ESILen]byte) (*EsiEntry, error) {
	key := &EsiKey{Esi: esi}
	var entry EsiEntry
	if err := m.objs.EsiMap.Lookup(key, &entry); err != nil {
		return nil, fmt.Errorf("failed to lookup esi entry: %w", err)
	}
	return &entry, nil
}

// SetEsiDfPe replaces the df_pe_src_addr of an existing ES. Pass an all-zero
// dfAddr to clear the DF. Returns ErrKeyNotExist if the ESI isn't registered.
func (m *MapOperations) SetEsiDfPe(esi [ESILen]byte, dfAddr [IPv6AddrLen]byte) (*EsiEntry, error) {
	entry, err := m.GetEsi(esi)
	if err != nil {
		return nil, err
	}
	entry.DfPeSrcAddr = dfAddr
	key := &EsiKey{Esi: esi}
	if err := m.objs.EsiMap.Put(key, entry); err != nil {
		return nil, fmt.Errorf("failed to update esi entry: %w", err)
	}
	return entry, nil
}

// ListEsi returns all Ethernet Segment entries keyed by ESI.
func (m *MapOperations) ListEsi() (map[[ESILen]byte]*EsiEntry, error) {
	result := make(map[[ESILen]byte]*EsiEntry)
	var key EsiKey
	var entry EsiEntry
	iter := m.objs.EsiMap.Iterate()
	for iter.Next(&key, &entry) {
		entryCopy := entry
		result[key.Esi] = &entryCopy
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate esi map: %w", err)
	}
	return result, nil
}

// CountAuxByOwner returns the number of live aux indices currently owned
// by ownerTag. Used by PluginUnregister to surface orphan plugin aux
// (indices that should have been freed via PluginAuxFree before the slot
// was retired). Stale lookups are unavoidable — the answer can change as
// soon as the lock is released.
func (m *MapOperations) CountAuxByOwner(ownerTag string) int {
	return m.auxAlloc.countByOwner(ownerTag)
}

// FreeAllByOwner zero-writes sid_aux_map for every index owned by
// ownerTag and releases those indices in the allocator. Returns the
// number of indices that were freed. Used by PluginAuxPurge after a slot
// has been retired with PluginUnregister to clean up indices that the
// plugin failed to release through PluginAuxFree.
//
// Errors on the BPF zero-write are best-effort: the allocator slot is
// still released so a subsequent alloc can reuse the index. The
// per-index error path mirrors freeOwnerLocked's "advance regardless"
// stance for exactly the same ABA-avoidance reason.
func (m *MapOperations) FreeAllByOwner(ownerTag string) int {
	// Snapshot first so the zero-write + free per index can run outside a
	// shared critical section. Each index is then released through the
	// same WithOwnerLocked path the per-RPC FreePluginAux uses, so any
	// concurrent FreeOwner that races us shows up as ErrOwnerMismatch on
	// the loser and the slot is freed exactly once.
	idxs := m.auxAlloc.snapshotByOwner(ownerTag)
	freed := 0
	for _, idx := range idxs {
		if err := m.FreePluginAux(idx, ownerTag); err == nil {
			freed++
		}
	}
	return freed
}

// snapshotByOwner returns a copy of every index currently tagged with
// ownerTag. Lock is taken just long enough to copy; the returned slice
// is safe to consult outside the allocator mutex.
func (a *indexAllocator) snapshotByOwner(ownerTag string) []uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]uint32, 0, len(a.owners))
	for idx, owner := range a.owners {
		if owner == ownerTag {
			out = append(out, idx)
		}
	}
	return out
}

// countByOwner is the locked underpinning of CountAuxByOwner.
func (a *indexAllocator) countByOwner(ownerTag string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, o := range a.owners {
		if o == ownerTag {
			n++
		}
	}
	return n
}
