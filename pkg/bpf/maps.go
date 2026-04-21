package bpf

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
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
)

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
}

// NewMapOperations creates a new MapOperations instance.
// The aux index allocator capacity is derived from the actual sid_aux_map MaxEntries.
func NewMapOperations(objs *BpfObjects) *MapOperations {
	auxMax := uint32(512) // fallback
	if info, err := objs.SidAuxMap.Info(); err == nil {
		auxMax = info.MaxEntries
	}
	return &MapOperations{
		objs:     objs,
		auxAlloc: newIndexAllocator(auxMax),
	}
}

// AuxOwnerBuiltin tags aux indices that belong to vinbero-managed SID
// behaviors (End.X / End.DT2 / End.B6 / etc.). Plugin-owned indices use
// AuxOwnerPluginTag with (mapType, slot).
const AuxOwnerBuiltin = "builtin"

// AuxOwnerPluginTag returns the owner tag used for plugin-allocated aux
// indices. Matches the tag PluginAux RPC handlers register at Alloc time.
func AuxOwnerPluginTag(mapType string, slot uint32) string {
	return fmt.Sprintf("plugin:%s:%d", mapType, slot)
}

// ErrOwnerMismatch is returned when FreeOwner / PutPluginAux / GetPluginAux
// / FreePluginAux are called with an owner tag that does not match the tag
// recorded at Alloc time. Guards against a plugin freeing another plugin's
// aux index or a builtin path accidentally stepping on plugin state.
var ErrOwnerMismatch = fmt.Errorf("aux owner mismatch")

// indexAllocator manages a pool of uint32 indices with a free-list and an
// owner tag per live index. Index 0 is reserved as the "no aux" sentinel
// used by sid_function_entry.
type indexAllocator struct {
	mu       sync.Mutex
	freeList []uint32
	maxIndex uint32
	nextNew  uint32
	owners   map[uint32]string
}

func newIndexAllocator(max uint32) *indexAllocator {
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
	a.owners[idx] = owner
	return idx, nil
}

// FreeOwner releases idx only if owner matches the tag recorded at Alloc
// time. Mismatched owners return ErrOwnerMismatch and leave the allocator
// state untouched. Freeing an already-free index is also ErrOwnerMismatch.
func (a *indexAllocator) FreeOwner(idx uint32, owner string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	got, ok := a.owners[idx]
	if !ok {
		return fmt.Errorf("%w: index %d is not allocated", ErrOwnerMismatch, idx)
	}
	if got != owner {
		return fmt.Errorf("%w: index %d owned by %q, caller %q",
			ErrOwnerMismatch, idx, got, owner)
	}
	delete(a.owners, idx)
	a.freeList = append(a.freeList, idx)
	return nil
}

// OwnerOf returns the owner tag registered for idx, or "" if idx is free.
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

// RecoverAuxIndices scans sid_function_map for entries with a non-zero
// aux_index and marks those indices as used in the allocator, reconstructing
// owner tags from each entry's action: actions below EndpointPluginBase are
// vinbero-managed (AuxOwnerBuiltin) and the rest are plugin-owned at the
// endpoint PROG_ARRAY slot indicated by action.
//
// Stand-alone plugin aux indices (allocated via PluginAuxAlloc without ever
// binding to a SID function) are NOT recovered: they are not visible from
// sid_function_map. Such indices vanish across process restart — BPF pinning
// would be required to preserve them (Phase 2).
func (m *MapOperations) RecoverAuxIndices() error {
	var key LpmKeyV6
	var entry SidFunctionEntry
	iter := m.objs.SidFunctionMap.Iterate()

	owners := make(map[uint32]string)
	for iter.Next(&key, &entry) {
		if entry.AuxIndex == 0 {
			continue
		}
		idx := uint32(entry.AuxIndex)
		if uint32(entry.Action) >= EndpointPluginBase {
			// endpoint PROG_ARRAY slot == action for plugin behaviors
			owners[idx] = AuxOwnerPluginTag(MapTypeEndpoint, uint32(entry.Action))
		} else {
			owners[idx] = AuxOwnerBuiltin
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to iterate SID function map for recovery: %w", err)
	}

	m.auxAlloc.RecoverWithOwners(owners)
	return nil
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

// NewSidAuxGtp4e creates an aux entry for End.M.GTP4.E
func NewSidAuxGtp4e(argsOffset uint8, gtpV4SrcAddr [IPv4AddrLen]uint8) *SidAuxEntry {
	entry := &SidAuxEntry{}
	entry.Nexthop.Nexthop[0] = argsOffset
	copy(entry.Nexthop.Nexthop[1:5], gtpV4SrcAddr[:])
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
// sid_aux_entry. Writes longer than this are rejected at the RPC layer so
// we never overflow the kernel-side union.
const SidAuxPluginRawMax = 196

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
func SidAuxGtp4eData(entry *SidAuxEntry) (argsOffset uint8, gtpV4SrcAddr [IPv4AddrLen]uint8) {
	argsOffset = entry.Nexthop.Nexthop[0]
	copy(gtpV4SrcAddr[:], entry.Nexthop.Nexthop[1:5])
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

// CreateSidFunction adds a SID function entry and optional aux data.
// If aux is non-nil, an aux index is allocated and both maps are written.
func (m *MapOperations) CreateSidFunction(triggerPrefix string, entry *SidFunctionEntry, aux *SidAuxEntry) error {
	key, err := buildLpmKeyV6(triggerPrefix)
	if err != nil {
		return fmt.Errorf("failed to build LPM key: %w", err)
	}

	if aux != nil {
		idx, err := m.auxAlloc.AllocOwner(AuxOwnerBuiltin)
		if err != nil {
			return fmt.Errorf("failed to allocate aux index: %w", err)
		}
		// sid_function_entry.aux_index is u16; the userspace allocator
		// can in principle hand out higher values if the operator set
		// an sid_aux_map capacity above 65535, which would silently
		// truncate here. Reject before we write the truncated value.
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
	}

	if err := m.objs.SidFunctionMap.Put(key, entry); err != nil {
		if aux != nil {
			_ = m.auxAlloc.FreeOwner(uint32(entry.AuxIndex), AuxOwnerBuiltin)
		}
		return fmt.Errorf("failed to put SID function entry: %w", err)
	}
	return nil
}

// CreateSidFunctionWithAuxIndex creates a SID function entry that references
// an aux index already allocated by PluginAuxAlloc. The caller is responsible
// for writing / freeing the aux entry via the PluginAux RPC path; this
// helper only touches sid_function_map. Intended for action >= plugin base.
func (m *MapOperations) CreateSidFunctionWithAuxIndex(triggerPrefix string, entry *SidFunctionEntry) error {
	if entry.AuxIndex == 0 {
		return fmt.Errorf("aux_index must be non-zero")
	}
	key, err := buildLpmKeyV6(triggerPrefix)
	if err != nil {
		return fmt.Errorf("failed to build LPM key: %w", err)
	}
	if err := m.objs.SidFunctionMap.Put(key, entry); err != nil {
		return fmt.Errorf("failed to put SID function entry: %w", err)
	}
	return nil
}

// AuxOwnerOf returns the owner tag currently registered for idx, or "" if
// idx is not allocated. Used by SidFunction create handlers to verify that a
// supplied plugin_aux_index belongs to the expected plugin slot.
func (m *MapOperations) AuxOwnerOf(idx uint32) string {
	return m.auxAlloc.OwnerOf(idx)
}

// AllocPluginAux reserves an index in the plugin_raw variant of sid_aux_map
// and tags it with owner. The caller must then write content via
// PutPluginAux; allocating and writing are split so a JSON-encode error
// leaves no half-populated entry behind.
func (m *MapOperations) AllocPluginAux(owner string) (uint32, error) {
	return m.auxAlloc.AllocOwner(owner)
}

// PutPluginAux writes raw into sid_aux_map[idx] after verifying owner. raw
// must be <= SidAuxPluginRawMax; shorter payloads are zero-padded on the
// wire. Owner mismatch returns ErrOwnerMismatch and does not touch the map.
func (m *MapOperations) PutPluginAux(idx uint32, raw []byte, owner string) error {
	if got := m.auxAlloc.OwnerOf(idx); got != owner {
		return fmt.Errorf("%w: index %d owned by %q, caller %q",
			ErrOwnerMismatch, idx, got, owner)
	}
	if len(raw) > SidAuxPluginRawMax {
		return fmt.Errorf("raw length %d exceeds SidAuxPluginRawMax (%d)",
			len(raw), SidAuxPluginRawMax)
	}
	entry := NewSidAuxPluginRaw(raw)
	if err := m.objs.SidAuxMap.Put(idx, entry); err != nil {
		return fmt.Errorf("failed to put plugin aux entry: %w", err)
	}
	return nil
}

// GetPluginAux returns the raw bytes stored at idx after verifying owner.
// Returned slice length is always SidAuxPluginRawMax (the on-wire size).
// Owner mismatch returns ErrOwnerMismatch.
func (m *MapOperations) GetPluginAux(idx uint32, owner string) ([]byte, error) {
	if got := m.auxAlloc.OwnerOf(idx); got != owner {
		return nil, fmt.Errorf("%w: index %d owned by %q, caller %q",
			ErrOwnerMismatch, idx, got, owner)
	}
	var entry SidAuxEntry
	if err := m.objs.SidAuxMap.Lookup(idx, &entry); err != nil {
		return nil, fmt.Errorf("failed to look up plugin aux entry: %w", err)
	}
	raw := make([]byte, SidAuxPluginRawMax)
	src := (*[SidAuxPluginRawMax]byte)(unsafe.Pointer(&entry))[:]
	copy(raw, src)
	return raw, nil
}

// FreePluginAux zeroes sid_aux_map[idx] and releases the allocator slot.
// Owner mismatch returns ErrOwnerMismatch; both map and allocator remain
// untouched in that case.
func (m *MapOperations) FreePluginAux(idx uint32, owner string) error {
	if got := m.auxAlloc.OwnerOf(idx); got != owner {
		return fmt.Errorf("%w: index %d owned by %q, caller %q",
			ErrOwnerMismatch, idx, got, owner)
	}
	var zero SidAuxEntry
	if err := m.objs.SidAuxMap.Put(idx, &zero); err != nil {
		return fmt.Errorf("failed to zero plugin aux entry: %w", err)
	}
	return m.auxAlloc.FreeOwner(idx, owner)
}

// DeleteSidFunction removes a SID function entry and its aux data
func (m *MapOperations) DeleteSidFunction(triggerPrefix string) error {
	key, err := buildLpmKeyV6(triggerPrefix)
	if err != nil {
		return fmt.Errorf("failed to build LPM key: %w", err)
	}

	// Read entry first so aux can be cleaned up after successful delete
	var entry SidFunctionEntry
	hasEntry := m.objs.SidFunctionMap.Lookup(key, &entry) == nil

	if err := m.objs.SidFunctionMap.Delete(key); err != nil {
		return fmt.Errorf("failed to delete SID function entry: %w", err)
	}

	// Clean up aux after SID entry is deleted to avoid index reuse while
	// entry exists. Plugin-owned aux is NOT freed here — the plugin path
	// (PluginAuxFree RPC) owns that lifecycle, so SID delete just unbinds
	// the reference.
	if hasEntry && entry.AuxIndex != 0 {
		idx := uint32(entry.AuxIndex)
		if m.auxAlloc.OwnerOf(idx) == AuxOwnerBuiltin {
			var zeroAux SidAuxEntry
			_ = m.objs.SidAuxMap.Put(idx, &zeroAux)
			_ = m.auxAlloc.FreeOwner(idx, AuxOwnerBuiltin)
		}
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

// CreateHeadendV4 adds a headend v4 entry to the map
func (m *MapOperations) CreateHeadendV4(triggerPrefix string, entry *HeadendEntry) error {
	key, err := buildLpmKeyV4(triggerPrefix)
	if err != nil {
		return fmt.Errorf("failed to build LPM key: %w", err)
	}

	if err := m.objs.HeadendV4Map.Put(key, entry); err != nil {
		return fmt.Errorf("failed to put headend v4 entry: %w", err)
	}
	return nil
}

// DeleteHeadendV4 removes a headend v4 entry from the map
func (m *MapOperations) DeleteHeadendV4(triggerPrefix string) error {
	key, err := buildLpmKeyV4(triggerPrefix)
	if err != nil {
		return fmt.Errorf("failed to build LPM key: %w", err)
	}

	if err := m.objs.HeadendV4Map.Delete(key); err != nil {
		return fmt.Errorf("failed to delete headend v4 entry: %w", err)
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

// ===== Headend V6 Map Operations =====

// CreateHeadendV6 adds a headend v6 entry to the map
func (m *MapOperations) CreateHeadendV6(triggerPrefix string, entry *HeadendEntry) error {
	key, err := buildLpmKeyV6(triggerPrefix)
	if err != nil {
		return fmt.Errorf("failed to build LPM key: %w", err)
	}

	if err := m.objs.HeadendV6Map.Put(key, entry); err != nil {
		return fmt.Errorf("failed to put headend v6 entry: %w", err)
	}
	return nil
}

// DeleteHeadendV6 removes a headend v6 entry from the map
func (m *MapOperations) DeleteHeadendV6(triggerPrefix string) error {
	key, err := buildLpmKeyV6(triggerPrefix)
	if err != nil {
		return fmt.Errorf("failed to build LPM key: %w", err)
	}

	if err := m.objs.HeadendV6Map.Delete(key); err != nil {
		return fmt.Errorf("failed to delete headend v6 entry: %w", err)
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

// AgeFdbEntries deletes dynamic FDB entries older than maxAgeNs nanoseconds.
// Static entries (is_static=1) and entries with last_seen=0 are never aged out.
// Returns the number of entries deleted.
func (m *MapOperations) AgeFdbEntries(maxAgeNs uint64) (int, error) {
	var key FdbKey
	var entry FdbEntry
	iter := m.objs.FdbMap.Iterate()

	now := currentKtimeNs()
	var toDelete []FdbKey
	for iter.Next(&key, &entry) {
		if entry.IsStatic != 0 || entry.LastSeen == 0 {
			continue
		}
		if entry.LastSeen > now {
			continue // clock skew or corruption
		}
		age := now - entry.LastSeen
		if age > maxAgeNs {
			keyCopy := key
			toDelete = append(toDelete, keyCopy)
		}
	}
	if err := iter.Err(); err != nil {
		return 0, fmt.Errorf("failed to iterate fdb map: %w", err)
	}

	deleted := 0
	for _, k := range toDelete {
		if err := m.objs.FdbMap.Delete(&k); err == nil {
			deleted++
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

// CreateBdPeer adds a BD peer entry for BUM flooding.
// Also populates bd_peer_reverse_map (RX split-horizon path) and
// bd_peer_l2_ext_map (TX split-horizon path). esi is the 10-byte RFC 7432
// Ethernet Segment Identifier; all-zero means single-homing.
func (m *MapOperations) CreateBdPeer(bdID, index uint16, entry *HeadendEntry, esi [ESILen]byte) error {
	key := &BdPeerKey{BdId: bdID, Index: index}
	if err := m.objs.BdPeerMap.Put(key, entry); err != nil {
		return fmt.Errorf("failed to put bd peer entry: %w", err)
	}

	rKey := &BdPeerReverseKey{BdId: bdID}
	copy(rKey.SrcAddr[:], entry.SrcAddr[:])
	rVal := &BdPeerReverseVal{Index: index, Esi: esi}
	if err := m.objs.BdPeerReverseMap.Put(rKey, rVal); err != nil {
		return fmt.Errorf("failed to put bd peer reverse entry: %w", err)
	}

	var zero [ESILen]byte
	extKey := &BpfBdPeerL2ExtKey{BdId: bdID, Index: index}
	if esi != zero {
		ext := &BpfBdPeerL2ExtVal{Esi: esi}
		if err := m.objs.BdPeerL2ExtMap.Put(extKey, ext); err != nil {
			return fmt.Errorf("failed to put bd peer L2 ESI ext: %w", err)
		}
	} else {
		_ = m.objs.BdPeerL2ExtMap.Delete(extKey)
	}

	return nil
}

// DeleteBdPeer removes a BD peer entry and its reverse-map entry.
// Deletes forward map first to avoid inconsistency if reverse delete fails.
func (m *MapOperations) DeleteBdPeer(bdID, index uint16) error {
	// Look up the entry first to get src_addr for reverse map cleanup
	key := &BdPeerKey{BdId: bdID, Index: index}
	var entry HeadendEntry
	hasEntry := m.objs.BdPeerMap.Lookup(key, &entry) == nil

	if err := m.objs.BdPeerMap.Delete(key); err != nil {
		return fmt.Errorf("failed to delete bd peer entry: %w", err)
	}

	// Clean up reverse map + ESI side tables (best-effort: ignore errors if already gone)
	if hasEntry {
		rKey := &BdPeerReverseKey{BdId: bdID}
		copy(rKey.SrcAddr[:], entry.SrcAddr[:])
		_ = m.objs.BdPeerReverseMap.Delete(rKey)
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

// FlushSidFunctions removes every SID function entry and releases the
// associated aux indices. Returns the number of entries deleted.
func (m *MapOperations) FlushSidFunctions() (uint32, error) {
	entries, err := m.ListSidFunctions()
	if err != nil {
		return 0, err
	}
	var count uint32
	for prefix := range entries {
		if err := m.DeleteSidFunction(prefix); err != nil {
			return count, fmt.Errorf("flush sid_function: delete %q: %w", prefix, err)
		}
		count++
	}
	return count, nil
}

// FlushHeadendV4 removes every headend_v4 entry.
func (m *MapOperations) FlushHeadendV4() (uint32, error) {
	entries, err := m.ListHeadendV4()
	if err != nil {
		return 0, err
	}
	var count uint32
	for prefix := range entries {
		if err := m.DeleteHeadendV4(prefix); err != nil {
			return count, fmt.Errorf("flush headend_v4: delete %q: %w", prefix, err)
		}
		count++
	}
	return count, nil
}

// FlushHeadendV6 removes every headend_v6 entry.
func (m *MapOperations) FlushHeadendV6() (uint32, error) {
	entries, err := m.ListHeadendV6()
	if err != nil {
		return 0, err
	}
	var count uint32
	for prefix := range entries {
		if err := m.DeleteHeadendV6(prefix); err != nil {
			return count, fmt.Errorf("flush headend_v6: delete %q: %w", prefix, err)
		}
		count++
	}
	return count, nil
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
// validator (Phase 2 will escalate to a hard reject; today it only warns).
func (m *MapOperations) GetSharedReadOnlyMaps() map[string]*ebpf.Map {
	return map[string]*ebpf.Map{
		"sid_function_map":    m.objs.SidFunctionMap,
		"sid_aux_map":         m.objs.SidAuxMap,
		"headend_v4_map":      m.objs.HeadendV4Map,
		"headend_v6_map":      m.objs.HeadendV6Map,
		"headend_l2_map":      m.objs.HeadendL2Map,
		"fdb_map":             m.objs.FdbMap,
		"bd_peer_map":         m.objs.BdPeerMap,
		"bd_peer_reverse_map": m.objs.BdPeerReverseMap,
		"esi_map":             m.objs.EsiMap,
		"bd_peer_l2_ext_map":  m.objs.BdPeerL2ExtMap,
		"headend_l2_ext_map":  m.objs.HeadendL2ExtMap,
		"bd_local_esi_map":    m.objs.BdLocalEsiMap,
		"dx2v_map":            m.objs.Dx2vMap,
		"tailcall_ctx_map":    m.objs.TailcallCtxMap,
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
		MapNameSidEndpointProgs: m.objs.SidEndpointProgs,
		MapNameHeadendV4Progs:   m.objs.HeadendV4Progs,
		MapNameHeadendV6Progs:   m.objs.HeadendV6Progs,
	}
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
)

// BPF map names for vinbero-managed PROG_ARRAYs. Referenced by the shared-map
// getters, resolvePluginMap, and the plugin validator's tail-call whitelist.
const (
	MapNameSidEndpointProgs = "sid_endpoint_progs"
	MapNameHeadendV4Progs   = "headend_v4_progs"
	MapNameHeadendV6Progs   = "headend_v6_progs"
)

var (
	ErrReservedSlot = fmt.Errorf("cannot register plugin in reserved slot")
	ErrIndexTooHigh = fmt.Errorf("plugin index exceeds PROG_ARRAY capacity")
)

// RegisterPlugin registers an external BPF program into a PROG_ARRAY slot.
// Only plugin-range indices are allowed (built-in slots are protected).
func (m *MapOperations) RegisterPlugin(mapType string, index uint32, progFD int) error {
	targetMap, base, maxEntries, err := m.resolvePluginMap(mapType)
	if err != nil {
		return err
	}
	if index < base {
		return fmt.Errorf("%w: index %d < base %d for %s", ErrReservedSlot, index, base, mapType)
	}
	if index >= maxEntries {
		return fmt.Errorf("%w: index %d >= max %d for %s", ErrIndexTooHigh, index, maxEntries, mapType)
	}
	return targetMap.Update(index, uint32(progFD), ebpf.UpdateAny)
}

// UnregisterPlugin removes a plugin from a PROG_ARRAY slot.
func (m *MapOperations) UnregisterPlugin(mapType string, index uint32) error {
	targetMap, base, _, err := m.resolvePluginMap(mapType)
	if err != nil {
		return err
	}
	if index < base {
		return fmt.Errorf("%w: index %d < base %d for %s", ErrReservedSlot, index, base, mapType)
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
	LocalAttached   bool
	RedundancyMode  uint8 // zero = UNSPECIFIED
	LocalPeSrcAddr  [IPv6AddrLen]byte
	DfPeSrcAddr     [IPv6AddrLen]byte
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
