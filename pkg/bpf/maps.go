package bpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
)

const (
	MaxSegments    = 10
	IPv4AddrLen    = 4
	IPv6AddrLen    = 16
	MaxBumNexthops = 8 // Must match MAX_BUM_NEXTHOPS in xdp_prog.h
)

// Type aliases for BPF generated types
type (
	LpmKeyV4           = BpfLpmKeyV4
	LpmKeyV6           = BpfLpmKeyV6
	HeadendL2Key       = BpfHeadendL2Key
	SidFunctionEntry   = BpfSidFunctionEntry
	SidAuxEntry        = BpfSidAuxEntry
	HeadendEntry       = BpfHeadendEntry
	FdbKey             = BpfFdbKey
	FdbEntry           = BpfFdbEntry
	BdPeerKey          = BpfBdPeerKey
	BdPeerReverseKey   = BpfBdPeerReverseKey
	BdPeerReverseVal   = BpfBdPeerReverseVal
)

// MapOperator interface for testability
type MapOperator interface {
	Put(key, value interface{}) error
	Delete(key interface{}) error
	Lookup(key, valueOut interface{}) error
	Iterate() *ebpf.MapIterator
}

// MapOperations provides operations for BPF maps
type MapOperations struct {
	objs     *BpfObjects
	auxAlloc *indexAllocator
}

// NewMapOperations creates a new MapOperations instance
func NewMapOperations(objs *BpfObjects) *MapOperations {
	return &MapOperations{
		objs:     objs,
		auxAlloc: newIndexAllocator(512),
	}
}

// indexAllocator manages a pool of uint32 indices with a free-list
type indexAllocator struct {
	mu       sync.Mutex
	freeList []uint32
	maxIndex uint32
	nextNew  uint32
}

func newIndexAllocator(max uint32) *indexAllocator {
	return &indexAllocator{maxIndex: max}
}

func (a *indexAllocator) Alloc() (uint32, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
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

func (a *indexAllocator) Free(idx uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.freeList = append(a.freeList, idx)
}

// RecoverUsed rebuilds allocator state from a list of indices currently in use.
// Gaps between used indices are added to the free list for reuse.
func (a *indexAllocator) RecoverUsed(usedIndices []uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(usedIndices) == 0 {
		return
	}

	used := make(map[uint32]bool, len(usedIndices))
	maxUsed := uint32(0)
	for _, idx := range usedIndices {
		used[idx] = true
		if idx >= maxUsed {
			maxUsed = idx
		}
	}

	a.nextNew = maxUsed + 1
	a.freeList = nil
	for i := uint32(0); i < a.nextNew; i++ {
		if !used[i] {
			a.freeList = append(a.freeList, i)
		}
	}
}

// RecoverAuxIndices scans sid_function_map for entries with has_aux=1
// and marks their aux_index as used in the allocator.
// Call this on startup to restore allocator state after process restart.
func (m *MapOperations) RecoverAuxIndices() error {
	var key LpmKeyV6
	var entry SidFunctionEntry
	iter := m.objs.SidFunctionMap.Iterate()

	var used []uint32
	for iter.Next(&key, &entry) {
		if entry.HasAux != 0 {
			used = append(used, entry.AuxIndex)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to iterate SID function map for recovery: %w", err)
	}

	m.auxAlloc.RecoverUsed(used)
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

// NewSidAuxB6Policy creates an aux entry for End.B6/End.B6.Encaps
// Stores a full HeadendEntry in the b6_policy union variant.
func NewSidAuxB6Policy(policy *HeadendEntry) *SidAuxEntry {
	entry := &SidAuxEntry{}
	raw := (*[200]byte)(unsafe.Pointer(entry))
	policyBytes := (*[196]byte)(unsafe.Pointer(policy))
	copy(raw[:196], policyBytes[:])
	return entry
}

// SidAuxB6PolicyData extracts End.B6 policy from a SidAuxEntry
func SidAuxB6PolicyData(entry *SidAuxEntry) *HeadendEntry {
	result := &HeadendEntry{}
	raw := (*[200]byte)(unsafe.Pointer(entry))
	resultBytes := (*[196]byte)(unsafe.Pointer(result))
	copy(resultBytes[:], raw[:196])
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
		idx, err := m.auxAlloc.Alloc()
		if err != nil {
			return fmt.Errorf("failed to allocate aux index: %w", err)
		}
		entry.HasAux = 1
		entry.AuxIndex = idx
		if err := m.objs.SidAuxMap.Put(idx, aux); err != nil {
			m.auxAlloc.Free(idx)
			return fmt.Errorf("failed to put SID aux entry: %w", err)
		}
	}

	if err := m.objs.SidFunctionMap.Put(key, entry); err != nil {
		if aux != nil {
			m.auxAlloc.Free(entry.AuxIndex)
		}
		return fmt.Errorf("failed to put SID function entry: %w", err)
	}
	return nil
}

// DeleteSidFunction removes a SID function entry and its aux data
func (m *MapOperations) DeleteSidFunction(triggerPrefix string) error {
	key, err := buildLpmKeyV6(triggerPrefix)
	if err != nil {
		return fmt.Errorf("failed to build LPM key: %w", err)
	}

	// Read entry first to free aux index
	var entry SidFunctionEntry
	if err := m.objs.SidFunctionMap.Lookup(key, &entry); err == nil {
		if entry.HasAux != 0 {
			// Zero out aux entry (ARRAY map entries can't be deleted, only zeroed)
			var zeroAux SidAuxEntry
			_ = m.objs.SidAuxMap.Put(entry.AuxIndex, &zeroAux)
			m.auxAlloc.Free(entry.AuxIndex)
		}
	}

	if err := m.objs.SidFunctionMap.Delete(key); err != nil {
		return fmt.Errorf("failed to delete SID function entry: %w", err)
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
	"RX_PACKETS", "SRV6_END", "H_ENCAPS_V4", "H_ENCAPS_V6",
	"PASS", "DROP", "REDIRECT", "ERROR",
}

type AggregatedStats struct {
	Name    string
	Packets uint64
	Bytes   uint64
}

// ReadStats reads the PERCPU_ARRAY stats_map and aggregates per-CPU values
func (m *MapOperations) ReadStats() ([]AggregatedStats, error) {
	result := make([]AggregatedStats, StatsMax)
	for i := uint32(0); i < StatsMax; i++ {
		var perCPU []BpfStatsEntry
		if err := m.objs.StatsMap.Lookup(i, &perCPU); err != nil {
			return nil, fmt.Errorf("failed to lookup stats counter %d: %w", i, err)
		}
		var totalPackets, totalBytes uint64
		for _, cpu := range perCPU {
			totalPackets += cpu.Packets
			totalBytes += cpu.Bytes
		}
		result[i] = AggregatedStats{
			Name:    StatsCounterName[i],
			Packets: totalPackets,
			Bytes:   totalBytes,
		}
	}
	return result, nil
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

// CreateHeadendL2 adds a headend L2 entry to the map (keyed by port + VLAN)
func (m *MapOperations) CreateHeadendL2(ifindex uint32, vlanID uint16, entry *HeadendEntry) error {
	key := buildHeadendL2Key(ifindex, vlanID)
	if err := m.objs.HeadendL2Map.Put(key, entry); err != nil {
		return fmt.Errorf("failed to put headend L2 entry: %w", err)
	}
	return nil
}

// DeleteHeadendL2 removes a headend L2 entry from the map
func (m *MapOperations) DeleteHeadendL2(ifindex uint32, vlanID uint16) error {
	key := buildHeadendL2Key(ifindex, vlanID)
	if err := m.objs.HeadendL2Map.Delete(key); err != nil {
		return fmt.Errorf("failed to delete headend L2 entry: %w", err)
	}
	return nil
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

// ===== BD Peer Map Operations (for P2MP BUM flooding) =====

// CreateBdPeer adds a BD peer entry for BUM flooding.
// Also populates bd_peer_reverse_map for O(1) peer_index resolution in End.DT2.
func (m *MapOperations) CreateBdPeer(bdID, index uint16, entry *HeadendEntry) error {
	key := &BdPeerKey{BdId: bdID, Index: index}
	if err := m.objs.BdPeerMap.Put(key, entry); err != nil {
		return fmt.Errorf("failed to put bd peer entry: %w", err)
	}

	// Maintain reverse map: {bd_id, src_addr} → index
	rKey := &BdPeerReverseKey{BdId: bdID}
	copy(rKey.SrcAddr[:], entry.SrcAddr[:])
	rVal := &BdPeerReverseVal{Index: index}
	if err := m.objs.BdPeerReverseMap.Put(rKey, rVal); err != nil {
		return fmt.Errorf("failed to put bd peer reverse entry: %w", err)
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

	// Clean up reverse map (best-effort: ignore error if already gone)
	if hasEntry {
		rKey := &BdPeerReverseKey{BdId: bdID}
		copy(rKey.SrcAddr[:], entry.SrcAddr[:])
		_ = m.objs.BdPeerReverseMap.Delete(rKey)
	}
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
