package bpf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

const (
	MaxSegments = 10
	IPv4AddrLen = 4
	IPv6AddrLen = 16
)

// Type aliases for BPF generated types
type (
	LpmKeyV4         = BpfLpmKeyV4
	LpmKeyV6         = BpfLpmKeyV6
	SidFunctionEntry = BpfSidFunctionEntry
	TransitEntry     = BpfTransitEntry
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
	objs *BpfObjects
}

// NewMapOperations creates a new MapOperations instance
func NewMapOperations(objs *BpfObjects) *MapOperations {
	return &MapOperations{objs: objs}
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

// ===== Generic LPM Key Interface =====

type lpmKey interface {
	LpmKeyV4 | LpmKeyV6
}

// ===== SID Function Map Operations =====

// CreateSidFunction adds a SID function entry to the map
func (m *MapOperations) CreateSidFunction(triggerPrefix string, entry *SidFunctionEntry) error {
	key, err := buildLpmKeyV6(triggerPrefix)
	if err != nil {
		return fmt.Errorf("failed to build LPM key: %w", err)
	}

	if err := m.objs.SidFunctionMap.Put(key, entry); err != nil {
		return fmt.Errorf("failed to put SID function entry: %w", err)
	}
	return nil
}

// DeleteSidFunction removes a SID function entry from the map
func (m *MapOperations) DeleteSidFunction(triggerPrefix string) error {
	key, err := buildLpmKeyV6(triggerPrefix)
	if err != nil {
		return fmt.Errorf("failed to build LPM key: %w", err)
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

// ===== Transit V4 Map Operations =====

// CreateTransitV4 adds a transit v4 entry to the map
func (m *MapOperations) CreateTransitV4(triggerPrefix string, entry *TransitEntry) error {
	key, err := buildLpmKeyV4(triggerPrefix)
	if err != nil {
		return fmt.Errorf("failed to build LPM key: %w", err)
	}

	if err := m.objs.TransitV4Map.Put(key, entry); err != nil {
		return fmt.Errorf("failed to put transit v4 entry: %w", err)
	}
	return nil
}

// DeleteTransitV4 removes a transit v4 entry from the map
func (m *MapOperations) DeleteTransitV4(triggerPrefix string) error {
	key, err := buildLpmKeyV4(triggerPrefix)
	if err != nil {
		return fmt.Errorf("failed to build LPM key: %w", err)
	}

	if err := m.objs.TransitV4Map.Delete(key); err != nil {
		return fmt.Errorf("failed to delete transit v4 entry: %w", err)
	}
	return nil
}

// GetTransitV4 retrieves a transit v4 entry from the map
func (m *MapOperations) GetTransitV4(triggerPrefix string) (*TransitEntry, error) {
	key, err := buildLpmKeyV4(triggerPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to build LPM key: %w", err)
	}

	var entry TransitEntry
	if err := m.objs.TransitV4Map.Lookup(key, &entry); err != nil {
		return nil, fmt.Errorf("failed to lookup transit v4 entry: %w", err)
	}
	return &entry, nil
}

// ListTransitV4 returns all transit v4 entries
func (m *MapOperations) ListTransitV4() (map[string]*TransitEntry, error) {
	result := make(map[string]*TransitEntry)

	var key LpmKeyV4
	var entry TransitEntry
	iter := m.objs.TransitV4Map.Iterate()

	for iter.Next(&key, &entry) {
		prefix := lpmKeyV4ToString(&key)
		entryCopy := entry
		result[prefix] = &entryCopy
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate transit v4 map: %w", err)
	}
	return result, nil
}

// ===== Transit V6 Map Operations =====

// CreateTransitV6 adds a transit v6 entry to the map
func (m *MapOperations) CreateTransitV6(triggerPrefix string, entry *TransitEntry) error {
	key, err := buildLpmKeyV6(triggerPrefix)
	if err != nil {
		return fmt.Errorf("failed to build LPM key: %w", err)
	}

	if err := m.objs.TransitV6Map.Put(key, entry); err != nil {
		return fmt.Errorf("failed to put transit v6 entry: %w", err)
	}
	return nil
}

// DeleteTransitV6 removes a transit v6 entry from the map
func (m *MapOperations) DeleteTransitV6(triggerPrefix string) error {
	key, err := buildLpmKeyV6(triggerPrefix)
	if err != nil {
		return fmt.Errorf("failed to build LPM key: %w", err)
	}

	if err := m.objs.TransitV6Map.Delete(key); err != nil {
		return fmt.Errorf("failed to delete transit v6 entry: %w", err)
	}
	return nil
}

// GetTransitV6 retrieves a transit v6 entry from the map
func (m *MapOperations) GetTransitV6(triggerPrefix string) (*TransitEntry, error) {
	key, err := buildLpmKeyV6(triggerPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to build LPM key: %w", err)
	}

	var entry TransitEntry
	if err := m.objs.TransitV6Map.Lookup(key, &entry); err != nil {
		return nil, fmt.Errorf("failed to lookup transit v6 entry: %w", err)
	}
	return &entry, nil
}

// ListTransitV6 returns all transit v6 entries
func (m *MapOperations) ListTransitV6() (map[string]*TransitEntry, error) {
	result := make(map[string]*TransitEntry)

	var key LpmKeyV6
	var entry TransitEntry
	iter := m.objs.TransitV6Map.Iterate()

	for iter.Next(&key, &entry) {
		prefix := lpmKeyV6ToString(&key)
		entryCopy := entry
		result[prefix] = &entryCopy
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate transit v6 map: %w", err)
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

// FormatSegments formats the segments array as a string slice
func FormatSegments(segments [MaxSegments][IPv6AddrLen]uint8, numSegments uint8) []string {
	result := make([]string, 0, numSegments)
	for i := uint8(0); i < numSegments; i++ {
		result = append(result, FormatIPv6(segments[i]))
	}
	return result
}
