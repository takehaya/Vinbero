package bpf

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
)

// SetFibGlobalMode writes which address families run their vrf 0 lookups
// as direct lookups (fib_global_mode_map, srv6_fib_global_flags). It only
// has an effect in a program loaded with fib_lookup_global_auto.
func (m *MapOperations) SetFibGlobalMode(v4, v6 bool) error {
	var mode BpfFibGlobalMode
	if v4 {
		mode.V4 = 1
	}
	if v6 {
		mode.V6 = 1
	}
	key := uint32(0)
	if err := m.objs.FibGlobalModeMap.Put(&key, &mode); err != nil {
		return fmt.Errorf("write fib_global_mode_map: %w", err)
	}
	return nil
}

// FibGlobalMode reads fib_global_mode_map.
func (m *MapOperations) FibGlobalMode() (v4, v6 bool, err error) {
	var mode BpfFibGlobalMode
	key := uint32(0)
	if err := m.objs.FibGlobalModeMap.Lookup(&key, &mode); err != nil {
		return false, false, fmt.Errorf("read fib_global_mode_map: %w", err)
	}
	return mode.V4 != 0, mode.V6 != 0, nil
}

// SyncFibLocal makes fib_local_v4_map and fib_local_v6_map hold exactly the
// given addresses (the host routes of the local table).
func (m *MapOperations) SyncFibLocal(v4, v6 []netip.Addr) error {
	want4 := make(map[[4]byte]struct{}, len(v4))
	for _, a := range v4 {
		if a.Is4() {
			want4[a.As4()] = struct{}{}
		}
	}
	want6 := make(map[[16]byte]struct{}, len(v6))
	for _, a := range v6 {
		// An IPv4-mapped address (::ffff:a.b.c.d) is an IPv6 destination
		// of its own; keep it in its 16-byte form.
		if a.Is6() {
			want6[a.As16()] = struct{}{}
		}
	}
	return errors.Join(syncSet(m.objs.FibLocalV4Map, want4), syncSet(m.objs.FibLocalV6Map, want6))
}

func syncSet[K comparable](mp *ebpf.Map, want map[K]struct{}) error {
	var stale []K
	var k K
	var v uint8
	it := mp.Iterate()
	have := map[K]struct{}{}
	for it.Next(&k, &v) {
		if _, ok := want[k]; ok {
			have[k] = struct{}{}
		} else {
			stale = append(stale, k)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("list %s: %w", mapName(mp), err)
	}
	for _, k := range stale {
		if err := mp.Delete(&k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete from %s: %w", mapName(mp), err)
		}
	}
	one := uint8(1)
	for k := range want {
		if _, ok := have[k]; ok {
			continue
		}
		if err := mp.Put(&k, &one); err != nil {
			return fmt.Errorf("write %s: %w", mapName(mp), err)
		}
	}
	return nil
}

func mapName(mp *ebpf.Map) string {
	if info, err := mp.Info(); err == nil && info.Name != "" {
		return info.Name
	}
	return "map"
}
