package bpf

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
)

// headendFamily is one family's headend map and owner map, with key-only
// scans of one VRF over each.
type headendFamily struct {
	family       string
	main, owners func(vrfID uint32, fn func(key any, prefixOK bool) bool) error
	ownerMap     *entryOwnerMap
}

func scanVRF[K comparable, PK headendKey[K]](m *ebpf.Map) func(uint32, func(any, bool) bool) error {
	return func(vrfID uint32, fn func(any, bool) bool) error {
		if m == nil {
			return nil
		}
		return eachKey(m, func(key *K) bool {
			if PK(key).vrf() != vrfID {
				return true
			}
			_, ok := PK(key).prefix()
			k := *key
			return fn(&k, ok)
		})
	}
}

// headendFamilies lists the headend maps and owner maps of both families.
func (m *MapOperations) headendFamilies() []headendFamily {
	var ownerV4, ownerV6 *ebpf.Map
	if m.headendV4Owners != nil {
		ownerV4 = m.headendV4Owners.m
	}
	if m.headendV6Owners != nil {
		ownerV6 = m.headendV6Owners.m
	}
	return []headendFamily{
		{"v4", scanVRF[HeadendV4Key](m.objs.HeadendV4Map), scanVRF[HeadendV4Key](ownerV4), m.headendV4Owners},
		{"v6", scanVRF[HeadendV6Key](m.objs.HeadendV6Map), scanVRF[HeadendV6Key](ownerV6), m.headendV6Owners},
	}
}

// HeadendVRFInUse reports whether a headend entry or owner record of
// either family is stored under vrfID. It reads keys only and stops at the
// first one.
func (m *MapOperations) HeadendVRFInUse(vrfID uint32) (bool, error) {
	for _, f := range m.headendFamilies() {
		for _, scan := range []func(uint32, func(any, bool) bool) error{f.main, f.owners} {
			found := false
			if err := scan(vrfID, func(any, bool) bool { found = true; return false }); err != nil {
				return false, fmt.Errorf("scan headend_%s: %w", f.family, err)
			}
			if found {
				return true, nil
			}
		}
	}
	return false, nil
}

// HeadendVRFRefs is what one VRF holds in the headend maps, by owner.
type HeadendVRFRefs struct {
	// Entries counts the entries of both families by recorded owner; the
	// empty owner is an entry with no owner record.
	Entries map[OwnerTag]int
	// OwnerOnly counts the owner records whose entry is gone, by owner.
	OwnerOnly map[OwnerTag]int
}

// HeadendVRFRefs counts what vrfID holds in the headend maps.
func (m *MapOperations) HeadendVRFRefs(vrfID uint32) (HeadendVRFRefs, error) {
	refs := HeadendVRFRefs{Entries: map[OwnerTag]int{}, OwnerOnly: map[OwnerTag]int{}}
	for _, f := range m.headendFamilies() {
		live := map[any]struct{}{}
		var scanErr error
		if err := f.main(vrfID, func(key any, _ bool) bool {
			live[keyOf(key)] = struct{}{}
			owner, ok, err := f.ownerMap.Lookup(key)
			if err != nil {
				scanErr = err
				return false
			}
			if !ok {
				owner = ""
			}
			refs.Entries[owner]++
			return true
		}); err != nil {
			return refs, fmt.Errorf("scan headend_%s: %w", f.family, err)
		}
		if scanErr != nil {
			return refs, fmt.Errorf("scan headend_%s owners: %w", f.family, scanErr)
		}
		if err := f.owners(vrfID, func(key any, _ bool) bool {
			if _, ok := live[keyOf(key)]; ok {
				return true
			}
			owner, ok, err := f.ownerMap.Lookup(key)
			if err != nil {
				scanErr = err
				return false
			}
			if ok {
				refs.OwnerOnly[owner]++
			}
			return true
		}); err != nil {
			return refs, fmt.Errorf("scan headend_%s owners: %w", f.family, err)
		}
		if scanErr != nil {
			return refs, fmt.Errorf("scan headend_%s owners: %w", f.family, scanErr)
		}
	}
	return refs, nil
}

// keyOf dereferences a key pointer for use as a map key.
func keyOf(key any) any {
	switch k := key.(type) {
	case *HeadendV4Key:
		return *k
	case *HeadendV6Key:
		return *k
	}
	return key
}

// PurgeHeadendVRFs removes every headend entry and owner record, whoever
// owns them, of each vrf_id other than the global one that keep refuses,
// malformed keys included. It is the boot-time cleanup of VRFs that no
// longer exist, and the end of a VRF delete. It returns how many entries
// and records it removed per vrf_id.
func (m *MapOperations) PurgeHeadendVRFs(keep func(vrfID uint32) bool) (map[uint32]int, error) {
	removed := map[uint32]int{}
	for _, f := range []struct {
		family string
		purge  func() (map[uint32]int, error)
	}{
		{"v4", func() (map[uint32]int, error) {
			return purgeHeadendVRFs[HeadendV4Key](m.objs.HeadendV4Map, m.headendV4Owners, keep)
		}},
		{"v6", func() (map[uint32]int, error) {
			return purgeHeadendVRFs[HeadendV6Key](m.objs.HeadendV6Map, m.headendV6Owners, keep)
		}},
	} {
		counts, err := f.purge()
		for id, n := range counts {
			removed[id] += n
		}
		if err != nil {
			return removed, fmt.Errorf("purge headend_%s: %w", f.family, err)
		}
	}
	return removed, nil
}

func purgeHeadendVRFs[K comparable, PK headendKey[K]](main *ebpf.Map, owners *entryOwnerMap, keep func(uint32) bool) (map[uint32]int, error) {
	drop := func(key *K) bool {
		id := PK(key).vrf()
		return id != globalVRF && !keep(id)
	}
	doomed := map[K]struct{}{}
	collect := func(key *K) bool {
		if drop(key) {
			doomed[*key] = struct{}{}
		}
		return true
	}
	if err := eachKey(main, collect); err != nil {
		return nil, err
	}
	if owners != nil {
		if err := eachKey(owners.m, collect); err != nil {
			return nil, err
		}
	}
	removed := map[uint32]int{}
	for key := range doomed {
		if err := deleteHeadendKey(main, owners, &key, "", true, ""); err != nil {
			return removed, err
		}
		removed[PK(&key).vrf()]++
	}
	return removed, nil
}

// HighestVRFIDInUse returns the largest vrf_id stored in a map keyed by
// one: the headend maps and the MUP uplink maps, owner maps included. The
// VRF id allocator starts above it, so an id a lost state file forgot is
// not handed to a new VRF while state keyed by it is still in the maps.
func (m *MapOperations) HighestVRFIDInUse() (uint32, error) {
	var highest uint32
	note := func(instance [4]uint8) {
		if id := binary.BigEndian.Uint32(instance[:]); id > highest {
			highest = id
		}
	}
	ownerMap := func(o *entryOwnerMap) *ebpf.Map {
		if o == nil {
			return nil
		}
		return o.m
	}
	for _, scan := range []struct {
		name string
		run  func() error
	}{
		{"headend_v4", func() error {
			return scanInstances(m.objs.HeadendV4Map, func(k *HeadendV4Key) { note(k.Instance) })
		}},
		{"headend_v4_owner", func() error {
			return scanInstances(ownerMap(m.headendV4Owners), func(k *HeadendV4Key) { note(k.Instance) })
		}},
		{"headend_v6", func() error {
			return scanInstances(m.objs.HeadendV6Map, func(k *HeadendV6Key) { note(k.Instance) })
		}},
		{"headend_v6_owner", func() error {
			return scanInstances(ownerMap(m.headendV6Owners), func(k *HeadendV6Key) { note(k.Instance) })
		}},
		{"mup_uplink_v4", func() error {
			return scanInstances(m.objs.MupUplinkV4Map, func(k *MupUplinkV4Key) { note(k.Instance) })
		}},
		{"mup_uplink_v4_owner", func() error {
			return scanInstances(ownerMap(m.mupUplinkV4Owners), func(k *MupUplinkV4Key) { note(k.Instance) })
		}},
		{"mup_uplink_v6", func() error {
			return scanInstances(m.objs.MupUplinkV6Map, func(k *MupUplinkV6Key) { note(k.Instance) })
		}},
		{"mup_uplink_v6_owner", func() error {
			return scanInstances(ownerMap(m.mupUplinkV6Owners), func(k *MupUplinkV6Key) { note(k.Instance) })
		}},
	} {
		if err := scan.run(); err != nil {
			return highest, fmt.Errorf("scan %s: %w", scan.name, err)
		}
	}
	return highest, nil
}

func scanInstances[K any](m *ebpf.Map, fn func(*K)) error {
	if m == nil {
		return nil
	}
	return eachKey(m, func(k *K) bool { fn(k); return true })
}
