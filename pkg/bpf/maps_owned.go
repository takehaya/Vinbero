package bpf

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf"
)

// checkControlOwner also protects untagged entries left by older daemons.
// LPM Lookup returns covering entries, so only an exact iteration can decide
// whether an untagged prefix belongs to a previous writer.
func checkControlOwner[K comparable, V any](main *ebpf.Map, owners *entryOwnerMap, key *K, owner OwnerTag, lpm bool) (bool, error) {
	owned, err := checkEntryOwner(owners, key, owner)
	if err != nil || owned {
		return owned, err
	}
	if !strings.HasPrefix(string(owner), "plugin:") {
		return false, nil
	}
	if owners == nil {
		return false, fmt.Errorf("plugin entry requires persistent owner map")
	}
	var value V
	exists := false
	if lpm {
		var candidate K
		it := main.Iterate()
		for it.Next(&candidate, &value) {
			if candidate == *key {
				exists = true
				break
			}
		}
		if err := it.Err(); err != nil {
			return false, err
		}
	} else {
		err := main.Lookup(key, &value)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, err
		}
		exists = err == nil
	}
	if exists {
		return false, fmt.Errorf("%w: untagged entry cannot be claimed by %q", ErrEntryOwnerMismatch, owner)
	}
	return false, nil
}

// Reserve ownership before exposing a new entry. A failed main-map write
// removes only the reservation made by this operation.
func putControlEntry[K comparable, V any](main *ebpf.Map, owners *entryOwnerMap, key *K, value *V, owner OwnerTag, lpm bool) error {
	owned, err := checkControlOwner[K, V](main, owners, key, owner, lpm)
	if err != nil {
		return err
	}
	if !owned {
		if err := owners.Put(key, owner); err != nil {
			return err
		}
	}
	flags := ebpf.UpdateAny
	if !owned && strings.HasPrefix(string(owner), "plugin:") && !lpm {
		flags = ebpf.UpdateNoExist
	}
	if err := main.Update(key, value, flags); err != nil {
		if !owned {
			err = errors.Join(err, owners.Delete(key))
		}
		return err
	}
	return nil
}

func deleteControlEntry[K comparable, V any](main *ebpf.Map, owners *entryOwnerMap, key *K, owner OwnerTag, lpm bool) error {
	if _, err := checkControlOwner[K, V](main, owners, key, owner, lpm); err != nil {
		return err
	}
	if err := deleteMapKey(main, key); err != nil {
		return err
	}
	return owners.Delete(key)
}

func (m *MapOperations) CreateMupUplinkV4Owned(instance uint32, endpoint string, teid uint32, bits uint8, entry *HeadendEntry, owner OwnerTag) error {
	key, err := buildMupUplinkV4Key(instance, endpoint, teid, bits)
	if err != nil {
		return err
	}
	if entry == nil {
		return errors.New("nil MUP uplink entry")
	}
	m.controlLifecycle.Lock()
	defer m.controlLifecycle.Unlock()
	value := *entry
	value.GroupId = EcmpGroupNone
	return putControlEntry(m.objs.MupUplinkV4Map, m.mupUplinkV4Owners, key, &value, owner, true)
}
func (m *MapOperations) DeleteMupUplinkV4Owned(instance uint32, endpoint string, teid uint32, bits uint8, owner OwnerTag) error {
	key, err := buildMupUplinkV4Key(instance, endpoint, teid, bits)
	if err != nil {
		return err
	}
	m.controlLifecycle.Lock()
	defer m.controlLifecycle.Unlock()
	return deleteControlEntry[MupUplinkV4Key, HeadendEntry](m.objs.MupUplinkV4Map, m.mupUplinkV4Owners, key, owner, true)
}
func (m *MapOperations) CreateMupUplinkV6Owned(instance uint32, endpoint string, teid uint32, bits uint8, entry *HeadendEntry, owner OwnerTag) error {
	key, err := buildMupUplinkV6Key(instance, endpoint, teid, bits)
	if err != nil {
		return err
	}
	if entry == nil {
		return errors.New("nil MUP uplink entry")
	}
	m.controlLifecycle.Lock()
	defer m.controlLifecycle.Unlock()
	value := *entry
	value.GroupId = EcmpGroupNone
	return putControlEntry(m.objs.MupUplinkV6Map, m.mupUplinkV6Owners, key, &value, owner, true)
}
func (m *MapOperations) DeleteMupUplinkV6Owned(instance uint32, endpoint string, teid uint32, bits uint8, owner OwnerTag) error {
	key, err := buildMupUplinkV6Key(instance, endpoint, teid, bits)
	if err != nil {
		return err
	}
	m.controlLifecycle.Lock()
	defer m.controlLifecycle.Unlock()
	return deleteControlEntry[MupUplinkV6Key, HeadendEntry](m.objs.MupUplinkV6Map, m.mupUplinkV6Owners, key, owner, true)
}

func (m *MapOperations) CreateFdbOwned(bdID uint16, mac net.HardwareAddr, entry *FdbEntry, owner OwnerTag) error {
	if len(mac) != 6 || entry == nil {
		return errors.New("FDB requires an Ethernet MAC and entry")
	}
	m.controlLifecycle.Lock()
	defer m.controlLifecycle.Unlock()
	value := *entry
	// RPC callers retain their explicit static/dynamic setting. Route-owned
	// entries must survive aging and BPF remote-MAC learning.
	if owner != OwnerRPC {
		value.IsStatic = 1
		value.LastSeen = 0
	}
	return putControlEntry(m.objs.FdbMap, m.fdbOwners, buildFdbKey(bdID, mac), &value, owner, false)
}
func (m *MapOperations) DeleteFdbOwned(bdID uint16, mac net.HardwareAddr, owner OwnerTag) error {
	if len(mac) != 6 {
		return errors.New("FDB requires an Ethernet MAC")
	}
	m.controlLifecycle.Lock()
	defer m.controlLifecycle.Unlock()
	return deleteControlEntry[FdbKey, FdbEntry](m.objs.FdbMap, m.fdbOwners, buildFdbKey(bdID, mac), owner, false)
}

func (m *MapOperations) CreateBdPeerOwned(bdID, index uint16, entry *HeadendEntry, esi [ESILen]byte, remoteSrc [IPv6AddrLen]byte, writeReverse bool, owner OwnerTag) error {
	m.bdPeerLifecycle.Lock()
	defer m.bdPeerLifecycle.Unlock()
	return m.createBdPeerOwnedLocked(bdID, index, entry, esi, remoteSrc, writeReverse, owner)
}
func (m *MapOperations) createBdPeerOwnedLocked(bdID, index uint16, entry *HeadendEntry, esi [ESILen]byte, remoteSrc [IPv6AddrLen]byte, writeReverse bool, owner OwnerTag) error {
	if entry == nil {
		return errors.New("nil BD peer entry")
	}
	key := &BdPeerKey{BdId: bdID, Index: index}
	owned, err := checkControlOwner[BdPeerKey, HeadendEntry](m.objs.BdPeerMap, m.bdPeerOwners, key, owner, false)
	if err != nil {
		return err
	}
	if !owned && strings.HasPrefix(string(owner), "plugin:") {
		present, err := m.bdPeerCompanionsPresent(bdID, index)
		if err != nil {
			return err
		}
		if present {
			return fmt.Errorf("%w: untagged BD peer companions", ErrEntryOwnerMismatch)
		}
	}
	if writeReverse {
		var existing BdPeerReverseVal
		err := m.objs.BdPeerReverseMap.Lookup(&BdPeerReverseKey{BdId: bdID, SrcAddr: remoteSrc}, &existing)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
		if err == nil && existing.Index != index {
			// The reverse key is shared across slots. It cannot be taken from
			// another producer, even when the new forward slot is free.
			tag, ok, err := m.bdPeerOwners.Lookup(&BdPeerKey{BdId: bdID, Index: existing.Index})
			if err != nil {
				return err
			}
			if (ok && tag != owner) || (!ok && strings.HasPrefix(string(owner), "plugin:")) {
				return fmt.Errorf("%w: BD reverse entry belongs to another peer", ErrEntryOwnerMismatch)
			}
		}
	}
	if !owned {
		if err := m.bdPeerOwners.Put(key, owner); err != nil {
			return err
		}
	}
	err = m.createBdPeerLocked(bdID, index, entry, esi, remoteSrc, writeReverse)
	if err != nil && !owned && !errors.Is(err, ErrBdPeerForwardLeaked) {
		present, inspectErr := m.bdPeerCompanionsPresent(bdID, index)
		if present || inspectErr != nil {
			return errors.Join(err, inspectErr, ErrBdPeerForwardLeaked)
		}
		if cleanupErr := m.bdPeerOwners.Delete(key); cleanupErr != nil {
			return errors.Join(err, cleanupErr, ErrBdPeerForwardLeaked)
		}
	}
	return err
}
func (m *MapOperations) CreateBdPeerAtFreeIndexOwned(bdID uint16, entry *HeadendEntry, esi [ESILen]byte, remoteSrc [IPv6AddrLen]byte, writeReverse bool, owner OwnerTag) (uint16, error) {
	m.bdPeerLifecycle.Lock()
	defer m.bdPeerLifecycle.Unlock()
	index := m.findFreeBdPeerIndexLocked(bdID)
	if index >= MaxBumNexthops {
		return index, fmt.Errorf("bd %d: maximum number of peers (%d) reached", bdID, MaxBumNexthops)
	}
	if _, err := m.deleteBdPeerOwnedLocked(bdID, index, owner); err != nil {
		return index, err
	}
	return index, m.createBdPeerOwnedLocked(bdID, index, entry, esi, remoteSrc, writeReverse, owner)
}
func (m *MapOperations) DeleteBdPeerOwned(bdID, index uint16, owner OwnerTag) (bool, error) {
	m.bdPeerLifecycle.Lock()
	defer m.bdPeerLifecycle.Unlock()
	return m.deleteBdPeerOwnedLocked(bdID, index, owner)
}
func (m *MapOperations) deleteBdPeerOwnedLocked(bdID, index uint16, owner OwnerTag) (bool, error) {
	key := &BdPeerKey{BdId: bdID, Index: index}
	owned, err := checkControlOwner[BdPeerKey, HeadendEntry](m.objs.BdPeerMap, m.bdPeerOwners, key, owner, false)
	if err != nil {
		return true, err
	}
	if !owned && strings.HasPrefix(string(owner), "plugin:") {
		present, err := m.bdPeerCompanionsPresent(bdID, index)
		if err != nil {
			return true, err
		}
		if present {
			return true, fmt.Errorf("%w: untagged BD peer companions", ErrEntryOwnerMismatch)
		}
	}
	existed, err := m.deleteBdPeerLocked(bdID, index)
	if err != nil {
		return existed || owned, err
	}
	if err := m.bdPeerOwners.Delete(key); err != nil {
		return true, err
	}
	return existed, nil
}

// Companion remnants occupy a peer slot even when the forward entry is gone.
func (m *MapOperations) bdPeerCompanionsPresent(bdID, index uint16) (bool, error) {
	var key BdPeerReverseKey
	var value BdPeerReverseVal
	it := m.objs.BdPeerReverseMap.Iterate()
	for it.Next(&key, &value) {
		if key.BdId == bdID && value.Index == index {
			return true, nil
		}
	}
	if err := it.Err(); err != nil {
		return false, err
	}
	var ext BpfBdPeerL2ExtVal
	err := m.objs.BdPeerL2ExtMap.Lookup(&BpfBdPeerL2ExtKey{BdId: bdID, Index: index}, &ext)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, nil
	}
	return err == nil, err
}

func listEntryOwners[K comparable](owners *entryOwnerMap) (map[K]OwnerTag, error) {
	result := make(map[K]OwnerTag)
	if owners == nil {
		return result, nil
	}
	var key K
	var value [auxOwnerTagBytes]byte
	it := owners.m.Iterate()
	for it.Next(&key, &value) {
		tag, ok := decodeOwnerTag(value[:])
		if !ok {
			return nil, errors.New("invalid persisted entry owner")
		}
		result[key] = OwnerTag(tag)
	}
	return result, it.Err()
}
func (m *MapOperations) ListMupUplinkV4Owners() (map[MupUplinkV4Key]OwnerTag, error) {
	return listEntryOwners[MupUplinkV4Key](m.mupUplinkV4Owners)
}

// ListHeadendV4Owners includes reservations left after partial deletion.
func (m *MapOperations) ListHeadendV4Owners() (map[string]OwnerTag, error) {
	owners, err := listEntryOwners[LpmKeyV4](m.headendV4Owners)
	result := make(map[string]OwnerTag, len(owners))
	for key, owner := range owners {
		result[lpmKeyV4ToString(&key)] = owner
	}
	return result, err
}

// ListHeadendV6Owners is the IPv6 counterpart of ListHeadendV4Owners.
func (m *MapOperations) ListHeadendV6Owners() (map[string]OwnerTag, error) {
	owners, err := listEntryOwners[LpmKeyV6](m.headendV6Owners)
	result := make(map[string]OwnerTag, len(owners))
	for key, owner := range owners {
		result[lpmKeyV6ToString(&key)] = owner
	}
	return result, err
}
func (m *MapOperations) ListMupUplinkV6Owners() (map[MupUplinkV6Key]OwnerTag, error) {
	return listEntryOwners[MupUplinkV6Key](m.mupUplinkV6Owners)
}
func (m *MapOperations) ListFdbOwners() (map[FdbKey]OwnerTag, error) {
	return listEntryOwners[FdbKey](m.fdbOwners)
}
func (m *MapOperations) ListBdPeerOwners() (map[BdPeerKey]OwnerTag, error) {
	return listEntryOwners[BdPeerKey](m.bdPeerOwners)
}
func (m *MapOperations) GetFdbOwner(bdID uint16, mac net.HardwareAddr) (OwnerTag, bool, error) {
	return m.fdbOwners.Lookup(buildFdbKey(bdID, mac))
}
func (m *MapOperations) GetBdPeerOwner(bdID, index uint16) (OwnerTag, bool, error) {
	return m.bdPeerOwners.Lookup(&BdPeerKey{BdId: bdID, Index: index})
}
func (m *MapOperations) GetMupUplinkV4Owner(instance uint32, endpoint string, teid uint32, bits uint8) (OwnerTag, bool, error) {
	key, err := buildMupUplinkV4Key(instance, endpoint, teid, bits)
	if err != nil {
		return "", false, err
	}
	return m.mupUplinkV4Owners.Lookup(key)
}
func (m *MapOperations) GetMupUplinkV6Owner(instance uint32, endpoint string, teid uint32, bits uint8) (OwnerTag, bool, error) {
	key, err := buildMupUplinkV6Key(instance, endpoint, teid, bits)
	if err != nil {
		return "", false, err
	}
	return m.mupUplinkV6Owners.Lookup(key)
}
