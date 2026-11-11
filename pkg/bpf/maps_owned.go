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
	defer m.encapWrote(headendDst(entry)...)
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
	defer m.encapWrote(headendDst(entry)...)
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
	// Success or not, the xdp-mode devmap follows whatever bd_peer_map
	// holds afterwards, rollbacks included. The rebuild runs once per
	// public call, after the lock is released.
	defer m.resyncBum(bdID)
	m.bdPeerLifecycle.Lock()
	defer m.bdPeerLifecycle.Unlock()
	return m.createBdPeerOwnedLocked(bdID, index, entry, esi, remoteSrc, writeReverse, owner)
}
func (m *MapOperations) createBdPeerOwnedLocked(bdID, index uint16, entry *HeadendEntry, esi [ESILen]byte, remoteSrc [IPv6AddrLen]byte, writeReverse bool, owner OwnerTag) error {
	defer m.encapWrote(headendDst(entry)...)
	if entry == nil {
		return errors.New("nil BD peer entry")
	}
	if err := checkBdPeerIndex(index, entry); err != nil {
		return fmt.Errorf("bd %d: %w", bdID, err)
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

// BdPeerUpdate is one in-place rewrite for UpdateBdPeersOwned.
type BdPeerUpdate struct {
	Index uint16
	Entry *HeadendEntry
	ESI   [ESILen]byte
}

// UpdateBdPeersOwned rewrites existing bd_peer entries of one bridge domain
// in place: the forward entry and its ESI side entry. The reverse map is
// not touched, so an update cannot move a reverse entry another peer of the
// BD shares. All updates run under one lifecycle lock and the BD's BUM
// state is rebuilt once, however many peers change. It returns one error
// per update (nil where the update was written); a slot that is no longer
// present is an error, not a create.
func (m *MapOperations) UpdateBdPeersOwned(bdID uint16, updates []BdPeerUpdate, owner OwnerTag) []error {
	errs := make([]error, len(updates))
	if len(updates) == 0 {
		return errs
	}
	defer m.resyncBum(bdID)
	m.bdPeerLifecycle.Lock()
	defer m.bdPeerLifecycle.Unlock()
	var noRemoteSrc [IPv6AddrLen]byte
	for i, u := range updates {
		var cur HeadendEntry
		if err := m.objs.BdPeerMap.Lookup(&BdPeerKey{BdId: bdID, Index: u.Index}, &cur); err != nil {
			errs[i] = fmt.Errorf("bd %d peer %d: %w", bdID, u.Index, err)
			continue
		}
		errs[i] = m.createBdPeerOwnedLocked(bdID, u.Index, u.Entry, u.ESI, noRemoteSrc, false, owner)
	}
	return errs
}

// CreateBdPeerAtFreeIndexOwned installs entry at the lowest free index of the
// range it belongs to (PeerRangeFor: the unicast range for a FloodExclude
// entry, the flood slots otherwise), probing and creating under one critical
// section. A full range returns ErrBdPeerRangeFull, and the next freed index
// of that range in this BD runs the hook SetBdPeerFreedHook installed.
func (m *MapOperations) CreateBdPeerAtFreeIndexOwned(bdID uint16, entry *HeadendEntry, esi [ESILen]byte, remoteSrc [IPv6AddrLen]byte, writeReverse bool, owner OwnerTag) (uint16, error) {
	defer m.notifyBdPeerFreed()
	defer m.resyncBum(bdID)
	m.bdPeerLifecycle.Lock()
	defer m.bdPeerLifecycle.Unlock()
	r := PeerRangeFor(entry)
	rk := bdPeerRangeKey{bd: bdID, base: r.Base}
	index, ok := m.findFreeBdPeerIndexLocked(bdID, r)
	if !ok {
		if m.bdPeerStarved == nil {
			m.bdPeerStarved = make(map[bdPeerRangeKey]struct{})
		}
		m.bdPeerStarved[rk] = struct{}{}
		return r.End(), fmt.Errorf("%w: bd %d: all %d %s peer indices are in use", ErrBdPeerRangeFull, bdID, r.Count, r.Name)
	}
	delete(m.bdPeerStarved, rk)
	if _, err := m.deleteBdPeerOwnedLocked(bdID, index, owner); err != nil {
		return index, err
	}
	return index, m.createBdPeerOwnedLocked(bdID, index, entry, esi, remoteSrc, writeReverse, owner)
}
func (m *MapOperations) DeleteBdPeerOwned(bdID, index uint16, owner OwnerTag) (bool, error) {
	defer m.notifyBdPeerFreed()
	defer m.resyncBum(bdID)
	m.bdPeerLifecycle.Lock()
	defer m.bdPeerLifecycle.Unlock()
	return m.deleteBdPeerOwnedLocked(bdID, index, owner)
}

// checkBdPeerIndex refuses an index outside the flood, Ethernet Segment and
// unicast ranges (the reserved part of the flood range included: nothing
// floods to it yet), and a flood peer (FloodExclude clear) in the unicast
// range, where nothing would ever flood to it either.
func checkBdPeerIndex(index uint16, entry *HeadendEntry) error {
	switch {
	case FloodPeerRange.Contains(index), EsPeerRange.Contains(index):
		return nil
	case UnicastPeerRange.Contains(index):
		if entry.FloodExclude == 0 {
			return fmt.Errorf("peer index %d is in the %s range, which is never flooded to, but the entry is a flood peer", index, UnicastPeerRange)
		}
		return nil
	}
	return fmt.Errorf("peer index %d is outside the %s, %s and %s ranges", index, FloodPeerRange, EsPeerRange, UnicastPeerRange)
}

// bdPeerRangeKey is one allocation range (by its base) of one BD.
type bdPeerRangeKey struct {
	bd   uint16
	base uint16
}

// SetBdPeerFreedHook installs what runs when an index is freed in a range a
// CreateBdPeerAtFreeIndex found full in that bridge domain: the daemon
// replays the EVPN routes, so a route that did not fit is installed. It runs
// after the bd_peer lock is released, once per call that freed such an
// index, and must not block.
func (m *MapOperations) SetBdPeerFreedHook(f func()) { m.onBdPeerFreed.Store(&f) }

// noteBdPeerFreedLocked records that the index of the BD is free again. The
// caller holds bdPeerLifecycle.
func (m *MapOperations) noteBdPeerFreedLocked(bdID, index uint16) {
	for _, r := range []BdPeerRange{FloodPeerRange, UnicastPeerRange} {
		if !r.Contains(index) {
			continue
		}
		rk := bdPeerRangeKey{bd: bdID, base: r.Base}
		if _, starved := m.bdPeerStarved[rk]; starved {
			delete(m.bdPeerStarved, rk)
			m.bdPeerFreed.Store(true)
		}
	}
}

// notifyBdPeerFreed runs the freed hook if the call it is deferred in freed
// an index a full range was waiting for. Called without bdPeerLifecycle.
func (m *MapOperations) notifyBdPeerFreed() {
	if !m.bdPeerFreed.Swap(false) {
		return
	}
	if f := m.onBdPeerFreed.Load(); f != nil {
		(*f)()
	}
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
	if existed || owned {
		m.noteBdPeerFreedLocked(bdID, index)
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

// ListHeadendV4Owners lists the owners of the global VRF (vrf_id 0) by
// trigger prefix, including reservations left after partial deletion.
func (m *MapOperations) ListHeadendV4Owners() (map[string]OwnerTag, error) {
	owners, err := m.ListHeadendV4OwnerIDs()
	return globalOnly(owners), err
}

// ListHeadendV6Owners is the IPv6 counterpart of ListHeadendV4Owners.
func (m *MapOperations) ListHeadendV6Owners() (map[string]OwnerTag, error) {
	owners, err := m.ListHeadendV6OwnerIDs()
	return globalOnly(owners), err
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
