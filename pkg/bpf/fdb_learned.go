package bpf

import (
	"errors"
	"net"

	"github.com/cilium/ebpf"
)

// LearnFdb mirrors a kernel bridge observation without claiming RPC ownership.
// It reports whether a local entry was installed, so callers only advertise
// MACs backed by local forwarding. Managed entries are protected by the lock;
// unowned static/remote checks are snapshots relative to BPF learners.
func (m *MapOperations) LearnFdb(bdID uint16, mac net.HardwareAddr, oif uint32) (bool, error) {
	if bdID == 0 || len(mac) != 6 || mac[0]&1 != 0 || oif == 0 {
		return false, errors.New("FDB learning requires a bridge domain, unicast MAC and output interface")
	}
	m.controlLifecycle.Lock()
	defer m.controlLifecycle.Unlock()
	key := buildFdbKey(bdID, mac)
	if _, owned, err := m.fdbOwners.Lookup(key); err != nil || owned {
		return false, err
	}
	// Retry once if a BPF learner inserts/deletes between lookup and update.
	for range 2 {
		var current FdbEntry
		err := m.objs.FdbMap.Lookup(key, &current)
		flags := ebpf.UpdateExist
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			flags = ebpf.UpdateNoExist
		} else if err != nil {
			return false, err
		} else if current.IsStatic != 0 || current.IsRemote != 0 {
			return false, nil
		}
		value := FdbEntry{Oif: oif, BdId: bdID, LastSeen: currentKtimeNs()}
		err = m.objs.FdbMap.Update(key, &value, flags)
		if errors.Is(err, ebpf.ErrKeyExist) || errors.Is(err, ebpf.ErrKeyNotExist) {
			continue
		}
		return err == nil, err
	}
	return false, nil
}

// DeleteLearnedFdb removes only an unowned dynamic local entry on the observed
// interface. A stale kernel DEL must not delete a route installed meanwhile.
func (m *MapOperations) DeleteLearnedFdb(bdID uint16, mac net.HardwareAddr, oif uint32) error {
	if bdID == 0 || len(mac) != 6 || mac[0]&1 != 0 || oif == 0 {
		return errors.New("FDB learning requires a bridge domain, unicast MAC and output interface")
	}
	m.controlLifecycle.Lock()
	defer m.controlLifecycle.Unlock()
	key := buildFdbKey(bdID, mac)
	if _, owned, err := m.fdbOwners.Lookup(key); err != nil || owned {
		return err
	}
	var current FdbEntry
	if err := m.objs.FdbMap.Lookup(key, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return err
	}
	if current.IsStatic != 0 || current.IsRemote != 0 || current.Oif != oif {
		return nil
	}
	// Like aging, the guard is a best-effort snapshot relative to unowned
	// BPF learners; controlLifecycle serializes every managed publication.
	return deleteMapKey(m.objs.FdbMap, key)
}
