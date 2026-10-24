package bpf

import (
	"fmt"
	"net/netip"
)

// CreateEsiPeer records an exact IPv6 source as an RT4 member of an ES.
// Only the host writes this unpinned map; local attachment is checked by BPF.
func (m *MapOperations) CreateEsiPeer(esi [ESILen]byte, source [IPv6AddrLen]byte) error {
	if esi == [ESILen]byte{} {
		return fmt.Errorf("all-zero ESI is reserved as single-homing sentinel")
	}
	addr := netip.AddrFrom16(source)
	if addr.IsUnspecified() || addr.IsMulticast() || addr.Is4In6() {
		return fmt.Errorf("ESI peer source must be a unicast IPv6 address")
	}
	key := &BpfEsiPeerKey{Esi: esi, SrcAddr: source}
	present := uint8(1)
	if err := m.objs.EsiPeerMap.Put(key, &present); err != nil {
		return fmt.Errorf("failed to put ESI peer membership: %w", err)
	}
	return nil
}

// DeleteEsiPeer removes only this ES/source pair. Missing membership is safe
// to delete again after a failed reconcile or an RT4 withdrawal replay.
func (m *MapOperations) DeleteEsiPeer(esi [ESILen]byte, source [IPv6AddrLen]byte) error {
	key := &BpfEsiPeerKey{Esi: esi, SrcAddr: source}
	if err := deleteMapKey(m.objs.EsiPeerMap, key); err != nil {
		return fmt.Errorf("failed to delete ESI peer membership: %w", err)
	}
	return nil
}
