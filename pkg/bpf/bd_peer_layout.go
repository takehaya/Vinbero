package bpf

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// CheckBdPeerLayout refuses bd_peer state that the index layout gives no
// meaning to: a peer, an owner record, a reverse entry or a remote FDB entry
// at an index of the reserved part of the flood range. This version never
// writes there, so such an entry comes from pinned maps of a run that used
// the earlier layout, in which the flood slots and the RT2 peers shared
// [0, 8) and the Ethernet Segment peers took [8, 40). The EVPN startup sweep
// removes what the BGP applier of the configured ASN wrote; anything left
// would turn into a flood slot once the flood range grows, so the start
// stops here and names each entry rather than guessing what it is. It reads
// the maps only.
func (m *MapOperations) CheckBdPeerLayout() error {
	r := ReservedFloodPeerRange
	if r.Count == 0 {
		return nil
	}
	var found []string
	peers, err := m.ListBdPeers()
	if err != nil {
		return err
	}
	owners, err := m.ListBdPeerOwners()
	if err != nil {
		return fmt.Errorf("list bd_peer owners: %w", err)
	}
	owner := func(k BdPeerKey) string {
		if tag, ok := owners[k]; ok {
			return string(tag)
		}
		return "no owner"
	}
	for k := range peers {
		if r.Contains(k.Index) {
			found = append(found, fmt.Sprintf("peer {bd %d, index %d} (%s)", k.BdId, k.Index, owner(k)))
		}
	}
	for k, tag := range owners {
		if _, ok := peers[k]; !ok && r.Contains(k.Index) {
			found = append(found, fmt.Sprintf("owner record {bd %d, index %d} (%s) without a peer", k.BdId, k.Index, tag))
		}
	}
	var (
		rk BdPeerReverseKey
		rv BdPeerReverseVal
	)
	it := m.objs.BdPeerReverseMap.Iterate()
	for it.Next(&rk, &rv) {
		if r.Contains(rv.Index) {
			found = append(found, fmt.Sprintf("reverse entry {bd %d, source %s} -> index %d", rk.BdId, netip.AddrFrom16(rk.SrcAddr), rv.Index))
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("list bd_peer reverse entries: %w", err)
	}
	fdbs, err := m.ListFdb()
	if err != nil {
		return err
	}
	fdbOwners, err := m.ListFdbOwners()
	if err != nil {
		return fmt.Errorf("list fdb owners: %w", err)
	}
	for k, e := range fdbs {
		if e.IsRemote == 0 || !r.Contains(e.PeerIndex) {
			continue
		}
		tag := "no owner"
		if t, ok := fdbOwners[k]; ok {
			tag = string(t)
		}
		found = append(found, fmt.Sprintf("FDB entry {bd %d, %s} -> peer index %d (%s)", k.BdId, net.HardwareAddr(k.Mac[:]), e.PeerIndex, tag))
	}
	if len(found) == 0 {
		return nil
	}
	sort.Strings(found)
	const shown = 8
	list := strings.Join(found[:min(len(found), shown)], "; ")
	if len(found) > shown {
		list += fmt.Sprintf("; and %d more", len(found)-shown)
	}
	return fmt.Errorf("the pinned bridge-domain maps use peer indices of the %s range, which the peer index layout keeps free (%d in all): %s. "+
		"They were written under the layout in which flood slots and RT2 peers share [0, 8) and Ethernet Segment peers take [8, 40). "+
		"Start vinberod with BGP enabled under the ASN that owns them, which removes the EVPN entries its applier wrote, "+
		"or stop vinberod, remove the pin directory and configure the bridge domains again",
		r, len(found), list)
}
