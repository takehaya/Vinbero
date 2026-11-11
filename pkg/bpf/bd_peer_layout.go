package bpf

import (
	"fmt"
	"sort"
	"strings"
)

// IsFloodRangeEsPeer reports whether a peer at index is an Ethernet Segment
// peer in the flood range: it carries an ECMP group, which only the
// synthetic ES peers of EVPN aliasing do. Such a peer comes from pinned maps
// of a run that used the earlier index layout, in which the flood slots and
// the RT2 peers shared [0, 8) and the ES peers took [8, 40).
func IsFloodRangeEsPeer(index uint16, entry *HeadendEntry) bool {
	return FloodPeerRange.Contains(index) && entry != nil && entry.GroupId != EcmpGroupNone
}

// CheckBdPeerLayout refuses bd_peer state the index layout gives no meaning
// to: a peer in the flood range that carries an ECMP group. Nothing of this
// version writes one, so it is an Ethernet Segment peer of the earlier
// layout (IsFloodRangeEsPeer) that the EVPN startup sweep did not remove
// because another owner wrote it. Left in place it would hold a flood slot,
// and the FDB entries pointing at it would be rewritten by MAC learning as
// if it were a remote PE, so the start stops here and names each one rather
// than guessing what it is. It reads the maps only.
func (m *MapOperations) CheckBdPeerLayout() error {
	peers, err := m.ListBdPeers()
	if err != nil {
		return err
	}
	owners, err := m.ListBdPeerOwners()
	if err != nil {
		return fmt.Errorf("list bd_peer owners: %w", err)
	}
	var found []string
	for k, e := range peers {
		if !IsFloodRangeEsPeer(k.Index, e) {
			continue
		}
		owner := "no owner"
		if tag, ok := owners[k]; ok {
			owner = string(tag)
		}
		found = append(found, fmt.Sprintf("peer {bd %d, index %d} with ECMP group %d (%s)", k.BdId, k.Index, e.GroupId, owner))
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
	return fmt.Errorf("the pinned bridge-domain maps hold Ethernet Segment peers in the %s range (%d in all): %s. "+
		"They were written under the layout in which flood slots and RT2 peers share [0, 8) and Ethernet Segment peers take [8, 40). "+
		"Start vinberod with BGP enabled under the ASN that owns them, which removes the EVPN entries its applier wrote, "+
		"or stop vinberod, remove the pin directory and configure the bridge domains again",
		FloodPeerRange, len(found), list)
}
