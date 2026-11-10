package vinbero

import (
	"slices"

	"github.com/takehaya/vinbero/pkg/netresource"
	"github.com/takehaya/vinbero/pkg/vrf"
)

// tableCloseGuard is the netresource.TableCloseGuard of the daemon: it reads
// the L2 headend circuits from the pinned map and the host's links.
func (v *Vinbero) tableCloseGuard(name string, table uint32, members []string) (*netresource.L2CircuitOnTable, error) {
	if v.mapOps == nil {
		return nil, nil
	}
	circuits, err := v.mapOps.HeadendL2Circuits()
	if err != nil || len(circuits) == 0 {
		return nil, err
	}
	links, err := vrf.SnapshotLinks()
	if err != nil {
		return nil, err
	}
	return l2CircuitOnTable(links, circuits, name, table, members), nil
}

// l2CircuitOnTable returns the first L2 headend circuit, by port ifindex,
// on a port the unreachable default of table would cut off: a port of any
// VRF device on the table (managed by Vinbero or not) or of the device
// name, or one of members, which name is to enslave. circuits are the
// circuits' VLANs by port ifindex.
func l2CircuitOnTable(links vrf.Links, circuits map[uint32][]uint16, name string, table uint32, members []string) *netresource.L2CircuitOnTable {
	vrfOf := map[uint32]string{} // port ifindex -> VRF name
	for ifindex, l := range links {
		master, ok := links[l.Master]
		if l.Master == 0 || !ok || !master.IsVrf {
			continue
		}
		if master.VrfTable == table || master.Name == name {
			vrfOf[ifindex] = master.Name
		}
	}
	for ifindex, l := range links {
		if slices.Contains(members, l.Name) {
			vrfOf[ifindex] = name
		}
	}
	ports := make([]uint32, 0, len(vrfOf))
	for ifindex := range vrfOf {
		ports = append(ports, ifindex)
	}
	slices.Sort(ports)
	for _, ifindex := range ports {
		if vlans := circuits[ifindex]; len(vlans) > 0 {
			return &netresource.L2CircuitOnTable{Port: links[ifindex].Name, VLAN: vlans[0], VRF: vrfOf[ifindex]}
		}
	}
	return nil
}
