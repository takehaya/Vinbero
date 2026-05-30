package export

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

// NetlinkVRFResolver is the production VRFResolver: it looks a VRF device up
// by name over netlink and returns its ifindex and the routing table its
// l3mdev owns. The exporter needs the ifindex to build the End.DT4/DT6 aux
// entry and the table id to match route events to the VRF.
type NetlinkVRFResolver struct{}

// Resolve implements VRFResolver.
func (NetlinkVRFResolver) Resolve(vrfName string) (ifindex uint32, table uint32, err error) {
	link, err := netlink.LinkByName(vrfName)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup link %q: %w", vrfName, err)
	}
	vrf, ok := link.(*netlink.Vrf)
	if !ok {
		return 0, 0, fmt.Errorf("link %q is not a VRF device (type %s)", vrfName, link.Type())
	}
	return uint32(link.Attrs().Index), vrf.Table, nil
}
