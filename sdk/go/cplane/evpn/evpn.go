// Package evpn projects the initial single-homed L2 forwarding profile. It does
// not select a BGP best path, implement MAC mobility, or manage bridge domains.
package evpn

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/gobgppath"
	"github.com/takehaya/vinbero/sdk/go/cplane/resolve"
	"github.com/takehaya/vinbero/sdk/go/cplane/routes"
)

// Projections own every value a builder reads. The zero-ESI, Ethernet-tag-zero
// profile is checked by builders, so unsupported candidates stay diagnosable.
type RT2 struct {
	RD          string
	ESI         [10]byte
	EthernetTag uint32
	MAC         [6]byte
	IP          netip.Addr
	Remote      netip.Addr
	Service     gobgppath.ServiceSID
}
type RT3 struct {
	RD          string
	EthernetTag uint32
	Originator  netip.Addr
	Remote      netip.Addr
	Service     gobgppath.ServiceSID
}

func RT2Selector() resolve.Selector[RT2] {
	return resolve.Selector[RT2]{Families: []string{"evpn"}, Project: func(e routes.Entry) resolve.Value[RT2] {
		n, err := packet(e)
		if err != nil {
			return resolve.Bad[RT2](err.Error())
		}
		r, ok := n.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)
		if !ok {
			return resolve.Absent[RT2]("not RT2")
		}
		if r == nil || r.RD == nil || r.MacAddressLength != 48 || len(r.MacAddress) != 6 || len(r.ESI.Value) > 9 {
			return resolve.Bad[RT2]("malformed RT2")
		}
		remote, sid, err := service(e)
		if err != nil {
			return resolve.Bad[RT2](err.Error())
		}
		out := RT2{RD: r.RD.String(), EthernetTag: r.ETag, IP: r.IPAddress, Remote: remote, Service: sid}
		out.ESI[0] = byte(r.ESI.Type)
		copy(out.ESI[1:], r.ESI.Value)
		copy(out.MAC[:], r.MacAddress)
		return resolve.Known(out)
	}}
}
func RT3Selector() resolve.Selector[RT3] {
	return resolve.Selector[RT3]{Families: []string{"evpn"}, Project: func(e routes.Entry) resolve.Value[RT3] {
		n, err := packet(e)
		if err != nil {
			return resolve.Bad[RT3](err.Error())
		}
		r, ok := n.RouteTypeData.(*bgp.EVPNMulticastEthernetTagRoute)
		if !ok {
			return resolve.Absent[RT3]("not RT3")
		}
		if r == nil || r.RD == nil || !r.IPAddress.IsValid() {
			return resolve.Bad[RT3]("malformed RT3")
		}
		remote, sid, err := service(e)
		if err != nil {
			return resolve.Bad[RT3](err.Error())
		}
		return resolve.Known(RT3{r.RD.String(), r.ETag, r.IPAddress, remote, sid})
	}}
}

func packet(e routes.Entry) (*bgp.EVPNNLRI, error) {
	if e.Path == nil || e.Path.Withdraw {
		return nil, fmt.Errorf("missing EVPN packet")
	}
	n, ok := e.Path.NLRI.(*bgp.EVPNNLRI)
	if !ok || n == nil {
		return nil, fmt.Errorf("not an EVPN NLRI")
	}
	return n, nil
}
func service(e routes.Entry) (netip.Addr, gobgppath.ServiceSID, error) {
	var next netip.Addr
	count := 0
	for _, a := range e.Path.Attributes {
		if mp, ok := a.(*bgp.PathAttributeMpReachNLRI); ok {
			count++
			if mp == nil || mp.AFI != bgp.AFI_L2VPN || mp.SAFI != bgp.SAFI_EVPN || mp.LinkLocalNexthop.IsValid() {
				return next, gobgppath.ServiceSID{}, fmt.Errorf("unsupported EVPN next hop")
			}
			next = mp.Nexthop
		}
	}
	if count != 1 || !usable(next) {
		return next, gobgppath.ServiceSID{}, fmt.Errorf("one IPv6 MP_REACH next hop required")
	}
	sid, err := gobgppath.ReadServiceSID(e.Path.Attributes, bgp.TLVTypeSRv6L2Service)
	return next, sid, err
}
func usable(a netip.Addr) bool {
	return a.Is6() && !a.Is4In6() && a.IsGlobalUnicast() && a.Zone() == ""
}

func forward(context string, source, remote netip.Addr, service gobgppath.ServiceSID, behavior bgp.SRBehavior) (cplane.EVPNForward, error) {
	var out cplane.EVPNForward
	st := service.Structure
	if context == "" || !usable(source) || !usable(remote) || !usable(service.Address) || service.Flags != 0 || service.Behavior != uint16(behavior) {
		return out, fmt.Errorf("unsupported EVPN forwarding profile")
	}
	if service.HasStructure && (int(st.LocatorBlock)+int(st.LocatorNode)+int(st.Function)+int(st.Argument) > 128 || st.TranspositionLength != 0 || st.TranspositionOffset != 0) {
		return out, fmt.Errorf("unsupported SID structure")
	}
	return cplane.EVPNForward{Context: context, Segments: []string{service.Address.String()}, SrcAddr: source.String(), RemoteSrc: remote.String()}, nil
}

// BuildStaticMAC uses an RT2 End.DT2U SID for one remote static MAC. Selection
// and MAC-mobility policy belong to the caller; the host arbitrates conflicts.
func BuildStaticMAC(route RT2, context string, source netip.Addr) (cplane.EVPNForward, error) {
	if route.ESI != [10]byte{} || route.EthernetTag != 0 || route.MAC == [6]byte{} || route.MAC[0]&1 != 0 {
		return cplane.EVPNForward{}, fmt.Errorf("unicast MAC, zero ESI and zero Ethernet tag required")
	}
	out, err := forward(context, source, route.Remote, route.Service, bgp.END_DT2U)
	if err != nil {
		return out, err
	}
	out.MAC = net.HardwareAddr(route.MAC[:]).String()
	return out, nil
}

// BuildFlood uses an RT3 End.DT2M SID. The host keeps this flood peer out of the
// reverse lookup used for remote MAC learning.
func BuildFlood(route RT3, context string, source netip.Addr) (cplane.EVPNForward, error) {
	if route.EthernetTag != 0 {
		return cplane.EVPNForward{}, fmt.Errorf("zero Ethernet tag required")
	}
	out, err := forward(context, source, route.Remote, route.Service, bgp.END_DT2M)
	if err != nil {
		return out, err
	}
	out.Flood = true
	return out, nil
}
