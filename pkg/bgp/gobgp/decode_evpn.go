package gobgp

import (
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// decodeEVPNRoute builds Vinbero's EVPNRoute view of a received EVPN NLRI
// (AFI 25 / SAFI 70). Only RT2 (MAC/IP) is decoded in Phase E1; other
// route types return nil so the subscriber skips them until their phase
// (RT3 in E2, RT4 in E3).
func decodeEVPNRoute(p *apiutil.Path) *bgp.EVPNRoute {
	nlri, ok := p.Nlri.(*gobgppkt.EVPNNLRI)
	if !ok {
		return nil
	}
	switch rt := nlri.RouteTypeData.(type) {
	case *gobgppkt.EVPNMacIPAdvertisementRoute:
		return decodeEVPNMacIP(p, rt)
	default:
		return nil
	}
}

// decodeEVPNMacIP decodes an RT2 MAC/IP Advertisement. The End.DT2U
// service SID rides in the BGP Prefix-SID attribute's SRv6 L2 Service TLV
// (RFC 9252 §6.2); decodeSRv6SID handles both L2 and L3 TLVs and folds in
// any RFC 9252 transposition carried in the NLRI's first label.
func decodeEVPNMacIP(p *apiutil.Path, rt *gobgppkt.EVPNMacIPAdvertisementRoute) *bgp.EVPNRoute {
	r := &bgp.EVPNRoute{
		Type:        bgp.EVPNRouteTypeMACIP,
		EthernetTag: rt.ETag,
		ESI:         esiToArray(rt.ESI),
		RTs:         decodeRouteTargets(p.Attrs),
		NextHop:     decodeNextHop(p.Attrs),
	}
	if rt.RD != nil {
		r.RD = rt.RD.String()
	}
	if len(rt.MacAddress) == 6 {
		r.MAC = rt.MacAddress.String()
	}
	if rt.IPAddress.IsValid() && !rt.IPAddress.IsUnspecified() {
		r.IPAddr = rt.IPAddress.String()
	}
	var label uint32
	if len(rt.Labels) > 0 {
		label = rt.Labels[0]
	}
	r.SRv6SID = decodeSRv6SID(p.Attrs, label)
	return r
}

// esiToArray renders a gobgp ESI as the RFC 7432 10-byte identifier:
// one Type octet followed by the 9-octet value (matching the wire
// serialization).
func esiToArray(esi gobgppkt.EthernetSegmentIdentifier) [10]byte {
	var out [10]byte
	out[0] = byte(esi.Type)
	copy(out[1:], esi.Value)
	return out
}
