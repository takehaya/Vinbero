package gobgp

import (
	"net/netip"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// decodeVPNRoute builds the Vinbero VPNRoute view of a received VPNv4 /
// VPNv6 path: RD + prefix from the NLRI, the SRv6 service SID from the
// BGP Prefix-SID attribute (RFC 9252), route targets from extended
// communities, and the next hop from MP_REACH_NLRI.
func decodeVPNRoute(p *apiutil.Path, fam bgp.Family) *bgp.VPNRoute {
	vr := &bgp.VPNRoute{Family: fam}
	var label uint32
	if vpn, ok := p.Nlri.(*gobgppkt.LabeledVPNIPAddrPrefix); ok {
		vr.Prefix = vpn.Prefix.String()
		if vpn.RD != nil {
			vr.RD = vpn.RD.String()
		}
		// RFC 9252 transposition may carry part of the SRv6 SID in the
		// VPN label; decodeSRv6SID folds it back into the SID.
		if len(vpn.Labels.Labels) > 0 {
			label = vpn.Labels.Labels[0]
		}
	} else if p.Nlri != nil {
		// Unexpected NLRI shape: keep the generic rendering rather than
		// dropping the route silently so the anomaly is still visible.
		vr.Prefix = p.Nlri.String()
	}
	// SID and structure come from one walk so they are guaranteed to
	// describe the same Information Sub-TLV -- pairing the SID of one
	// TLV with the structure of another could misclassify the encap mode.
	if sid, st, ok := srv6ServiceSIDBytes(p.Attrs, label, gobgppkt.TLVTypeSRv6L3Service); ok {
		if addr, ok := netip.AddrFromSlice(sid); ok {
			vr.SRv6SID = addr.String()
			vr.SIDStructure = st
		}
	}
	vr.RTs = decodeRouteTargets(p.Attrs)
	vr.NextHop = decodeNextHop(p.Attrs)
	vr.Color = decodeColor(p.Attrs)
	return vr
}

// decodeColor returns the value of the Color Extended Community (RFC 9012
// §4.3) on the path, or 0 when none is present. When several are present
// the highest color value wins. CO bits (Color-Only steering) are not
// interpreted in Phase 1e-c -- CO=00 is assumed.
func decodeColor(attrs []gobgppkt.PathAttributeInterface) uint32 {
	var color uint32
	for _, a := range attrs {
		ec, ok := a.(*gobgppkt.PathAttributeExtendedCommunities)
		if !ok {
			continue
		}
		for _, c := range ec.Value {
			if col, ok := c.(*gobgppkt.ColorExtended); ok && col.Color > color {
				color = col.Color
			}
		}
	}
	return color
}

// decodeSRv6SID walks the BGP Prefix-SID attribute (RFC 9252) and
// returns the first SRv6 service SID as an IPv6 string. When the SID
// Structure Sub-Sub-TLV signals transposition, the transposed bits are
// folded back in from the VPN label (RFC 9252 §4); label is the route's
// MPLS label. An empty result means the path carried no SRv6 SID.
func decodeSRv6SID(attrs []gobgppkt.PathAttributeInterface, label uint32, tlvType gobgppkt.TLVType) string {
	sid, _, ok := srv6ServiceSIDBytes(attrs, label, tlvType)
	if !ok {
		return ""
	}
	addr, ok := netip.AddrFromSlice(sid)
	if !ok {
		return ""
	}
	return addr.String()
}

// srv6ServiceSIDBytes returns the reconstructed 16-byte service SID and
// the SID Structure of the same Information Sub-TLV (zero when the peer did
// not signal one), folding any RFC 9252 transposed label bits back in. Only
// Service TLVs of tlvType are considered -- RFC 9252 ties the TLV type to
// the route type (L3 for VPN-IP and MUP, L2 for EVPN), so a stray TLV of
// the other kind on a path must not supply the SID. ok is false when no
// usable SID is found. A Sub-TLV whose structure fails semantic validation
// is skipped entirely (RFC 9252 Sec.7 treats a path without valid SID
// information as ineligible).
func srv6ServiceSIDBytes(attrs []gobgppkt.PathAttributeInterface, label uint32, tlvType gobgppkt.TLVType) ([]byte, bgp.SIDStructure, bool) {
	for _, a := range attrs {
		psid, ok := a.(*gobgppkt.PathAttributePrefixSID)
		if !ok {
			continue
		}
		for _, tlv := range psid.TLVs {
			svc, ok := tlv.(*gobgppkt.SRv6ServiceTLV)
			if !ok || svc.Type != tlvType {
				continue
			}
			for _, st := range svc.SubTLVs {
				info, ok := st.(*gobgppkt.SRv6InformationSubTLV)
				if !ok || len(info.SID) != 16 {
					continue
				}
				structure, ok := sidStructureOf(info, tlvType == gobgppkt.TLVTypeSRv6L3Service)
				if !ok {
					continue
				}
				sid := info.SID
				if structure.TranspositionLen != 0 {
					folded := make([]byte, 16)
					copy(folded, info.SID)
					if !foldTransposedLabel(folded, label,
						structure.TranspositionLen, structure.TranspositionOffset) {
						// Transposition is signalled but the SID Structure
						// Sub-Sub-TLV is malformed: the real SID cannot be
						// rebuilt, so skip it rather than use a wrong target.
						continue
					}
					sid = folded
				}
				return sid, structure, true
			}
		}
	}
	return nil, bgp.SIDStructure{}, false
}

// sidStructureOf returns the SID Structure Sub-Sub-TLV of an Information
// Sub-TLV. ok is false when a structure is present but semantically invalid
// -- all off-the-wire values are attacker-controlled. Rejected shapes:
// length fields that cannot fit a 128-bit SID, a transposition offset
// without a transposition length, and -- for an L3 Service TLV, where RFC
// 9252 §4.1 transposes function bits -- a transposition longer than the
// Function field. On an L2 Service TLV the TL/FL relation is not checked:
// EVPN routes transpose argument bits (§6.1/§6.2). TO+TL is bounded only
// by the 128-bit SID, not by LBL+LNL+FL+AL: FRR's classic-mode
// advertisements place the transposed function AFTER the declared
// structure (32/16/16/0 with TO=64 -- see TestDecodeSRv6SID_Transposition,
// captured from real FRR), so the stricter Errata 7817 bound would break
// interop with deployed implementations.
func sidStructureOf(info *gobgppkt.SRv6InformationSubTLV, l3 bool) (bgp.SIDStructure, bool) {
	for _, ss := range info.SubSubTLVs {
		st, isStruct := ss.(*gobgppkt.SRv6SIDStructureSubSubTLV)
		if !isStruct {
			continue
		}
		if int(st.LocatorBlockLength)+int(st.LocatorNodeLength)+
			int(st.FunctionLength)+int(st.ArgumentLength) > 128 {
			return bgp.SIDStructure{}, false
		}
		if st.TranspositionLength == 0 && st.TranspositionOffset != 0 {
			return bgp.SIDStructure{}, false
		}
		if int(st.TranspositionOffset)+int(st.TranspositionLength) > 128 {
			return bgp.SIDStructure{}, false
		}
		if l3 && st.TranspositionLength != 0 {
			if st.TranspositionLength > st.FunctionLength {
				return bgp.SIDStructure{}, false
			}
			// The label carries (part of) the Function, which sits after
			// Locator Block + Node: a transposition offset inside the
			// locator would let the label rewrite the locator itself.
			// FRR's real offsets (48 for usid-f3216, 64 for classic) both
			// satisfy this.
			if int(st.TranspositionOffset) <
				int(st.LocatorBlockLength)+int(st.LocatorNodeLength) {
				return bgp.SIDStructure{}, false
			}
		}
		return bgp.SIDStructure{
			LocatorBlockLen:     st.LocatorBlockLength,
			LocatorNodeLen:      st.LocatorNodeLength,
			FunctionLen:         st.FunctionLength,
			ArgumentLen:         st.ArgumentLength,
			TranspositionLen:    st.TranspositionLength,
			TranspositionOffset: st.TranspositionOffset,
		}, true
	}
	return bgp.SIDStructure{}, true
}

// decodeSIDStructure returns the SID Structure Sub-Sub-TLV (RFC 9252
// Sec.3.2.1) accompanying the path's service SID, or the zero value when
// the peer did not signal one.
func decodeSIDStructure(attrs []gobgppkt.PathAttributeInterface) bgp.SIDStructure {
	_, st, _ := srv6ServiceSIDBytes(attrs, 0, gobgppkt.TLVTypeSRv6L3Service)
	return st
}

// srv6SIDLocatorLen returns the locator length in bits (LocatorBlockLen +
// LocatorNodeLen) of a decoded SID Structure, or 0 when there is no
// structure or the value is out of range.
func srv6SIDLocatorLen(st bgp.SIDStructure) uint8 {
	n := int(st.LocatorBlockLen) + int(st.LocatorNodeLen)
	if n <= 0 || n > 128 {
		return 0
	}
	return uint8(n)
}

// decodeRemoteSrc derives the advertising PE's SRv6 encap source from a
// received L2 service SID: the SID masked to its locator length. The length
// comes from the SID Structure Sub-Sub-TLV; when that is absent it falls back
// to fallbackLen. Returns "" if there is no usable SID. The End.DT2 RX path
// keys split-horizon and remote-MAC learning on this remote source -- distinct
// from the local encap source the bd_peer's SrcAddr holds for TX.
//
// This assumes the remote PE's outer encap source equals its SID's locator base
// (true Vinbero-to-Vinbero, where encapSource() returns the source-locator
// prefix). A third-party PE that sources packets from an address outside the
// SID locator (e.g. a loopback) would not match the data plane's full-outer-src
// reverse-map key; third-party interop is future work.
func decodeRemoteSrc(attrs []gobgppkt.PathAttributeInterface, label uint32, fallbackLen uint8) string {
	sid, structure, ok := srv6ServiceSIDBytes(attrs, label, gobgppkt.TLVTypeSRv6L2Service)
	if !ok {
		return ""
	}
	locLen := srv6SIDLocatorLen(structure)
	if locLen == 0 {
		locLen = fallbackLen
	}
	addr, ok := netip.AddrFromSlice(sid)
	if !ok {
		return ""
	}
	prefix, err := addr.Prefix(int(locLen))
	if err != nil {
		return ""
	}
	return prefix.Addr().String()
}


// foldTransposedLabel reconstructs an SRv6 SID whose bits were
// transposed into the VPN MPLS label (RFC 9252 §4): the high-order
// `length` bits of the 20-bit label are OR-ed into sid at bit `offset`
// counted from the SID's most significant bit. RFC 9252 §4 requires the
// on-wire SID to have that bit range zeroed, so OR-folding is sufficient
// -- and a range that is NOT zero is a malformed advertisement whose
// real SID cannot be known, not something to merge bits into. It returns
// false, leaving sid untouched, when the parameters or the SID bits --
// all attacker-controlled off the wire -- cannot describe a valid
// transposition.
func foldTransposedLabel(sid []byte, label uint32, length, offset uint8) bool {
	const mplsLabelBits = 20
	if length == 0 || length > mplsLabelBits || int(offset)+int(length) > 8*len(sid) {
		return false
	}
	for i := 0; i < int(length); i++ {
		pos := int(offset) + i
		if sid[pos/8]&(byte(1)<<uint(7-pos%8)) != 0 {
			return false
		}
	}
	val := (label & (1<<mplsLabelBits - 1)) >> (mplsLabelBits - length)
	for i := 0; i < int(length); i++ {
		if (val>>uint(int(length)-1-i))&1 == 0 {
			continue
		}
		pos := int(offset) + i
		sid[pos/8] |= byte(1) << uint(7-pos%8)
	}
	return true
}

// decodeRouteTargets returns every route-target extended community on
// the path, each rendered "as:admin" (e.g. "65000:100"). Non-RT
// communities (Site-of-Origin etc.) share the same wire types and are
// distinguished by sub-type.
func decodeRouteTargets(attrs []gobgppkt.PathAttributeInterface) []string {
	var rts []string
	for _, a := range attrs {
		ec, ok := a.(*gobgppkt.PathAttributeExtendedCommunities)
		if !ok {
			continue
		}
		for _, c := range ec.Value {
			if _, sub := c.GetTypes(); sub == gobgppkt.EC_SUBTYPE_ROUTE_TARGET {
				rts = append(rts, c.String())
			}
		}
	}
	return rts
}

// decodeESImportRT returns the ES-Import route target (RFC 7432 §7.6) carried
// on the path, rendered as a MAC string, or "" if absent. RT4 signals Ethernet
// Segment membership with this community (sub-type EC_SUBTYPE_ES_IMPORT), which
// is distinct from the ordinary route targets decodeRouteTargets returns.
func decodeESImportRT(attrs []gobgppkt.PathAttributeInterface) string {
	for _, a := range attrs {
		ec, ok := a.(*gobgppkt.PathAttributeExtendedCommunities)
		if !ok {
			continue
		}
		for _, c := range ec.Value {
			if esi, ok := c.(*gobgppkt.ESImportRouteTarget); ok {
				return esi.ESImport.String()
			}
		}
	}
	return ""
}

// decodeNextHop returns the path's next hop. VPN families carry it in
// MP_REACH_NLRI; plain IPv4 unicast uses the legacy NEXT_HOP attribute.
func decodeNextHop(attrs []gobgppkt.PathAttributeInterface) string {
	for _, a := range attrs {
		switch attr := a.(type) {
		case *gobgppkt.PathAttributeMpReachNLRI:
			if attr.Nexthop.IsValid() {
				return attr.Nexthop.String()
			}
		case *gobgppkt.PathAttributeNextHop:
			if attr.Value.IsValid() {
				return attr.Value.String()
			}
		}
	}
	return ""
}

// nlriString renders an NLRI, tolerating a nil interface value.
func nlriString(n gobgppkt.NLRI) string {
	if n == nil {
		return ""
	}
	return n.String()
}
