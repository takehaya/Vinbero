// Package mup provides typed selectors and GTP4 builders for the pinned
// GoBGP MUP draft-01 codec. It does not resolve routes or write host state.
package mup

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/takehaya/vinbero/sdk/go/cplane/gobgppath"
	"github.com/takehaya/vinbero/sdk/go/cplane/resolve"
	"github.com/takehaya/vinbero/sdk/go/cplane/routes"
)

// DirectSegment is the pinned codec's two-octet/four-octet identifier.
// Zero is a valid identifier; Value.State distinguishes it from absence.
type DirectSegment struct {
	High uint16
	Low  uint32
}
type ST1 struct {
	RD       string
	Prefix   netip.Prefix
	Endpoint netip.Addr
	Source   resolve.Value[netip.Addr]
	TEID     uint32
	QFI      uint8
	Service  resolve.Value[gobgppath.ServiceSID]
}
type ISD struct {
	RD      string
	Prefix  netip.Prefix
	Service resolve.Value[gobgppath.ServiceSID]
}
type ST2 struct {
	RD       string
	Endpoint netip.Addr
	TEID     uint32
	TEIDBits uint8
	Direct   resolve.Value[DirectSegment]
	Service  resolve.Value[gobgppath.ServiceSID]
}
type DSD struct {
	RD      string
	Address netip.Addr
	Direct  resolve.Value[DirectSegment]
	Service resolve.Value[gobgppath.ServiceSID]
}

var ST1Endpoint = resolve.Field[ST1, netip.Addr]{Name: "ST1.endpoint", Get: func(v ST1) resolve.Value[netip.Addr] { return resolve.Known(v.Endpoint) }}
var ISDPrefix = resolve.Field[ISD, netip.Prefix]{Name: "ISD.prefix", Get: func(v ISD) resolve.Value[netip.Prefix] { return resolve.Known(v.Prefix) }}
var ST2DirectSegment = resolve.Field[ST2, DirectSegment]{Name: "ST2.direct_segment", Get: func(v ST2) resolve.Value[DirectSegment] { return v.Direct }}
var DSDDirectSegment = resolve.Field[DSD, DirectSegment]{Name: "DSD.direct_segment", Get: func(v DSD) resolve.Value[DirectSegment] { return v.Direct }}

func families() []string { return []string{"mup_ipv4", "mup_ipv6"} }
func ST1Selector() resolve.Selector[ST1] {
	return resolve.Selector[ST1]{Families: families(), Project: projectST1}
}
func ISDSelector() resolve.Selector[ISD] {
	return resolve.Selector[ISD]{Families: families(), Project: projectISD}
}
func ST2Selector() resolve.Selector[ST2] {
	return resolve.Selector[ST2]{Families: families(), Project: projectST2}
}
func DSDSelector() resolve.Selector[DSD] {
	return resolve.Selector[DSD]{Families: families(), Project: projectDSD}
}

func route(e routes.Entry, kind uint16) (*bgp.MUPNLRI, resolve.State, string) {
	if e.Path == nil {
		return nil, resolve.Invalid, "missing packet model"
	}
	n, ok := e.Path.NLRI.(*bgp.MUPNLRI)
	if !ok || n == nil || e.Path.Withdraw {
		return nil, resolve.Missing, "not a MUP announcement"
	}
	if n.ArchitectureType != bgp.MUP_ARCH_TYPE_3GPP_5G {
		return nil, resolve.Invalid, "unsupported MUP architecture"
	}
	if n.RouteType != kind {
		return nil, resolve.Missing, "different MUP route type"
	}
	if (n.Afi == bgp.AFI_IP && e.Family != "mup_ipv4") || (n.Afi == bgp.AFI_IP6 && e.Family != "mup_ipv6") || (n.Afi != bgp.AFI_IP && n.Afi != bgp.AFI_IP6) {
		return nil, resolve.Invalid, "MUP family mismatch"
	}
	return n, resolve.Present, ""
}
func usableIP(a netip.Addr) bool {
	return a.IsValid() && !a.Is4In6() && a.Zone() == "" && a.IsGlobalUnicast()
}
func prefixValid(p netip.Prefix, afi uint16) bool {
	return p.IsValid() && !p.Addr().Is4In6() && ((afi == bgp.AFI_IP && p.Addr().Is4()) || (afi == bgp.AFI_IP6 && p.Addr().Is6()))
}
func service(e routes.Entry) resolve.Value[gobgppath.ServiceSID] {
	sid, err := gobgppath.ReadServiceSID(e.Path.Attributes, bgp.TLVTypeSRv6L3Service)
	if err == nil {
		return resolve.Known(sid)
	}
	state := resolve.Invalid
	if errors.Is(err, gobgppath.ErrMissingSID) {
		state = resolve.Missing
	} else if errors.Is(err, gobgppath.ErrAmbiguousSID) {
		state = resolve.Ambiguous
	}
	return resolve.Value[gobgppath.ServiceSID]{State: state, Reason: err.Error()}
}
func direct(e routes.Entry) resolve.Value[DirectSegment] {
	var result DirectSegment
	count := 0
	unsupported := false
	for _, a := range e.Path.Attributes {
		ec, ok := a.(*bgp.PathAttributeExtendedCommunities)
		if !ok {
			continue
		}
		if ec == nil {
			return resolve.Bad[DirectSegment]("nil extended communities")
		}
		for _, c := range ec.Value {
			if c == nil {
				return resolve.Bad[DirectSegment]("nil extended community")
			}
			typ, sub := c.GetTypes()
			if typ != bgp.EC_TYPE_MUP {
				continue
			}
			m, ok := c.(*bgp.MUPExtended)
			if sub != bgp.EC_SUBTYPE_MUP_DIRECT_SEG || !ok || m == nil || m.SubType != bgp.EC_SUBTYPE_MUP_DIRECT_SEG {
				unsupported = true
				continue
			}
			count++
			result = DirectSegment{m.SegmentID2, m.SegmentID4}
		}
	}
	if unsupported {
		return resolve.Bad[DirectSegment]("unsupported_mup_community: only pinned Direct subtype 0 is supported; mixed kinds are rejected")
	}
	if count == 0 {
		return resolve.Absent[DirectSegment]("missing_direct_segment: ST2+ISD is unsupported")
	}
	if count != 1 {
		return resolve.Value[DirectSegment]{State: resolve.Ambiguous, Reason: "duplicate_direct_segment"}
	}
	return resolve.Known(result)
}
func projectST1(e routes.Entry) resolve.Value[ST1] {
	n, state, reason := route(e, bgp.MUP_ROUTE_TYPE_TYPE_1_SESSION_TRANSFORMED)
	if state != resolve.Present {
		return resolve.Value[ST1]{State: state, Reason: reason}
	}
	r, ok := n.RouteTypeData.(*bgp.MUPType1SessionTransformedRoute)
	if !ok || r == nil || r.RD == nil || !prefixValid(r.Prefix, n.Afi) || !usableIP(r.EndpointAddress) || int(r.EndpointAddressLength) != r.EndpointAddress.BitLen() || !r.TEID.Is4() {
		return resolve.Bad[ST1]("invalid ST1 fields")
	}
	source := resolve.Absent[netip.Addr]("source absent")
	if r.SourceAddress != nil {
		if !usableIP(*r.SourceAddress) || int(r.SourceAddressLength) != r.SourceAddress.BitLen() {
			return resolve.Bad[ST1]("invalid source")
		}
		source = resolve.Known(*r.SourceAddress)
	} else if r.SourceAddressLength != 0 {
		return resolve.Bad[ST1]("source length without source")
	}
	teid := r.TEID.As4()
	return resolve.Known(ST1{r.RD.String(), r.Prefix.Masked(), r.EndpointAddress, source, binary.BigEndian.Uint32(teid[:]), r.QFI, service(e)})
}
func projectISD(e routes.Entry) resolve.Value[ISD] {
	n, state, reason := route(e, bgp.MUP_ROUTE_TYPE_INTERWORK_SEGMENT_DISCOVERY)
	if state != resolve.Present {
		return resolve.Value[ISD]{State: state, Reason: reason}
	}
	r, ok := n.RouteTypeData.(*bgp.MUPInterworkSegmentDiscoveryRoute)
	if !ok || r == nil || r.RD == nil || !prefixValid(r.Prefix, n.Afi) {
		return resolve.Bad[ISD]("invalid ISD fields")
	}
	// Missing or unusable service information remains on the candidate. A
	// builder failure must not cause selection of a less-specific ISD.
	return resolve.Known(ISD{r.RD.String(), r.Prefix.Masked(), service(e)})
}
func projectST2(e routes.Entry) resolve.Value[ST2] {
	n, state, reason := route(e, bgp.MUP_ROUTE_TYPE_TYPE_2_SESSION_TRANSFORMED)
	if state != resolve.Present {
		return resolve.Value[ST2]{State: state, Reason: reason}
	}
	r, ok := n.RouteTypeData.(*bgp.MUPType2SessionTransformedRoute)
	if !ok || r == nil || r.RD == nil || !usableIP(r.EndpointAddress) || !r.TEID.Is4() {
		return resolve.Bad[ST2]("invalid ST2 fields")
	}
	if (n.Afi == bgp.AFI_IP) != r.EndpointAddress.Is4() {
		return resolve.Bad[ST2]("ST2 endpoint family mismatch")
	}
	bits := int(r.EndpointAddressLength) - r.EndpointAddress.BitLen()
	if bits < 0 || bits > 32 {
		return resolve.Bad[ST2]("invalid ST2 TEID prefix length")
	}
	teid := r.TEID.As4()
	value := binary.BigEndian.Uint32(teid[:]) & (^uint32(0) << uint(32-bits))
	return resolve.Known(ST2{r.RD.String(), r.EndpointAddress, value, uint8(bits), direct(e), service(e)})
}
func projectDSD(e routes.Entry) resolve.Value[DSD] {
	n, state, reason := route(e, bgp.MUP_ROUTE_TYPE_DIRECT_SEGMENT_DISCOVERY)
	if state != resolve.Present {
		return resolve.Value[DSD]{State: state, Reason: reason}
	}
	r, ok := n.RouteTypeData.(*bgp.MUPDirectSegmentDiscoveryRoute)
	if !ok || r == nil || r.RD == nil || !usableIP(r.Address) || (n.Afi == bgp.AFI_IP) != r.Address.Is4() {
		return resolve.Bad[DSD]("invalid DSD fields")
	}
	return resolve.Known(DSD{r.RD.String(), r.Address, direct(e), service(e)})
}
