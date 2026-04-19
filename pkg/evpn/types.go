// Package evpn defines RFC 7432 / RFC 9252 BGP EVPN route-type handling for Vinbero.
// pkg/bgp decodes UPDATEs into evpn.Route values and passes them to a Handler,
// which applies them to the underlying BPF maps.
package evpn

// Fixed lengths from RFC 7432 / RFC 8200. Kept local to keep pkg/evpn free of
// BPF-layer dependencies; an importing package should pick whichever constant
// it already has.
const (
	ESILen     = 10
	IPv6Length = 16
	MACLength  = 6
)

// RouteType enumerates the RFC 7432 / RFC 9252 EVPN NLRI types Vinbero cares
// about. RT5 (IP Prefix) and RT6/RT7 (multicast) are intentionally omitted;
// they're out of scope per docs/plan/dt2m-esi.md.
type RouteType uint8

const (
	RouteTypeUnspecified        RouteType = 0
	RouteTypeEthernetAutoDisc   RouteType = 1 // RT1: Ethernet A-D per-ES / per-EVI
	RouteTypeMACIPAdvertisement RouteType = 2 // RT2: MAC / IP Advertisement → fdb_map / bd_peer_map
	RouteTypeInclusiveMulticast RouteType = 3 // RT3: Inclusive Multicast → bd_peer_map (BUM nexthops)
	RouteTypeEthernetSegment    RouteType = 4 // RT4: Ethernet Segment → esi_map (DF election)
)

// Payload is the closed set of per-RouteType bodies a Route can carry.
// Implementing `isPayload()` keeps Phase E's type switches exhaustive:
// a new payload must explicitly opt in, and unrelated types can't leak in.
type Payload interface {
	isPayload()
}

// Route is the common envelope for a decoded EVPN NLRI.
type Route struct {
	Type               RouteType
	RouteDistinguisher string
	ESI                [ESILen]byte // RFC 7432 10-byte ESI (zero = N/A for this type)
	Payload            Payload
}

// MACIPAdvertisement is the RT2 payload: a MAC→PE mapping to install in fdb_map.
type MACIPAdvertisement struct {
	MAC         [MACLength]byte
	IPAddr      [IPv6Length]byte // optional; zero if NLRI carries MAC only
	BDID        uint16
	PESrcAddr   [IPv6Length]byte
	SegmentList [][IPv6Length]byte
}

// InclusiveMulticast is the RT3 payload: this peer is a BUM endpoint for BDID.
type InclusiveMulticast struct {
	BDID      uint16
	PESrcAddr [IPv6Length]byte
}

// EthernetSegment is the RT4 payload: DF election input for ESI.
type EthernetSegment struct {
	ESI              [ESILen]byte
	PESrcAddr        [IPv6Length]byte
	IsDFCandidate    bool
}

func (MACIPAdvertisement) isPayload() {}
func (InclusiveMulticast) isPayload() {}
func (EthernetSegment) isPayload()    {}

// Handler consumes decoded EVPN routes and reflects them into Vinbero's BPF maps.
type Handler interface {
	ApplyRoute(Route) error
	WithdrawRoute(Route) error
}
