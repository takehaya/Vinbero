// Package bgp is Vinbero's BGP control-plane integration. It defines a
// BGPd-agnostic interface surface so the daemon can embed GoBGP today
// (pkg/bgp/gobgp) and, if needed later, swap in an out-of-process BGP
// speaker without touching the call sites.
//
// The surface is split into four roles per the GoBGP integration plan
// (docs/plan/gobgp-integration.md §2.2):
//
//   - Session            -- peer / global lifecycle, no data path
//   - RouteAdvertiser    -- push local state out as BGP routes
//   - RouteSubscriber    -- receive BGP routes into Vinbero
//   - SRPolicyController -- SR Policy specific receive / advertise
//
// Phase 1c implements Session only (peer establishment). The other
// three interfaces are defined here so Phase 1d / 1e can fill them in
// without reshaping the package.
package bgp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
)

// ValidateIPv6NextHop validates a BGP next hop for an advertised SRv6 route and
// returns the parsed address. SRv6 VPN / SR Policy / MUP / EVPN transport is
// IPv6-only, so the next hop must be a specific, routable IPv6 address: empty,
// IPv4, v4-in-6, and the unspecified address (::) are all rejected. :: in
// particular would originate a blackhole next hop no receiving PE can forward
// toward, reachable over the unauthenticated RPC surface. Shared by every
// advertise path (pkg/bgp/export, pkg/server) so they enforce it identically.
func ValidateIPv6NextHop(nextHop string) (netip.Addr, error) {
	// Messages are subject-neutral so each caller can prefix the source (e.g.
	// "bgp.global.next_hop") without repeating the word "next_hop".
	if nextHop == "" {
		return netip.Addr{}, errors.New("is required (a routable IPv6 address)")
	}
	a, err := netip.ParseAddr(nextHop)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%q is not a valid IP address", nextHop)
	}
	// Must be a global-scope IPv6 unicast address a remote PE can forward toward:
	// reject IPv4 / v4-in-6, and the unspecified (::), loopback (::1),
	// link-local (fe80::/10), and multicast (ff00::/8) addresses, which would all
	// originate a route no PE can use.
	if !a.Is6() || a.Is4In6() || a.IsUnspecified() || a.IsLoopback() ||
		a.IsLinkLocalUnicast() || a.IsMulticast() {
		return netip.Addr{}, fmt.Errorf("%q must be a routable IPv6 address", nextHop)
	}
	return a, nil
}

// Session lifecycle errors. Exposed as sentinels so callers can branch
// with errors.Is rather than string-matching.
var (
	ErrSessionNotStarted     = errors.New("bgp: session not started")
	ErrSessionAlreadyStarted = errors.New("bgp: session already started")
)

// Family identifies an AFI/SAFI pair in operator-friendly form. The
// gobgp adapter maps these to api.Family values.
type Family string

const (
	FamilyVPNv4        Family = "vpnv4"
	FamilyVPNv6        Family = "vpnv6"
	FamilyIPv4Unicast  Family = "ipv4_unicast"
	FamilyIPv6Unicast  Family = "ipv6_unicast"
	FamilySRPolicyIPv6 Family = "sr_policy_ipv6"
	FamilyEVPN         Family = "evpn"     // AFI 25 (L2VPN) / SAFI 70 (EVPN)
	FamilyMUPIPv4      Family = "mup_ipv4" // AFI 1 (IPv4) / SAFI 85 (BGP MUP, GTP4)
	FamilyMUPIPv6      Family = "mup_ipv6" // AFI 2 (IPv6) / SAFI 85 (BGP MUP, GTP6)
)

// String renders the family for logs and error messages.
func (f Family) String() string { return string(f) }

// Valid reports whether f is one of the recognized families.
func (f Family) Valid() bool {
	switch f {
	case FamilyVPNv4, FamilyVPNv6, FamilyIPv4Unicast, FamilyIPv6Unicast, FamilySRPolicyIPv6, FamilyEVPN, FamilyMUPIPv4, FamilyMUPIPv6:
		return true
	default:
		return false
	}
}

// ParseFamily validates an operator-supplied family string (as written
// in vinbero.yml) and returns the typed Family.
func ParseFamily(s string) (Family, error) {
	f := Family(s)
	if !f.Valid() {
		return "", fmt.Errorf("unknown BGP family %q (want vpnv4|vpnv6|ipv4_unicast|ipv6_unicast|sr_policy_ipv6|evpn|mup_ipv4|mup_ipv6)", s)
	}
	return f, nil
}

// GlobalConfig is the BGP speaker's own identity.
type GlobalConfig struct {
	LocalASN uint32
	RouterID string
	// ListenPort is the TCP port the speaker binds. -1 disables the
	// listener entirely (in-process / passive-only operation), which is
	// the default for Vinbero so it can coexist with a host BGP daemon.
	ListenPort int32
}

// PeerConfig describes a single BGP neighbor.
type PeerConfig struct {
	Neighbor     string
	PeerASN      uint32
	HoldTimeSec  uint32
	KeepaliveSec uint32
	Families     []Family
	// Passive keeps this neighbor from initiating the TCP connection; the
	// session is established only when the remote dials in. In an iBGP
	// full mesh both ends would otherwise dial each other at once, and the
	// resulting connection collision makes gobgp tear a freshly
	// ESTABLISHED socket back down, flapping the session. Marking one end
	// of every pair passive pins each pair to a single direction. Note both
	// ends passive forms no session at all (nobody dials), and both ends
	// active reintroduces the flap -- exactly one end of each pair must be set.
	Passive bool
	// ConnectRetrySec is the BGP ConnectRetry timer in seconds. gobgp's
	// default is 120s; a smaller value reconnects faster after a startup or
	// transient failure. Governs the pre-establishment dial only.
	ConnectRetrySec uint32
	// AddPathsReceive negotiates ADD-PATH receive (RFC 7911) for every
	// family of this neighbor, so the peer may send several paths for one
	// NLRI and each arrives with its own PathID.
	//
	// It matters behind a route reflector, which by default reflects only
	// its best path per NLRI: without ADD-PATH the client simply never sees
	// the other PEs' paths and no amount of receiver-side work recovers
	// them. In an iBGP full mesh every PE already sends its own path
	// directly, so this is not needed there.
	//
	// This is receive-only. Vinbero does not advertise multiple paths for
	// its own NLRIs, so the send direction stays off.
	AddPathsReceive bool
}

// PeerState is a read-only snapshot of a neighbor's session.
type PeerState struct {
	Neighbor     string
	PeerASN      uint32
	SessionState string // "idle" / "connect" / "active" / "opensent" / "openconfirm" / "established"
}

// Session owns peer and global lifecycle. It carries no data-path
// responsibility -- route exchange lives in the other three interfaces.
type Session interface {
	Start(ctx context.Context, cfg GlobalConfig) error
	Stop(ctx context.Context) error
	AddPeer(ctx context.Context, p PeerConfig) error
	DeletePeer(ctx context.Context, neighbor string) error
	Peers(ctx context.Context) ([]PeerState, error)
}

// RouteKey identifies a previously-advertised route for withdrawal.
type RouteKey struct {
	Family Family
	Prefix string
	RD     string // route distinguisher; empty for non-VPN families
}

// VPNRoute is an L3VPN (VPNv4 / VPNv6) route carrying an SRv6 service
// SID. Fields are intentionally minimal for Phase 1c; Phase 1d/1e fill
// in the SID structure and extended-community detail.
type VPNRoute struct {
	Family  Family
	Prefix  string
	RD      string
	RTs     []string
	SRv6SID string
	NextHop string
	// Color is the value of the Color Extended Community (RFC 9012 §4.3),
	// or 0 when the route carries none. A non-zero color requests
	// auto-steering onto the SR Policy keyed by {Color, NextHop}.
	Color uint32
}

// Key returns the RouteKey that identifies this VPN route for withdrawal.
func (r VPNRoute) Key() RouteKey {
	return RouteKey{Family: r.Family, Prefix: r.Prefix, RD: r.RD}
}

// UnicastRoute is a plain IPv6 unicast route.
type UnicastRoute struct {
	Prefix  string
	NextHop string
}

// RouteAdvertiser pushes Vinbero's local state out to BGP peers.
// Implemented in Phase 1e.
type RouteAdvertiser interface {
	Advertise(ctx context.Context, r VPNRoute) error
	AdvertiseUnicast(ctx context.Context, r UnicastRoute) error
	Withdraw(ctx context.Context, key RouteKey) error
}

// PathSource identifies which BGP path an update came from, so a consumer
// can hold several paths for one NLRI instead of collapsing them.
//
// Without it a receiver can only key on the NLRI, and a second PE
// advertising the same prefix is indistinguishable from an update to the
// first PE's route. That is what blocks ECMP: the paths are all present on
// the wire and gobgp delivers each one, but the receiver has nowhere to put
// the second.
//
// Peer is the neighbor the path was learned from, and is the zero Addr for
// a locally originated path (which is how ListRoutes tells the two apart).
// PathID is the ADD-PATH identifier (RFC 7911) as sent by that peer; it is
// 0 unless ADD-PATH receive is negotiated, and is only unique within a
// peer, so a path is identified by the pair and never by PathID alone.
type PathSource struct {
	Peer   netip.Addr
	PathID uint32
}

// IsLocal reports whether the path was originated by this node rather than
// learned from a neighbor.
func (s PathSource) IsLocal() bool { return !s.Peer.IsValid() }

// String renders the source for logs: "local" for a locally originated
// path, the bare peer address when no ADD-PATH id applies, and
// "<peer address>#<path id>" otherwise.
func (s PathSource) String() string {
	if s.IsLocal() {
		return "local"
	}
	if s.PathID == 0 {
		return s.Peer.String()
	}
	return fmt.Sprintf("%s#%d", s.Peer, s.PathID)
}

// RouteEvent is a single received BGP route update delivered to a
// RouteHandler. IsWithdraw distinguishes a withdrawal from an
// advertisement.
type RouteEvent struct {
	Family Family
	// Source identifies the path this update belongs to. Consumers that
	// keep per-path state must include it in their key; consumers that
	// only track the NLRI can ignore it.
	Source     PathSource
	VPN        *VPNRoute
	Unicast    *UnicastRoute
	SRPolicy   *SRPolicy
	EVPN       *EVPNRoute
	MUP        *MUPRoute
	IsWithdraw bool
}

// RouteHandler consumes received BGP routes. It is invoked from a
// GoBGP-internal goroutine; implementations must not block.
type RouteHandler func(ev RouteEvent)

// RouteSubscriber delivers received BGP routes to Vinbero. Implemented
// in Phase 1d.
type RouteSubscriber interface {
	Subscribe(filter Family, handler RouteHandler) (cancel func(), err error)
}

// RouteLister reads a snapshot of the current loc-rib for one family and
// hands each peer-learned route to handler, synchronously on the calling
// goroutine. Locally originated paths (this node's own advertisements) are
// skipped -- unlike the live Subscribe stream, the rib holds them too, and
// re-applying an own EVPN RT3 would install a self-pointing BUM peer.
// Used to re-apply routes that were dropped fail-closed while their
// import surface (binding / bridge facet) did not exist yet.
type RouteLister interface {
	ListRoutes(family Family, handler RouteHandler) error
}

// Origin identifies what signaled a candidate path (RFC 9256 §2.4
// Protocol-Origin). The numeric values are the RFC's recommended
// defaults; the best-path tie-break prefers the HIGHER value, so a
// locally configured path outranks one learned via BGP, which outranks
// PCEP.
type Origin uint8

const (
	OriginPCEP  Origin = 10
	OriginBGP   Origin = 20
	OriginLocal Origin = 30
)

// String renders the origin for logs.
func (o Origin) String() string {
	switch o {
	case OriginPCEP:
		return "pcep"
	case OriginBGP:
		return "bgp"
	case OriginLocal:
		return "local"
	default:
		return fmt.Sprintf("origin(%d)", uint8(o))
	}
}

// SRPolicy is an SR Policy identified by {Color, Endpoint} (RFC 9256
// §2.1). It aggregates the candidate paths advertised for that key; a
// single received BGP SR Policy NLRI (or one local definition) maps to
// exactly one CandidatePath, distinguished by Distinguisher.
type SRPolicy struct {
	Color      uint32
	Endpoint   netip.Addr
	Candidates []CandidatePath
	// AdvertiseNextHop is the BGP next hop used only when advertising this
	// policy (PushPolicy). It is the zero Addr for received policies.
	AdvertiseNextHop netip.Addr
}

// SRPolicyDefaultPreference is the candidate path preference assumed when
// none is signaled (RFC 9256 §2.7).
const SRPolicyDefaultPreference = 100

// WeightedSegmentList is one Segment List of a candidate path with the
// share it takes (RFC 9256 §2.2). A candidate path may carry several, which
// together form a weighted ECMP set.
//
// Weight is the value from the Weight sub-TLV, or SRPolicyDefaultWeight
// when the sub-TLV is absent (RFC 9256: "The default weight is 1"). It is
// never 0: the RFC declares a segment list whose weight is 0 invalid, so
// such a list never reaches this type.
type WeightedSegmentList struct {
	Segments []netip.Addr
	Weight   uint32
}

// CandidatePath is one segment-list option for an SRPolicy. The active
// path is chosen per RFC 9256 §2.9: highest Preference, then highest
// Origin, then lowest Distinguisher.
type CandidatePath struct {
	Origin        Origin
	Distinguisher uint32
	Preference    uint32
	// SegmentList is the transport SID list actually programmed: the first
	// usable Segment List of this candidate path. Kept as the single-list
	// view every existing consumer uses.
	SegmentList []netip.Addr
	// SegmentLists holds every usable Segment List with its weight, in wire
	// order, and is only populated by the BGP decoder. Read it through
	// Lists() rather than directly: a locally configured path carries just
	// the single SegmentList, and a consumer reading this field raw would
	// see such a path as having none.
	SegmentLists []WeightedSegmentList
}

// Lists returns the candidate path's Segment Lists as the weighted set to
// select over, whatever shape the producer filled in.
//
// SegmentList and SegmentLists are two views of the same thing, and only the
// BGP decoder sets both. Locally configured paths and the advertise API set
// only SegmentList, so a weighted consumer reading SegmentLists directly
// would treat a perfectly valid single-list path as empty and stop steering
// it. Going through here means a new producer cannot introduce that bug by
// omission.
func (c CandidatePath) Lists() []WeightedSegmentList {
	if len(c.SegmentLists) > 0 {
		return c.SegmentLists
	}
	if len(c.SegmentList) == 0 {
		return nil
	}
	return []WeightedSegmentList{{
		Segments: c.SegmentList,
		Weight:   SRPolicyDefaultWeight,
	}}
}

// SRPolicyDefaultWeight is the share a Segment List takes when it carries
// no Weight sub-TLV: RFC 9256 states "The default weight is 1".
const SRPolicyDefaultWeight = 1

// SRPolicyKey identifies a previously-advertised SR Policy for
// withdrawal: the {Distinguisher, Color, Endpoint} tuple of the NLRI
// (RFC 9830).
type SRPolicyKey struct {
	Color         uint32
	Endpoint      netip.Addr
	Distinguisher uint32
}

// SRPolicyController advertises local SR Policies into BGP (SAFI 73).
// Reception is delivered through RouteSubscriber as RouteEvent.SRPolicy;
// PushPolicy / WithdrawPolicy are the advertise direction, surfaced
// operator-side as `vbctl bgp advertise-sr-policy` / `withdraw-sr-policy`.
//
// PushPolicy advertises exactly one candidate path: p.Candidates must hold
// a single CandidatePath, and p.AdvertiseNextHop supplies the BGP next hop.
type SRPolicyController interface {
	PushPolicy(ctx context.Context, p SRPolicy) error
	WithdrawPolicy(ctx context.Context, key SRPolicyKey) error
}

// EVPNRouteType enumerates the RFC 7432 / RFC 9252 EVPN NLRI types
// Vinbero consumes. RT1 (Ethernet A-D), RT5 (IP Prefix), and RT6/7
// (multicast) are out of scope (see docs/dev/bgp_evpn_integration.md).
type EVPNRouteType uint8

const (
	EVPNRouteTypeEthernetAD         EVPNRouteType = 1 // RT1: Ethernet A-D -> aliasing / mass withdraw
	EVPNRouteTypeMACIP              EVPNRouteType = 2 // RT2: MAC/IP -> fdb_map + bd_peer_map
	EVPNRouteTypeInclusiveMulticast EVPNRouteType = 3 // RT3: Inclusive Multicast -> bd_peer_map (BUM)
	EVPNRouteTypeEthernetSegment    EVPNRouteType = 4 // RT4: Ethernet Segment -> esi_map (DF election)
)

// EVPNMACKey identifies a previously-advertised RT2 for withdrawal: the
// {RD, EthernetTag, MAC} tuple of the NLRI.
type EVPNMACKey struct {
	RD          string
	EthernetTag uint32
	MAC         string
}

// EVPNMcastKey identifies a previously-advertised RT3 (Inclusive Multicast)
// for withdrawal: the {RD, EthernetTag} tuple of the NLRI.
type EVPNMcastKey struct {
	RD          string
	EthernetTag uint32
}

// EVPNESKey identifies a previously-advertised RT4 (Ethernet Segment) for
// withdrawal: the {RD, ESI} tuple of the NLRI.
type EVPNESKey struct {
	RD  string
	ESI [10]byte
}

// EVPNController advertises Vinbero's local EVPN state into BGP (AFI 25 /
// SAFI 70). Reception is delivered through RouteSubscriber as
// RouteEvent.EVPN; PushEVPNMac / WithdrawEVPNMac are the advertise direction
// for RT2 (MAC/IP), surfaced operator-side as `vbctl bgp advertise-evpn-mac`
// / `withdraw-evpn-mac`. The EVPNRoute argument carries the RD, route
// targets, MAC, End.DT2U SID, next hop, and optional ESI to encode.
type EVPNController interface {
	PushEVPNMac(ctx context.Context, r EVPNRoute) error
	WithdrawEVPNMac(ctx context.Context, key EVPNMACKey) error
	// PushEVPNInclusiveMulticast / WithdrawEVPNInclusiveMulticast are the
	// advertise direction for RT3 (Inclusive Multicast), carrying the local
	// End.DT2M flood SID so remote PEs flood BUM traffic toward this node.
	PushEVPNInclusiveMulticast(ctx context.Context, r EVPNRoute) error
	WithdrawEVPNInclusiveMulticast(ctx context.Context, key EVPNMcastKey) error
	// PushEVPNEthernetSegment / WithdrawEVPNEthernetSegment are the advertise
	// direction for RT4 (Ethernet Segment), carrying the ES-Import route target
	// so peers learn this PE attaches to the segment (DF election input).
	PushEVPNEthernetSegment(ctx context.Context, r EVPNRoute) error
	WithdrawEVPNEthernetSegment(ctx context.Context, key EVPNESKey) error
}

// EVPNRoute is a decoded BGP EVPN NLRI (AFI 25 / SAFI 70). One envelope
// carries every route type; the fields a type does not use stay zero.
// The SRv6 service SID (End.DT2U for RT2 and for a per-EVI RT1, End.DT2M
// for RT3) is decoded from the BGP Prefix-SID attribute's SRv6 L2 Service
// TLV (RFC 9252 §6); RT4 and a per-ES RT1 carry no SID. The route targets resolve the local bridge domain
// through the same import-RT filter the L3VPN path uses.
type EVPNRoute struct {
	Type        EVPNRouteType
	RD          string
	RTs         []string
	ESI         [10]byte
	EthernetTag uint32
	MAC         string // RT2: "aa:bb:cc:dd:ee:ff"
	IPAddr      string // RT2: optional host IP (IRB); "" when MAC-only
	SRv6SID     string // End.DT2U (RT2, per-EVI RT1) / End.DT2M (RT3); "" if none
	NextHop     string
	ESImportRT  string // RT4: ES-Import route target ("aa:bb:cc:dd:ee:ff"); "" otherwise
	// SingleActive is the ESI Label extended community's Single-Active bit
	// (RFC 7432 §7.5), carried on a per-ES RT1. It says the segment is
	// single-active, so only the DF forwards for it and the segment must NOT
	// be aliased across PEs. Meaningless on other route types.
	SingleActive bool
	// RemoteSrc is the advertising PE's SRv6 encap source (the SID's locator
	// base) for any route carrying a SID -- RT2, RT3 and a per-EVI RT1 --
	// used as the RX reverse-map key for split-horizon and remote-MAC
	// learning, distinct from the local TX encap source. "" if not derivable.
	RemoteSrc string
}

// EVPNMaxEthernetTag is the reserved Ethernet Tag (MAX-ET) that marks a
// per-ES Ethernet A-D route, as opposed to a per-EVI one (RFC 7432 §8.2).
// The two carry different meaning: per-ES is the segment-wide statement used
// for mass withdraw, per-EVI is the per-broadcast-domain statement that
// enables aliasing.
const EVPNMaxEthernetTag uint32 = 0xFFFFFFFF

// IsPerES reports whether an Ethernet A-D route is the per-ES form.
func (r EVPNRoute) IsPerES() bool {
	return r.Type == EVPNRouteTypeEthernetAD && r.EthernetTag == EVPNMaxEthernetTag
}

// MUPRouteType enumerates the BGP MUP SAFI (85) route types Vinbero consumes
// under Architecture Type 1 (3GPP-5G), per draft-mpmz-bess-mup-safi §3.1.
type MUPRouteType uint8

const (
	MUPRouteTypeISD  MUPRouteType = 1 // Interwork Segment Discovery (downlink interwork segment)
	MUPRouteTypeDSD  MUPRouteType = 2 // Direct Segment Discovery (uplink direct segment)
	MUPRouteTypeT1ST MUPRouteType = 3 // Type-1 Session Transformed (per-UE, downlink)
	MUPRouteTypeT2ST MUPRouteType = 4 // Type-2 Session Transformed (aggregate, uplink)
)

// String renders the MUP route type for logs.
func (t MUPRouteType) String() string {
	switch t {
	case MUPRouteTypeISD:
		return "isd"
	case MUPRouteTypeDSD:
		return "dsd"
	case MUPRouteTypeT1ST:
		return "t1st"
	case MUPRouteTypeT2ST:
		return "t2st"
	default:
		return fmt.Sprintf("mup-type(%d)", uint8(t))
	}
}

// MUPRoute is a decoded BGP MUP NLRI (SAFI 85, 3GPP-5G). One envelope carries
// every route type; fields a type does not use stay zero. The SRv6 service SID
// (the interwork/direct segment locator:function) is decoded from the
// Prefix-SID attribute's SRv6 Services TLV, the same path VPNv4/EVPN use.
//
// Direction mapping (draft-mpmz-bess-mup-safi, RFC 9433): T1ST is the downlink
// per-UE session (UE Prefix + exact TEID + QFI + gNB Endpoint), T2ST the uplink
// aggregate (Endpoint + a variable-length TEID *prefix*). ISD/DSD advertise the
// interwork/direct segments that T1ST/T2ST resolve against.
type MUPRoute struct {
	Type MUPRouteType
	RD   string
	RTs  []string

	// Prefix is the ISD interwork-segment prefix or the T1ST UE prefix (CIDR).
	Prefix string
	// Address is the DSD originating speaker's direct-segment endpoint.
	Address string

	// TEID is the GTP-U Tunnel Endpoint Identifier. For T1ST it is an exact
	// 32-bit value; for T2ST it is the high-order bits of a TEID prefix whose
	// significant length is TEIDLen (the rest are zero).
	TEID uint32
	// TEIDLen is the significant TEID prefix length in bits: 32 for T1ST (exact),
	// 0..32 for T2ST (EndpointAddressLength - 32 for IPv4). 0 means "any TEID".
	TEIDLen  uint8
	QFI      uint8  // T1ST QoS Flow Identifier
	RQI      uint8  // T1ST Reflective QoS Indicator
	Endpoint string // T1ST gNB N3 address / T2ST GTP tunnel endpoint
	Source   string // T1ST optional source address ("" if none)

	// SegmentID2 / SegmentID4 are the BGP MUP Extended Community segment
	// identifier halves (draft §3.2), used to resolve a T2ST against its Direct
	// Segment (DSD). Zero when the community is absent.
	SegmentID2 uint16
	SegmentID4 uint32

	// SRv6SID is the segment's locator:function base from the Prefix-SID TLV;
	// "" if none.
	SRv6SID string
	NextHop string

	// SIDStructure carries the SRv6 SID layout (RFC 9252 §3.2.1.1) for SRv6SID.
	// Zero means "unset", in which case the SRv6 SID Structure Sub-Sub-TLV is
	// omitted on advertise. Receivers that need the locator-block length for
	// next-hop tracking then fall back to /0 and the path stays
	// NEXT_HOP_UNREACHABLE.
	SIDStructure SIDStructure
}

// SIDStructure is the SRv6 SID layout signalled by the SRv6 SID Structure
// Sub-Sub-TLV (RFC 9252 §3.2.1.1). All fields are bit lengths except
// TranspositionOffset (bit position). LocatorBlockLen + LocatorNodeLen +
// FunctionLen + ArgumentLen must equal 128.
type SIDStructure struct {
	LocatorBlockLen     uint8
	LocatorNodeLen      uint8
	FunctionLen         uint8
	ArgumentLen         uint8
	TranspositionLen    uint8
	TranspositionOffset uint8
}

// IsZero reports whether the structure carries no usable layout (all fields
// zero), in which case advertise paths must omit the sub-sub-TLV rather than
// emit a /0-locator SID that breaks receiver next-hop tracking.
func (s SIDStructure) IsZero() bool {
	return s == SIDStructure{}
}

// Family returns the address family (FamilyMUPIPv4 / FamilyMUPIPv6) the
// route belongs to, derived from its mobile-user-plane address field:
// ISD/T1ST use Prefix, DSD uses Address, T2ST uses Endpoint. Returns
// ok=false for an unparseable / unknown route type so callers can fall
// back to the route's own RTs rather than misclassify the binding lookup.
func (mr MUPRoute) Family() (Family, bool) {
	var s string
	switch mr.Type {
	case MUPRouteTypeISD, MUPRouteTypeT1ST:
		s = mr.Prefix
	case MUPRouteTypeDSD:
		s = mr.Address
	case MUPRouteTypeT2ST:
		s = mr.Endpoint
	default:
		return "", false
	}
	var addr netip.Addr
	if p, err := netip.ParsePrefix(s); err == nil {
		addr = p.Addr()
	} else if a, err := netip.ParseAddr(s); err == nil {
		addr = a
	} else {
		return "", false
	}
	// Unmap so an IPv4-mapped IPv6 address (::ffff:a.b.c.d) classifies as
	// FamilyMUPIPv4. netip.Addr.Is4 returns false for the mapped form, so a
	// 4-in-6 endpoint would otherwise hit the IPv6 binding family and read
	// the wrong export RTs.
	if addr.Unmap().Is4() {
		return FamilyMUPIPv4, true
	}
	return FamilyMUPIPv6, true
}

// MUP withdraw keys identify a previously-advertised MUP route by the subset of
// NLRI fields that form its BGP route key (draft-mpmz-bess-mup-safi §3.1).
type (
	MUPISDKey struct {
		RD     string
		Prefix string
	}
	MUPDSDKey struct {
		RD      string
		Address string
	}
	MUPT1STKey struct {
		RD     string
		Prefix string // UE prefix
		TEID   uint32
	}
	MUPT2STKey struct {
		RD       string
		Endpoint string
		TEID     uint32
		TEIDLen  uint8
	}
)

// MUPController advertises Vinbero's local BGP MUP routes (SAFI 85). Reception
// is delivered through RouteSubscriber as RouteEvent.MUP; the Push / Withdraw
// methods are the advertise direction, surfaced operator-side as
// `vbctl bgp advertise-mup --route-type {isd|dsd|t1st|t2st}` / `withdraw-mup`.
// This is the MUP Controller role: a node that signals UE-session and segment
// state without necessarily forwarding the data itself.
type MUPController interface {
	PushMUPISD(ctx context.Context, r MUPRoute) error
	WithdrawMUPISD(ctx context.Context, key MUPISDKey) error
	PushMUPDSD(ctx context.Context, r MUPRoute) error
	WithdrawMUPDSD(ctx context.Context, key MUPDSDKey) error
	PushMUPT1ST(ctx context.Context, r MUPRoute) error
	WithdrawMUPT1ST(ctx context.Context, key MUPT1STKey) error
	PushMUPT2ST(ctx context.Context, r MUPRoute) error
	WithdrawMUPT2ST(ctx context.Context, key MUPT2STKey) error
}
