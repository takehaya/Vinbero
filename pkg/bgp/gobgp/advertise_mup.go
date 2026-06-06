package gobgp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

var _ bgp.MUPController = (*Session)(nil)

// PushMUPISD advertises a local BGP MUP Interwork Segment Discovery route
// (Type 1). The path UUID is tracked under {RD, Prefix} for a later withdraw.
func (s *Session) PushMUPISD(_ context.Context, r bgp.MUPRoute) error {
	return s.pushMUP(encodeMUPISDPath, r, mupISDKey(r.RD, r.Prefix))
}

// WithdrawMUPISD removes a previously advertised ISD; a no-op if never advertised.
func (s *Session) WithdrawMUPISD(ctx context.Context, key bgp.MUPISDKey) error {
	return s.Withdraw(ctx, mupISDKey(key.RD, key.Prefix))
}

// PushMUPDSD advertises a local Direct Segment Discovery route (Type 2).
func (s *Session) PushMUPDSD(_ context.Context, r bgp.MUPRoute) error {
	return s.pushMUP(encodeMUPDSDPath, r, mupDSDKey(r.RD, r.Address))
}

// WithdrawMUPDSD removes a previously advertised DSD.
func (s *Session) WithdrawMUPDSD(ctx context.Context, key bgp.MUPDSDKey) error {
	return s.Withdraw(ctx, mupDSDKey(key.RD, key.Address))
}

// PushMUPT1ST advertises a Type-1 Session Transformed route (per-UE downlink).
func (s *Session) PushMUPT1ST(_ context.Context, r bgp.MUPRoute) error {
	return s.pushMUP(encodeMUPT1STPath, r, mupT1STAdvKey(r.RD, r.Prefix, r.TEID))
}

// WithdrawMUPT1ST removes a previously advertised T1ST.
func (s *Session) WithdrawMUPT1ST(ctx context.Context, key bgp.MUPT1STKey) error {
	return s.Withdraw(ctx, mupT1STAdvKey(key.RD, key.Prefix, key.TEID))
}

// PushMUPT2ST advertises a Type-2 Session Transformed route (aggregate uplink).
func (s *Session) PushMUPT2ST(_ context.Context, r bgp.MUPRoute) error {
	return s.pushMUP(encodeMUPT2STPath, r, mupT2STAdvKey(r.RD, r.Endpoint, r.TEID, r.TEIDLen))
}

// WithdrawMUPT2ST removes a previously advertised T2ST.
func (s *Session) WithdrawMUPT2ST(ctx context.Context, key bgp.MUPT2STKey) error {
	return s.Withdraw(ctx, mupT2STAdvKey(key.RD, key.Endpoint, key.TEID, key.TEIDLen))
}

// pushMUP encodes r with enc and adds the path to the RIB under rk.
func (s *Session) pushMUP(enc func(bgp.MUPRoute) (*apiutil.Path, error), r bgp.MUPRoute, rk bgp.RouteKey) error {
	srv := s.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	path, err := enc(r)
	if err != nil {
		return err
	}
	return s.addAndTrack(srv, path, rk)
}

// Advertised-path tracking keys. RD goes in the dedicated RouteKey.RD field so
// the ':'-bearing RD never blurs the tuple boundary; Prefix encodes the route
// type plus its remaining key fields.
func mupISDKey(rd, prefix string) bgp.RouteKey {
	return bgp.RouteKey{Family: bgp.FamilyMUPIPv4, RD: rd, Prefix: "mup-isd:" + prefix}
}

func mupDSDKey(rd, address string) bgp.RouteKey {
	return bgp.RouteKey{Family: bgp.FamilyMUPIPv4, RD: rd, Prefix: "mup-dsd:" + address}
}

func mupT1STAdvKey(rd, prefix string, teid uint32) bgp.RouteKey {
	return bgp.RouteKey{Family: bgp.FamilyMUPIPv4, RD: rd, Prefix: fmt.Sprintf("mup-t1st:%s:%d", prefix, teid)}
}

func mupT2STAdvKey(rd, endpoint string, teid uint32, teidLen uint8) bgp.RouteKey {
	return bgp.RouteKey{Family: bgp.FamilyMUPIPv4, RD: rd, Prefix: fmt.Sprintf("mup-t2st:%s:%d/%d", endpoint, teid, teidLen)}
}

// teidToAddr renders a 32-bit TEID as the 4-byte (MSB-first) netip.Addr gobgp's
// MUP route types carry. For a T2ST TEID prefix the significant bits are the
// high-order ones, so the serializer takes them from the front of this slice.
func teidToAddr(teid uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], teid)
	return netip.AddrFrom4(b)
}

// mupPrefixSID builds the Prefix-SID attribute carrying the segment's SRv6 SID.
// The behavior identifies the SRv6 endpoint function the receiver should
// associate with the SID: ISD carries the GW's interwork-segment behavior
// (`ENDM_GTP4E` for IPv4 underlay, `ENDM_GTP6E` for IPv6), DSD carries the
// PE's decap behavior (`END_DT4` / `END_DT6`). Vinbero ignores the field on
// receive (decodeSRv6SID just extracts the SID bytes), but other MUP-aware
// implementations key off it to choose an install path,
// so reporting `END_DT4` for an ISD prevents the PE-side downlink H.Encaps
// composition from firing.
func mupPrefixSID(sidStr string, behavior gobgppkt.SRBehavior) (gobgppkt.PathAttributeInterface, error) {
	sid, err := netip.ParseAddr(sidStr)
	if err != nil || !sid.Is6() || sid.Is4In6() || sid.IsUnspecified() {
		return nil, fmt.Errorf("MUP SID must be a usable IPv6 SID: %q", sidStr)
	}
	info := gobgppkt.NewSRv6InformationSubTLV(sid, behavior)
	svc := gobgppkt.NewSRv6ServiceTLV(gobgppkt.TLVTypeSRv6L3Service, info)
	return gobgppkt.NewPathAttributePrefixSID(svc), nil
}

// mupExtComms assembles the extended-communities attribute: the route targets
// plus, when a segment id is set, the BGP MUP Extended Community (draft §3.2)
// that links a T2ST to its Direct Segment / a DSD to its identifier. Returns nil
// when there are no communities to attach.
func mupExtComms(r bgp.MUPRoute, withSegmentID bool) (gobgppkt.PathAttributeInterface, error) {
	ecs, err := parseRouteTargets(r.RTs)
	if err != nil {
		return nil, err
	}
	if withSegmentID && (r.SegmentID2 != 0 || r.SegmentID4 != 0) {
		ecs = append(ecs, gobgppkt.NewMUPExtended(r.SegmentID2, r.SegmentID4))
	}
	if len(ecs) == 0 {
		return nil, nil
	}
	return gobgppkt.NewPathAttributeExtendedCommunities(ecs), nil
}

// mupParseRD parses the route distinguisher shared by all four MUP encoders.
func mupParseRD(rd string) (gobgppkt.RouteDistinguisherInterface, error) {
	parsed, err := gobgppkt.ParseRouteDistinguisher(rd)
	if err != nil {
		return nil, fmt.Errorf("parse RD %q: %w", rd, err)
	}
	return parsed, nil
}

// mupFinishPath builds the attribute set common to all four MUP encoders: the
// Origin, the optional ext-communities, the Prefix-SID (with the route-type's
// endpoint behavior), and the MP_REACH_NLRI.
func mupFinishPath(nlri *gobgppkt.MUPNLRI, r bgp.MUPRoute, withSegmentID bool, sidBehavior gobgppkt.SRBehavior) (*apiutil.Path, error) {
	attrs := []gobgppkt.PathAttributeInterface{gobgppkt.NewPathAttributeOrigin(0)}
	ec, err := mupExtComms(r, withSegmentID)
	if err != nil {
		return nil, err
	}
	if ec != nil {
		attrs = append(attrs, ec)
	}
	if r.SRv6SID != "" {
		psid, err := mupPrefixSID(r.SRv6SID, sidBehavior)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, psid)
	}
	nh, err := netip.ParseAddr(r.NextHop)
	if err != nil {
		return nil, fmt.Errorf("parse nexthop %q: %w", r.NextHop, err)
	}
	// The NLRI constructor set the AFI from the route's address family; the
	// MP_REACH family and the Path family must match it (RF_MUP_IPv4 vs IPv6).
	family := gobgppkt.RF_MUP_IPv4
	if nlri.Afi == gobgppkt.AFI_IP6 {
		family = gobgppkt.RF_MUP_IPv6
	}
	mpReach, err := gobgppkt.NewPathAttributeMpReachNLRI(family, []gobgppkt.PathNLRI{{NLRI: nlri}}, nh)
	if err != nil {
		return nil, fmt.Errorf("build MP_REACH_NLRI: %w", err)
	}
	attrs = append(attrs, mpReach)
	return &apiutil.Path{Family: family, Nlri: nlri, Attrs: attrs}, nil
}

func encodeMUPISDPath(r bgp.MUPRoute) (*apiutil.Path, error) {
	rd, err := mupParseRD(r.RD)
	if err != nil {
		return nil, err
	}
	prefix, err := netip.ParsePrefix(r.Prefix)
	if err != nil {
		return nil, fmt.Errorf("parse ISD prefix %q: %w", r.Prefix, err)
	}
	nlri := gobgppkt.NewMUPInterworkSegmentDiscoveryRoute(rd, prefix)
	// ISD advertises a GW interwork-segment SID -- End.M.GTP4.E for an IPv4 gNB
	// prefix, End.M.GTP6.E for an IPv6 one. The address family is the prefix's.
	behavior := gobgppkt.ENDM_GTP4E
	if prefix.Addr().Is6() {
		behavior = gobgppkt.ENDM_GTP6E
	}
	return mupFinishPath(nlri, r, false, behavior)
}

func encodeMUPDSDPath(r bgp.MUPRoute) (*apiutil.Path, error) {
	rd, err := mupParseRD(r.RD)
	if err != nil {
		return nil, err
	}
	addr, err := netip.ParseAddr(r.Address)
	if err != nil {
		return nil, fmt.Errorf("parse DSD address %q: %w", r.Address, err)
	}
	nlri := gobgppkt.NewMUPDirectSegmentDiscoveryRoute(rd, addr)
	// DSD advertises the PE's decap SID; mirror the address family with the
	// matching End.DT* function.
	behavior := gobgppkt.END_DT4
	if addr.Is6() {
		behavior = gobgppkt.END_DT6
	}
	return mupFinishPath(nlri, r, true, behavior)
}

func encodeMUPT1STPath(r bgp.MUPRoute) (*apiutil.Path, error) {
	rd, err := mupParseRD(r.RD)
	if err != nil {
		return nil, err
	}
	prefix, err := netip.ParsePrefix(r.Prefix)
	if err != nil {
		return nil, fmt.Errorf("parse T1ST UE prefix %q: %w", r.Prefix, err)
	}
	ep, err := netip.ParseAddr(r.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse T1ST endpoint %q: %w", r.Endpoint, err)
	}
	var src *netip.Addr
	if r.Source != "" {
		sa, err := netip.ParseAddr(r.Source)
		if err != nil {
			return nil, fmt.Errorf("parse T1ST source %q: %w", r.Source, err)
		}
		src = &sa
	}
	nlri := gobgppkt.NewMUPType1SessionTransformedRoute(rd, prefix, teidToAddr(r.TEID), r.QFI, ep, src)
	// T1ST is SID-less in this stack (the receiving PE resolves the interwork
	// SID from an ISD), so the behavior never reaches the wire; pick a
	// family-matched DT* default to keep mupFinishPath consistent.
	behavior := gobgppkt.END_DT4
	if prefix.Addr().Is6() {
		behavior = gobgppkt.END_DT6
	}
	return mupFinishPath(nlri, r, false, behavior)
}

func encodeMUPT2STPath(r bgp.MUPRoute) (*apiutil.Path, error) {
	rd, err := mupParseRD(r.RD)
	if err != nil {
		return nil, err
	}
	ep, err := netip.ParseAddr(r.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse T2ST endpoint %q: %w", r.Endpoint, err)
	}
	if r.TEIDLen > 32 {
		return nil, fmt.Errorf("T2ST TEID prefix length %d exceeds 32", r.TEIDLen)
	}
	// EndpointAddressLength carries the endpoint (32 bits for IPv4, 128 for IPv6)
	// plus the significant TEID prefix bits.
	endpointBits := uint8(32)
	if ep.Is6() {
		endpointBits = 128
	}
	eaLen := endpointBits + r.TEIDLen
	nlri := gobgppkt.NewMUPType2SessionTransformedRoute(rd, eaLen, ep, teidToAddr(r.TEID))
	// T2ST is SID-less (the receiving GW resolves the direct SID from a DSD by
	// segment-id), so the behavior never reaches the wire; pick a family-matched
	// DT* default to keep mupFinishPath consistent.
	behavior := gobgppkt.END_DT4
	if ep.Is6() {
		behavior = gobgppkt.END_DT6
	}
	return mupFinishPath(nlri, r, true, behavior)
}
