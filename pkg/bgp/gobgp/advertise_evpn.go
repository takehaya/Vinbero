package gobgp

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/google/uuid"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

var _ bgp.EVPNController = (*Session)(nil)

// PushEVPNMac advertises a local EVPN RT2 (MAC/IP) into the BGP RIB. The
// gobgp path UUID is recorded under the {RD, EthernetTag, MAC} key so a
// later WithdrawEVPNMac removes that exact path.
func (s *Session) PushEVPNMac(_ context.Context, r bgp.EVPNRoute) error {
	srv := s.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	path, err := encodeEVPNMacPath(r)
	if err != nil {
		return err
	}
	return s.addAndTrack(srv, path, evpnAdvKey(r.RD, r.EthernetTag, r.MAC))
}

// WithdrawEVPNMac removes a previously advertised RT2. Withdrawing one that
// was never advertised is a no-op so callers can withdraw idempotently.
func (s *Session) WithdrawEVPNMac(_ context.Context, key bgp.EVPNMACKey) error {
	srv := s.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	rk := evpnAdvKey(key.RD, key.EthernetTag, key.MAC)
	s.advMu.Lock()
	id, ok := s.advertised[rk]
	s.advMu.Unlock()
	if !ok {
		return nil
	}
	// Drop the tracking entry only after gobgp confirms the delete, so a
	// failed DeletePath leaves the route still withdrawable on retry.
	if err := srv.DeletePath(apiutil.DeletePathRequest{UUIDs: []uuid.UUID{id}}); err != nil {
		return fmt.Errorf("withdraw EVPN RT2 {rd=%s, etag=%d, mac=%s}: %w",
			key.RD, key.EthernetTag, key.MAC, err)
	}
	s.advMu.Lock()
	delete(s.advertised, rk)
	delete(s.producers, rk)
	s.advMu.Unlock()
	return nil
}

// evpnAdvKey synthesizes the advertised-path tracking key for an RT2. The
// shared advertised map is keyed by bgp.RouteKey. The RD goes in the dedicated
// RD field (like the VPNv4 path) rather than the Prefix, so the ':'-bearing RD
// cannot blur the boundary with the rest of the tuple; Prefix holds only the
// EthernetTag (digits) and the already-normalized MAC (fixed 17 chars), which
// cannot collide across distinct tuples.
func evpnAdvKey(rd string, etag uint32, mac string) bgp.RouteKey {
	return bgp.RouteKey{
		Family: bgp.FamilyEVPN,
		RD:     rd,
		Prefix: fmt.Sprintf("evpn-rt2:%d:%s", etag, mac),
	}
}

// PushEVPNInclusiveMulticast advertises a local EVPN RT3 (Inclusive Multicast)
// into the BGP RIB. The path UUID is tracked under {RD, EthernetTag} so a
// later WithdrawEVPNInclusiveMulticast removes that exact path.
func (s *Session) PushEVPNInclusiveMulticast(_ context.Context, r bgp.EVPNRoute) error {
	srv := s.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	path, err := encodeEVPNMulticastPath(r)
	if err != nil {
		return err
	}
	return s.addAndTrack(srv, path, evpnImetKey(r.RD, r.EthernetTag))
}

// WithdrawEVPNInclusiveMulticast removes a previously advertised RT3.
// Withdrawing one never advertised is a no-op.
func (s *Session) WithdrawEVPNInclusiveMulticast(_ context.Context, key bgp.EVPNMcastKey) error {
	srv := s.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	rk := evpnImetKey(key.RD, key.EthernetTag)
	s.advMu.Lock()
	id, ok := s.advertised[rk]
	s.advMu.Unlock()
	if !ok {
		return nil
	}
	if err := srv.DeletePath(apiutil.DeletePathRequest{UUIDs: []uuid.UUID{id}}); err != nil {
		return fmt.Errorf("withdraw EVPN RT3 {rd=%s, etag=%d}: %w",
			key.RD, key.EthernetTag, err)
	}
	s.advMu.Lock()
	delete(s.advertised, rk)
	delete(s.producers, rk)
	s.advMu.Unlock()
	return nil
}

// evpnImetKey synthesizes the advertised-path tracking key for an RT3
// (Inclusive Multicast Ethernet Tag). RD goes in the dedicated RD field;
// Prefix holds only the EthernetTag.
func evpnImetKey(rd string, etag uint32) bgp.RouteKey {
	return bgp.RouteKey{
		Family: bgp.FamilyEVPN,
		RD:     rd,
		Prefix: fmt.Sprintf("evpn-rt3:%d", etag),
	}
}

// encodeEVPNMulticastPath builds the gobgp Path for an RT3 advertisement: the
// {RD, ETag, Originating Router IP} NLRI, an End.DT2M SID in the SRv6 L2
// Service TLV (RFC 9252 §6.3), a PMSI Tunnel (Ingress Replication) attribute
// whose endpoint is the originating router (RFC 7432 §11.2), the route targets
// as extended communities, and the next hop in MP_REACH_NLRI.
func encodeEVPNMulticastPath(r bgp.EVPNRoute) (*apiutil.Path, error) {
	sid, err := netip.ParseAddr(r.SRv6SID)
	if err != nil || !sid.Is6() || sid.Is4In6() || sid.IsUnspecified() {
		return nil, fmt.Errorf("EVPN RT3 SID must be a usable IPv6 SID: %q", r.SRv6SID)
	}
	nh, err := netip.ParseAddr(r.NextHop)
	if err != nil || !nh.Is6() || nh.Is4In6() || nh.IsUnspecified() {
		return nil, fmt.Errorf("EVPN RT3 next hop must be IPv6: %q", r.NextHop)
	}
	rd, err := gobgppkt.ParseRouteDistinguisher(r.RD)
	if err != nil {
		return nil, fmt.Errorf("parse RD %q: %w", r.RD, err)
	}

	nlri := gobgppkt.NewEVPNNLRI(
		gobgppkt.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG,
		&gobgppkt.EVPNMulticastEthernetTagRoute{
			RD:              rd,
			ETag:            r.EthernetTag,
			IPAddressLength: uint8(nh.BitLen()),
			IPAddress:       nh,
		},
	)

	attrs := []gobgppkt.PathAttributeInterface{gobgppkt.NewPathAttributeOrigin(0)}
	ecs, err := parseRouteTargets(r.RTs)
	if err != nil {
		return nil, err
	}
	if len(ecs) > 0 {
		attrs = append(attrs, gobgppkt.NewPathAttributeExtendedCommunities(ecs))
	}

	tid, err := gobgppkt.NewIngressReplTunnelID(nh)
	if err != nil {
		return nil, fmt.Errorf("build PMSI tunnel id: %w", err)
	}
	attrs = append(attrs, gobgppkt.NewPathAttributePmsiTunnel(
		gobgppkt.PMSI_TUNNEL_TYPE_INGRESS_REPL, false, 0, tid))

	infoSubTLV := gobgppkt.NewSRv6InformationSubTLV(sid, gobgppkt.END_DT2M)
	svcTLV := gobgppkt.NewSRv6ServiceTLV(gobgppkt.TLVTypeSRv6L2Service, infoSubTLV)
	attrs = append(attrs, gobgppkt.NewPathAttributePrefixSID(svcTLV))

	mpReach, err := gobgppkt.NewPathAttributeMpReachNLRI(
		gobgppkt.RF_EVPN, []gobgppkt.PathNLRI{{NLRI: nlri}}, nh)
	if err != nil {
		return nil, fmt.Errorf("build MP_REACH_NLRI: %w", err)
	}
	attrs = append(attrs, mpReach)
	return &apiutil.Path{Family: gobgppkt.RF_EVPN, Nlri: nlri, Attrs: attrs}, nil
}

// encodeEVPNMacPath builds the gobgp Path for an RT2 advertisement. It is the
// inverse of decodeEVPNMacIP: the {RD, ESI, EthernetTag, MAC} NLRI plus an
// End.DT2U SID in the SRv6 L2 Service TLV (RFC 9252 §6.2) and the route
// targets as extended communities; the next hop rides in MP_REACH_NLRI.
func encodeEVPNMacPath(r bgp.EVPNRoute) (*apiutil.Path, error) {
	hw, err := net.ParseMAC(r.MAC)
	if err != nil {
		return nil, fmt.Errorf("parse MAC %q: %w", r.MAC, err)
	}
	if len(hw) != 6 {
		return nil, fmt.Errorf("EVPN RT2 MAC must be 48-bit: %s", r.MAC)
	}
	sid, err := netip.ParseAddr(r.SRv6SID)
	if err != nil || !sid.Is6() || sid.Is4In6() || sid.IsUnspecified() {
		return nil, fmt.Errorf("EVPN RT2 SID must be a usable IPv6 SID: %q", r.SRv6SID)
	}
	nh, err := netip.ParseAddr(r.NextHop)
	if err != nil || !nh.Is6() || nh.Is4In6() || nh.IsUnspecified() {
		return nil, fmt.Errorf("EVPN RT2 next hop must be IPv6: %q", r.NextHop)
	}
	rd, err := gobgppkt.ParseRouteDistinguisher(r.RD)
	if err != nil {
		return nil, fmt.Errorf("parse RD %q: %w", r.RD, err)
	}

	nlri := gobgppkt.NewEVPNNLRI(
		gobgppkt.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT,
		&gobgppkt.EVPNMacIPAdvertisementRoute{
			RD:               rd,
			ESI:              arrayToESI(r.ESI),
			ETag:             r.EthernetTag,
			MacAddressLength: 48,
			MacAddress:       hw,
			Labels:           []uint32{0},
		},
	)

	attrs := []gobgppkt.PathAttributeInterface{gobgppkt.NewPathAttributeOrigin(0)}
	ecs, err := parseRouteTargets(r.RTs)
	if err != nil {
		return nil, err
	}
	if len(ecs) > 0 {
		attrs = append(attrs, gobgppkt.NewPathAttributeExtendedCommunities(ecs))
	}
	infoSubTLV := gobgppkt.NewSRv6InformationSubTLV(sid, gobgppkt.END_DT2U)
	svcTLV := gobgppkt.NewSRv6ServiceTLV(gobgppkt.TLVTypeSRv6L2Service, infoSubTLV)
	attrs = append(attrs, gobgppkt.NewPathAttributePrefixSID(svcTLV))

	mpReach, err := gobgppkt.NewPathAttributeMpReachNLRI(
		gobgppkt.RF_EVPN, []gobgppkt.PathNLRI{{NLRI: nlri}}, nh)
	if err != nil {
		return nil, fmt.Errorf("build MP_REACH_NLRI: %w", err)
	}
	attrs = append(attrs, mpReach)
	return &apiutil.Path{Family: gobgppkt.RF_EVPN, Nlri: nlri, Attrs: attrs}, nil
}

// PushEVPNEthernetSegment advertises a local EVPN RT4 (Ethernet Segment) into
// the BGP RIB so peers learn this PE attaches to the segment. The path UUID is
// tracked under {RD, ESI} for a later withdraw.
func (s *Session) PushEVPNEthernetSegment(_ context.Context, r bgp.EVPNRoute) error {
	srv := s.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	path, err := encodeEVPNEthernetSegmentPath(r)
	if err != nil {
		return err
	}
	return s.addAndTrack(srv, path, evpnEsKey(r.RD, r.ESI))
}

// WithdrawEVPNEthernetSegment removes a previously advertised RT4. Withdrawing
// one never advertised is a no-op.
func (s *Session) WithdrawEVPNEthernetSegment(_ context.Context, key bgp.EVPNESKey) error {
	srv := s.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	rk := evpnEsKey(key.RD, key.ESI)
	s.advMu.Lock()
	id, ok := s.advertised[rk]
	s.advMu.Unlock()
	if !ok {
		return nil
	}
	if err := srv.DeletePath(apiutil.DeletePathRequest{UUIDs: []uuid.UUID{id}}); err != nil {
		return fmt.Errorf("withdraw EVPN RT4 {rd=%s, esi=%x}: %w", key.RD, key.ESI, err)
	}
	s.advMu.Lock()
	delete(s.advertised, rk)
	delete(s.producers, rk)
	s.advMu.Unlock()
	return nil
}

// evpnEsKey synthesizes the advertised-path tracking key for an RT4. RD goes in
// the dedicated RD field; Prefix holds only the fixed-width hex ESI.
func evpnEsKey(rd string, esi [10]byte) bgp.RouteKey {
	return bgp.RouteKey{
		Family: bgp.FamilyEVPN,
		RD:     rd,
		Prefix: fmt.Sprintf("evpn-rt4:%x", esi),
	}
}

// encodeEVPNEthernetSegmentPath builds the gobgp Path for an RT4 advertisement:
// the {RD, ESI, originating router IP} NLRI and the ES-Import route target as
// an extended community. RT4 carries no Prefix-SID; the next hop rides in
// MP_REACH_NLRI.
func encodeEVPNEthernetSegmentPath(r bgp.EVPNRoute) (*apiutil.Path, error) {
	var zeroESI [10]byte
	if r.ESI == zeroESI {
		return nil, fmt.Errorf("EVPN RT4 ESI must be non-zero")
	}
	nh, err := netip.ParseAddr(r.NextHop)
	if err != nil || !nh.Is6() || nh.Is4In6() || nh.IsUnspecified() {
		return nil, fmt.Errorf("EVPN RT4 next hop must be IPv6: %q", r.NextHop)
	}
	rd, err := gobgppkt.ParseRouteDistinguisher(r.RD)
	if err != nil {
		return nil, fmt.Errorf("parse RD %q: %w", r.RD, err)
	}
	if r.ESImportRT == "" {
		return nil, fmt.Errorf("EVPN RT4 requires an ES-Import route target")
	}
	esImport := gobgppkt.NewESImportRouteTarget(r.ESImportRT)
	if esImport == nil {
		return nil, fmt.Errorf("invalid ES-Import RT (must be a MAC): %q", r.ESImportRT)
	}

	nlri := gobgppkt.NewEVPNNLRI(
		gobgppkt.EVPN_ETHERNET_SEGMENT_ROUTE,
		&gobgppkt.EVPNEthernetSegmentRoute{
			RD:              rd,
			ESI:             arrayToESI(r.ESI),
			IPAddressLength: uint8(nh.BitLen()),
			IPAddress:       nh,
		},
	)
	attrs := []gobgppkt.PathAttributeInterface{
		gobgppkt.NewPathAttributeOrigin(0),
		gobgppkt.NewPathAttributeExtendedCommunities([]gobgppkt.ExtendedCommunityInterface{esImport}),
	}
	mpReach, err := gobgppkt.NewPathAttributeMpReachNLRI(
		gobgppkt.RF_EVPN, []gobgppkt.PathNLRI{{NLRI: nlri}}, nh)
	if err != nil {
		return nil, fmt.Errorf("build MP_REACH_NLRI: %w", err)
	}
	attrs = append(attrs, mpReach)
	return &apiutil.Path{Family: gobgppkt.RF_EVPN, Nlri: nlri, Attrs: attrs}, nil
}

// PushEVPNEthernetAD advertises a local EVPN RT1 (Ethernet A-D) into the BGP
// RIB. The EthernetTag selects the form: MAX-ET emits the per-ES route, any
// other tag the per-EVI route. The path UUID is tracked under
// {RD, ESI, EthernetTag} for a later withdraw.
func (s *Session) PushEVPNEthernetAD(_ context.Context, r bgp.EVPNRoute) error {
	srv := s.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	path, err := encodeEVPNEthernetADPath(r)
	if err != nil {
		return err
	}
	return s.addAndTrack(srv, path, evpnAdKey(r.RD, r.ESI, r.EthernetTag))
}

// WithdrawEVPNEthernetAD removes a previously advertised RT1. Withdrawing one
// never advertised is a no-op.
func (s *Session) WithdrawEVPNEthernetAD(_ context.Context, key bgp.EVPNADKey) error {
	srv := s.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	rk := evpnAdKey(key.RD, key.ESI, key.EthernetTag)
	s.advMu.Lock()
	id, ok := s.advertised[rk]
	s.advMu.Unlock()
	if !ok {
		return nil
	}
	if err := srv.DeletePath(apiutil.DeletePathRequest{UUIDs: []uuid.UUID{id}}); err != nil {
		return fmt.Errorf("withdraw EVPN RT1 {rd=%s, esi=%x, etag=%d}: %w",
			key.RD, key.ESI, key.EthernetTag, err)
	}
	s.advMu.Lock()
	delete(s.advertised, rk)
	delete(s.producers, rk)
	s.advMu.Unlock()
	return nil
}

// evpnAdKey synthesizes the advertised-path tracking key for an RT1. RD goes
// in the dedicated RD field; Prefix holds the EthernetTag (digits) and the
// fixed-width hex ESI, which cannot collide across distinct tuples.
func evpnAdKey(rd string, esi [10]byte, etag uint32) bgp.RouteKey {
	return bgp.RouteKey{
		Family: bgp.FamilyEVPN,
		RD:     rd,
		Prefix: fmt.Sprintf("evpn-rt1:%d:%x", etag, esi),
	}
}

// encodeEVPNEthernetADPath builds the gobgp Path for an RT1 advertisement,
// the inverse of decodeEVPNEthernetAD. Both forms share the
// {RD, ESI, EthernetTag} NLRI (label 0) and the route targets; what differs
// is the payload. The per-ES form (ETag = MAX-ET) carries the ESI Label
// extended community, mandatory per RFC 7432 §8.2.1, whose Single-Active bit
// tells peers whether the segment may be aliased; it needs no SRv6 SID
// because the receive side only reads the bit. The per-EVI form carries the
// PE's own End.DT2U SID in the SRv6 L2 Service TLV (RFC 9252 §6.1), the
// address a peer sends aliased traffic to, so the SID is required there.
func encodeEVPNEthernetADPath(r bgp.EVPNRoute) (*apiutil.Path, error) {
	var zeroESI [10]byte
	if r.ESI == zeroESI {
		return nil, fmt.Errorf("EVPN RT1 ESI must be non-zero")
	}
	nh, err := netip.ParseAddr(r.NextHop)
	if err != nil || !nh.Is6() || nh.Is4In6() || nh.IsUnspecified() {
		return nil, fmt.Errorf("EVPN RT1 next hop must be IPv6: %q", r.NextHop)
	}
	rd, err := gobgppkt.ParseRouteDistinguisher(r.RD)
	if err != nil {
		return nil, fmt.Errorf("parse RD %q: %w", r.RD, err)
	}

	nlri := gobgppkt.NewEVPNEthernetAutoDiscoveryRoute(rd, arrayToESI(r.ESI), r.EthernetTag, 0)

	attrs := []gobgppkt.PathAttributeInterface{gobgppkt.NewPathAttributeOrigin(0)}
	ecs, err := parseRouteTargets(r.RTs)
	if err != nil {
		return nil, err
	}
	if r.IsPerES() {
		ecs = append(ecs, gobgppkt.NewESILabelExtended(0, r.SingleActive))
	}
	if len(ecs) > 0 {
		attrs = append(attrs, gobgppkt.NewPathAttributeExtendedCommunities(ecs))
	}
	if !r.IsPerES() {
		sid, err := netip.ParseAddr(r.SRv6SID)
		if err != nil || !sid.Is6() || sid.Is4In6() || sid.IsUnspecified() {
			return nil, fmt.Errorf("EVPN per-EVI RT1 SID must be a usable IPv6 SID: %q", r.SRv6SID)
		}
		infoSubTLV := gobgppkt.NewSRv6InformationSubTLV(sid, gobgppkt.END_DT2U)
		svcTLV := gobgppkt.NewSRv6ServiceTLV(gobgppkt.TLVTypeSRv6L2Service, infoSubTLV)
		attrs = append(attrs, gobgppkt.NewPathAttributePrefixSID(svcTLV))
	}

	mpReach, err := gobgppkt.NewPathAttributeMpReachNLRI(
		gobgppkt.RF_EVPN, []gobgppkt.PathNLRI{{NLRI: nlri}}, nh)
	if err != nil {
		return nil, fmt.Errorf("build MP_REACH_NLRI: %w", err)
	}
	attrs = append(attrs, mpReach)
	return &apiutil.Path{Family: gobgppkt.RF_EVPN, Nlri: nlri, Attrs: attrs}, nil
}

// arrayToESI is the inverse of esiToArray: it splits the RFC 7432 10-byte
// identifier back into gobgp's {Type, 9-byte Value} form.
func arrayToESI(esi [10]byte) gobgppkt.EthernetSegmentIdentifier {
	return gobgppkt.EthernetSegmentIdentifier{
		Type:  gobgppkt.ESIType(esi[0]),
		Value: append([]byte(nil), esi[1:]...),
	}
}
