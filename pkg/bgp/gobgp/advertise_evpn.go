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
	s.advMu.Unlock()
	return nil
}

// evpnAdvKey synthesizes the advertised-path tracking key for an RT2. The
// shared advertised map is keyed by bgp.RouteKey, so the {RD, EthernetTag,
// MAC} tuple is encoded into the Prefix field.
func evpnAdvKey(rd string, etag uint32, mac string) bgp.RouteKey {
	return bgp.RouteKey{
		Family: bgp.FamilyEVPN,
		Prefix: fmt.Sprintf("evpn-rt2:%s:%d:%s", rd, etag, mac),
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
	s.advMu.Unlock()
	return nil
}

// evpnImetKey synthesizes the advertised-path tracking key for an RT3
// (Inclusive Multicast Ethernet Tag), encoding {RD, EthernetTag} into Prefix.
func evpnImetKey(rd string, etag uint32) bgp.RouteKey {
	return bgp.RouteKey{
		Family: bgp.FamilyEVPN,
		Prefix: fmt.Sprintf("evpn-rt3:%s:%d", rd, etag),
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
	if err != nil || !nh.Is6() {
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
	ecs := make([]gobgppkt.ExtendedCommunityInterface, 0, len(r.RTs))
	for _, rt := range r.RTs {
		ec, err := gobgppkt.ParseRouteTarget(rt)
		if err != nil {
			return nil, fmt.Errorf("parse RT %q: %w", rt, err)
		}
		ecs = append(ecs, ec)
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
	if err != nil || !nh.Is6() {
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
	ecs := make([]gobgppkt.ExtendedCommunityInterface, 0, len(r.RTs))
	for _, rt := range r.RTs {
		ec, err := gobgppkt.ParseRouteTarget(rt)
		if err != nil {
			return nil, fmt.Errorf("parse RT %q: %w", rt, err)
		}
		ecs = append(ecs, ec)
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

// arrayToESI is the inverse of esiToArray: it splits the RFC 7432 10-byte
// identifier back into gobgp's {Type, 9-byte Value} form.
func arrayToESI(esi [10]byte) gobgppkt.EthernetSegmentIdentifier {
	return gobgppkt.EthernetSegmentIdentifier{
		Type:  gobgppkt.ESIType(esi[0]),
		Value: append([]byte(nil), esi[1:]...),
	}
}
