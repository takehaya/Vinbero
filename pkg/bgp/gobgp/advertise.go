package gobgp

import (
	"context"
	"fmt"
	"net/netip"

	"go.uber.org/zap"

	"github.com/google/uuid"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	gobgpsrv "github.com/osrg/gobgp/v4/pkg/server"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// Advertise injects a VPNv4 / VPNv6 route carrying an SRv6 service SID
// into the BGP RIB. The gobgp path UUID is recorded so a later Withdraw
// can remove that exact path.
func (s *Session) Advertise(_ context.Context, r bgp.VPNRoute) error {
	srv := s.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	path, err := encodeVPNPath(r)
	if err != nil {
		return err
	}
	return s.addAndTrack(srv, path, r.Key())
}

// AdvertiseUnicast injects an IPv6 unicast route.
func (s *Session) AdvertiseUnicast(_ context.Context, r bgp.UnicastRoute) error {
	srv := s.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	path, err := encodeUnicastPath(r)
	if err != nil {
		return err
	}
	return s.addAndTrack(srv, path, bgp.RouteKey{Family: bgp.FamilyIPv6Unicast, Prefix: r.Prefix})
}

// ValidateVPNRoute reports whether this route could be encoded, without
// sending it.
//
// It exists for callers that reconcile a set of routes: they withdraw
// before they advertise, so a route that only fails inside the encoder has
// already cost the caller its other routes by the time the failure
// surfaces. Running the same encoder up front gives the same verdict
// without that cost, and without a second copy of its rules that could
// drift from it.
func (s *Session) ValidateVPNRoute(r bgp.VPNRoute) error {
	_, err := encodeVPNPath(r)
	return err
}

// ValidateUnicastRoute is ValidateVPNRoute for IPv6 unicast.
func (s *Session) ValidateUnicastRoute(r bgp.UnicastRoute) error {
	_, err := encodeUnicastPath(r)
	return err
}

// CanonicalRD renders a route distinguisher the one way the wire has it.
//
// 65000:1 and 065000:0001 are the same RD on the wire and different
// strings, so a caller keying anything on the string it was handed -- a
// lease, a diff -- has to canonicalize first or it will treat one route as
// two.
func (s *Session) CanonicalRD(rd string) (string, error) {
	parsed, err := gobgppkt.ParseRouteDistinguisher(rd)
	if err != nil {
		return "", err
	}
	return parsed.String(), nil
}

// Withdraw removes a previously advertised route. Withdrawing a route
// that was never advertised is a no-op so callers can withdraw
// idempotently.
func (s *Session) Withdraw(ctx context.Context, key bgp.RouteKey) error {
	return s.withdrawAs(ctx, key, "")
}

// withdrawAs removes a route on behalf of one producer.
//
// A key another producer put there is left alone. gobgp keeps one local
// path per NLRI, so two producers advertising one NLRI share the entry:
// deleting it on the strength of the wrong one's withdraw removes a route
// that is still wanted, and the producer that owns it goes on believing it
// is advertised. Refusing is not a fix for the overlap, which is a
// configuration problem, but it keeps the overlap from turning into a
// route that nothing will bring back.
func (s *Session) withdrawAs(_ context.Context, key bgp.RouteKey, producer string) error {
	srv := s.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	s.advMu.Lock()
	id, ok := s.advertised[key]
	holder := s.producers[key]
	s.advMu.Unlock()
	if !ok {
		return nil
	}
	if holder != producer {
		s.logger.Warn("not withdrawing a route another producer advertised",
			zap.String("prefix", key.Prefix),
			zap.String("rd", key.RD),
			zap.String("holder", producerName(holder)),
			zap.String("caller", producerName(producer)))
		return nil
	}
	// Drop the tracking entry only after gobgp confirms the delete, so a
	// failed DeletePath leaves the route still withdrawable on retry.
	if err := srv.DeletePath(apiutil.DeletePathRequest{UUIDs: []uuid.UUID{id}}); err != nil {
		return fmt.Errorf("withdraw %s: %w", key.Prefix, err)
	}
	s.advMu.Lock()
	delete(s.advertised, key)
	delete(s.producers, key)
	s.advMu.Unlock()
	return nil
}

// producerName renders a producer for a log line.
func producerName(p string) string {
	if p == "" {
		return "vinbero"
	}
	return p
}

// addAndTrack adds path to the RIB and records its UUID under key so
// Withdraw can later delete exactly this path. Re-advertising an
// existing key is safe: gobgp supersedes the local path with the same
// NLRI on AddPath, so the prior UUID is already invalid and is simply
// overwritten here -- no orphan path is left in the RIB.
func (s *Session) addAndTrack(srv *gobgpsrv.BgpServer, path *apiutil.Path, key bgp.RouteKey) error {
	return s.addAndTrackAs(srv, path, key, "")
}

// addAndTrackAs is addAndTrack on behalf of a named producer.
func (s *Session) addAndTrackAs(srv *gobgpsrv.BgpServer, path *apiutil.Path, key bgp.RouteKey, producer string) error {
	// The key is claimed under the lock, before AddPath, and given back if
	// AddPath fails. Checking and then claiming afterwards would let two
	// producers advertising the same new NLRI both pass the check and the
	// second overwrite the first, which is the outcome this exists to
	// prevent.
	s.advMu.Lock()
	holder, taken := s.producers[key]
	if taken && holder != producer {
		s.advMu.Unlock()
		// Refused rather than superseded. There is one local path per
		// NLRI, so taking it over discards the first producer's UUID: the
		// second producer's withdraw then removes the route outright,
		// while the first goes on believing it is advertising and never
		// puts it back. Whoever got there first keeps it, and the one
		// refused is told why, which is a conflict it can act on.
		return fmt.Errorf("advertise %s: already advertised by %s; %s cannot originate the same route "+
			"because BGP carries one local path per NLRI",
			key.Prefix, producerName(holder), producerName(producer))
	}
	s.producers[key] = producer
	s.advMu.Unlock()

	resps, err := srv.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{path}})
	// The claim is released on every failure path, or a route that was
	// never advertised would keep the key from anyone else forever.
	release := func() {
		s.advMu.Lock()
		if _, live := s.advertised[key]; !live && !taken {
			delete(s.producers, key)
		}
		s.advMu.Unlock()
	}
	if err != nil {
		release()
		return fmt.Errorf("advertise %s: %w", key.Prefix, err)
	}
	if len(resps) == 0 {
		release()
		return fmt.Errorf("advertise %s: gobgp returned no response", key.Prefix)
	}
	if resps[0].Error != nil {
		release()
		return fmt.Errorf("advertise %s: %w", key.Prefix, resps[0].Error)
	}
	s.advMu.Lock()
	s.advertised[key] = resps[0].UUID
	s.advMu.Unlock()
	return nil
}

// vinberoFamilyToAPI maps a Vinbero Family to a gobgp route family. It
// is the inverse of apiFamilyToVinbero.
func vinberoFamilyToAPI(f bgp.Family) (gobgppkt.Family, error) {
	switch f {
	case bgp.FamilyVPNv4:
		return gobgppkt.RF_IPv4_VPN, nil
	case bgp.FamilyVPNv6:
		return gobgppkt.RF_IPv6_VPN, nil
	case bgp.FamilyIPv6Unicast:
		return gobgppkt.RF_IPv6_UC, nil
	case bgp.FamilySRPolicyIPv6:
		return gobgppkt.RF_SR_POLICY_IPv6, nil
	case bgp.FamilyEVPN:
		return gobgppkt.RF_EVPN, nil
	case bgp.FamilyMUPIPv4:
		return gobgppkt.RF_MUP_IPv4, nil
	case bgp.FamilyMUPIPv6:
		return gobgppkt.RF_MUP_IPv6, nil
	default:
		return 0, fmt.Errorf("unsupported BGP family %q", f)
	}
}

// parseRouteTargets parses route-target strings into extended communities.
// Shared by the VPN / EVPN / MUP path encoders.
func parseRouteTargets(rts []string) ([]gobgppkt.ExtendedCommunityInterface, error) {
	ecs := make([]gobgppkt.ExtendedCommunityInterface, 0, len(rts))
	for _, rt := range rts {
		ec, err := gobgppkt.ParseRouteTarget(rt)
		if err != nil {
			return nil, fmt.Errorf("parse RT %q: %w", rt, err)
		}
		ecs = append(ecs, ec)
	}
	return ecs, nil
}

// vpnEndpointBehavior is the SRv6 endpoint behavior advertised with a
// VPN route: End.DT4 for VPNv4, End.DT6 for VPNv6, unless the route names
// one of its own.
//
// The override is for a plugin advertising a behavior it implements
// itself. The codepoint is not validated against the behaviors vinbero
// knows, because an unrecognized one is exactly the point.
func vpnEndpointBehavior(r bgp.VPNRoute) gobgppkt.SRBehavior {
	if r.EndpointBehavior != 0 {
		return gobgppkt.SRBehavior(r.EndpointBehavior)
	}
	if r.Family == bgp.FamilyVPNv6 {
		return gobgppkt.END_DT6
	}
	return gobgppkt.END_DT4
}

// encodeVPNPath builds the gobgp Path for a VPNv4 / VPNv6 advertisement.
// It is the inverse of decodeVPNRoute.
func encodeVPNPath(r bgp.VPNRoute) (*apiutil.Path, error) {
	family, err := vinberoFamilyToAPI(r.Family)
	if err != nil {
		return nil, err
	}
	rd, err := gobgppkt.ParseRouteDistinguisher(r.RD)
	if err != nil {
		return nil, fmt.Errorf("parse RD %q: %w", r.RD, err)
	}
	prefix, err := netip.ParsePrefix(r.Prefix)
	if err != nil {
		return nil, fmt.Errorf("parse prefix %q: %w", r.Prefix, err)
	}
	nlri, err := gobgppkt.NewLabeledVPNIPAddrPrefix(prefix, *gobgppkt.NewMPLSLabelStack(0), rd)
	if err != nil {
		return nil, fmt.Errorf("build VPN NLRI: %w", err)
	}
	attrs := []gobgppkt.PathAttributeInterface{gobgppkt.NewPathAttributeOrigin(0)}
	// Route targets and the Color Extended Community (RFC 9012 §4.3) are both
	// extended communities; carry them in one attribute. Color != 0 marks the
	// route for SR Policy steering on the receiving headend.
	ecs, err := parseRouteTargets(r.RTs)
	if err != nil {
		return nil, err
	}
	if r.Color != 0 {
		ecs = append(ecs, gobgppkt.NewColorExtended(r.Color))
	}
	if len(ecs) > 0 {
		attrs = append(attrs, gobgppkt.NewPathAttributeExtendedCommunities(ecs))
	}
	if r.SRv6SID != "" {
		sid, err := netip.ParseAddr(r.SRv6SID)
		if err != nil {
			return nil, fmt.Errorf("parse SRv6 SID %q: %w", r.SRv6SID, err)
		}
		var subSubs []gobgppkt.PrefixSIDTLVInterface
		if st := r.SIDStructure; !st.IsZero() {
			// Advertising a transposition means the transposed SID bits are
			// zeroed and carried in the VPN label (RFC 9252 §4). This encoder
			// does neither, so a non-zero transposition would put the peer's
			// fold out of sync with the wire -- reject rather than lie.
			if st.TranspositionLen != 0 || st.TranspositionOffset != 0 {
				return nil, fmt.Errorf("SID Structure with transposition %d/%d is not supported on advertise",
					st.TranspositionLen, st.TranspositionOffset)
			}
			subSubs = append(subSubs, gobgppkt.NewSRv6SIDStructureSubSubTLV(
				st.LocatorBlockLen, st.LocatorNodeLen, st.FunctionLen,
				st.ArgumentLen, st.TranspositionLen, st.TranspositionOffset))
		}
		infoSubTLV := gobgppkt.NewSRv6InformationSubTLV(sid, vpnEndpointBehavior(r), subSubs...)
		svcTLV := gobgppkt.NewSRv6ServiceTLV(gobgppkt.TLVTypeSRv6L3Service, infoSubTLV)
		attrs = append(attrs, gobgppkt.NewPathAttributePrefixSID(svcTLV))
	}
	nh, err := netip.ParseAddr(r.NextHop)
	if err != nil {
		return nil, fmt.Errorf("parse nexthop %q: %w", r.NextHop, err)
	}
	mpReach, err := gobgppkt.NewPathAttributeMpReachNLRI(family, []gobgppkt.PathNLRI{{NLRI: nlri}}, nh)
	if err != nil {
		return nil, fmt.Errorf("build MP_REACH_NLRI: %w", err)
	}
	attrs = append(attrs, mpReach)
	return &apiutil.Path{Family: family, Nlri: nlri, Attrs: attrs}, nil
}

// encodeUnicastPath builds the gobgp Path for an IPv6 unicast
// advertisement.
func encodeUnicastPath(r bgp.UnicastRoute) (*apiutil.Path, error) {
	prefix, err := netip.ParsePrefix(r.Prefix)
	if err != nil {
		return nil, fmt.Errorf("parse prefix %q: %w", r.Prefix, err)
	}
	nlri, err := gobgppkt.NewIPAddrPrefix(prefix)
	if err != nil {
		return nil, fmt.Errorf("build IPv6 NLRI: %w", err)
	}
	nh, err := netip.ParseAddr(r.NextHop)
	if err != nil {
		return nil, fmt.Errorf("parse nexthop %q: %w", r.NextHop, err)
	}
	mpReach, err := gobgppkt.NewPathAttributeMpReachNLRI(
		gobgppkt.RF_IPv6_UC, []gobgppkt.PathNLRI{{NLRI: nlri}}, nh)
	if err != nil {
		return nil, fmt.Errorf("build MP_REACH_NLRI: %w", err)
	}
	return &apiutil.Path{
		Family: gobgppkt.RF_IPv6_UC,
		Nlri:   nlri,
		Attrs:  []gobgppkt.PathAttributeInterface{gobgppkt.NewPathAttributeOrigin(0), mpReach},
	}, nil
}

// The names vinbero's own originators advertise under.
//
// They are distinct so the session can tell them apart, and prefixed so
// they cannot collide with a plugin's owner tag, which is what a plugin's
// producer name is.
const (
	// ProducerExport is the VRF auto-advertise path (pkg/bgp/export): the
	// routes vinbero originates because a VRF's own prefixes changed.
	ProducerExport = "vinbero:export"
	// ProducerOperator is the operator's own advertisements, made over
	// RPC. They are a separate producer from the exporter because they are
	// a separate intent: one follows the routing table, the other is what
	// an operator asked for, and one silently replacing the other is how a
	// route ends up advertised by nobody.
	ProducerOperator = "vinbero:operator"
)

// ProducerSession is a view of a Session that names itself on everything
// it originates.
//
// It exists because gobgp keeps one local path per NLRI: everything
// originating through one session shares that path, so a route two
// producers both advertise is one route, and the second withdraw to
// arrive would otherwise delete what the first still wants. Naming the
// producer is what lets the session tell those apart.
//
// It holds the session rather than embedding it, so it offers only the
// surfaces it actually names. Embedding would have it satisfy the EVPN,
// MUP and SR Policy interfaces through methods that write as the unnamed
// producer, and the compiler would accept it silently -- which is the
// failure this type exists to prevent, in the one form it would not be
// visible.
type ProducerSession struct {
	session  *Session
	producer string
}

var _ bgp.RouteAdvertiser = (*ProducerSession)(nil)

// AsProducer returns a view of this session that names producer on
// everything it advertises, and withdraws only what it advertised.
func (s *Session) AsProducer(producer string) *ProducerSession {
	return &ProducerSession{session: s, producer: producer}
}

// Producer is the name this view advertises under.
func (p *ProducerSession) Producer() string { return p.producer }

// Advertise injects a VPN route on behalf of this producer.
func (p *ProducerSession) Advertise(_ context.Context, r bgp.VPNRoute) error {
	srv := p.session.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	path, err := encodeVPNPath(r)
	if err != nil {
		return err
	}
	return p.session.addAndTrackAs(srv, path, r.Key(), p.producer)
}

// AdvertiseUnicast injects an IPv6 unicast route on behalf of this
// producer.
func (p *ProducerSession) AdvertiseUnicast(_ context.Context, r bgp.UnicastRoute) error {
	srv := p.session.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	path, err := encodeUnicastPath(r)
	if err != nil {
		return err
	}
	return p.session.addAndTrackAs(srv, path,
		bgp.RouteKey{Family: bgp.FamilyIPv6Unicast, Prefix: r.Prefix}, p.producer)
}

// Withdraw removes a route this producer advertised, and leaves one
// another producer advertised alone.
func (p *ProducerSession) Withdraw(ctx context.Context, key bgp.RouteKey) error {
	return p.session.withdrawAs(ctx, key, p.producer)
}

// ValidateVPNRoute, ValidateUnicastRoute and CanonicalRD ask the encoder
// the same questions the session would. They carry no producer: whether a
// route can be encoded does not depend on who is originating it, and a
// caller reconciling a set needs the answer before it withdraws anything.
func (p *ProducerSession) ValidateVPNRoute(r bgp.VPNRoute) error {
	return p.session.ValidateVPNRoute(r)
}

func (p *ProducerSession) ValidateUnicastRoute(r bgp.UnicastRoute) error {
	return p.session.ValidateUnicastRoute(r)
}

func (p *ProducerSession) CanonicalRD(rd string) (string, error) {
	return p.session.CanonicalRD(rd)
}
