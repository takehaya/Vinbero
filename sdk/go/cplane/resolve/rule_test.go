package resolve_test

import (
	"net/netip"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/gobgppath"
	"github.com/takehaya/vinbero/sdk/go/cplane/resolve"
	"github.com/takehaya/vinbero/sdk/go/cplane/routes"
)

// A third protocol combination: resolve a VPN's service SID through an IPv6
// unicast prefix. The projection includes every field a hypothetical builder
// would consume, so equal prefixes with different next hops remain ambiguous.
type vpnRoute struct {
	RD      string
	Prefix  netip.Prefix
	Service gobgppath.ServiceSID
}
type underlayRoute struct {
	Prefix  netip.Prefix
	NextHop netip.Addr
}

func vpnRule() resolve.Rule[vpnRoute, underlayRoute] {
	left := resolve.Selector[vpnRoute]{Families: []string{"vpnv4"}, Project: func(e routes.Entry) resolve.Value[vpnRoute] {
		n, ok := e.Path.NLRI.(*bgp.LabeledVPNIPAddrPrefix)
		if !ok {
			return resolve.Absent[vpnRoute]("not a VPN")
		}
		sid, err := gobgppath.ReadServiceSID(e.Path.Attributes, bgp.TLVTypeSRv6L3Service)
		if err != nil {
			return resolve.Bad[vpnRoute](err.Error())
		}
		return resolve.Known(vpnRoute{n.RD.String(), n.Prefix, sid})
	}}
	right := resolve.Selector[underlayRoute]{Families: []string{"ipv6_unicast"}, Project: func(e routes.Entry) resolve.Value[underlayRoute] {
		n, ok := e.Path.NLRI.(*bgp.IPAddrPrefix)
		if !ok {
			return resolve.Absent[underlayRoute]("not unicast")
		}
		var next netip.Addr
		for _, a := range e.Path.Attributes {
			if mp, ok := a.(*bgp.PathAttributeMpReachNLRI); ok {
				next = mp.Nexthop
			}
		}
		if !next.IsValid() {
			return resolve.Bad[underlayRoute]("missing next hop")
		}
		return resolve.Known(underlayRoute{n.Prefix, next})
	}}
	sid := resolve.Field[vpnRoute, netip.Addr]{Name: "service_sid", Get: func(v vpnRoute) resolve.Value[netip.Addr] { return resolve.Known(v.Service.Address) }}
	prefix := resolve.Field[underlayRoute, netip.Prefix]{Name: "prefix", Get: func(v underlayRoute) resolve.Value[netip.Prefix] { return resolve.Known(v.Prefix) }}
	rank := resolve.LongestPrefix(resolve.Right(prefix))
	return resolve.Rule[vpnRoute, underlayRoute]{Name: "vpn-underlay", Context: "tenant", Left: left, Right: right,
		Match: resolve.Contains(resolve.Right(prefix), resolve.Left(sid)), Rank: &rank, Choose: resolve.Unique}
}

func engine(t *testing.T, vl routes.Limits, el resolve.Limits) (*resolve.Engine, *resolve.Plan[vpnRoute, underlayRoute]) {
	t.Helper()
	v, err := routes.NewView(cplane.InputConfig{Version: 1, Codec: cplane.BGPPathCodec,
		Contexts: []cplane.InputContext{{Name: "tenant", Families: []string{"vpnv4", "ipv6_unicast"}}, {Name: "other", Families: []string{"ipv6_unicast"}}}}, vl)
	if err != nil {
		t.Fatal(err)
	}
	e, err := resolve.NewEngine(v, el)
	if err != nil {
		t.Fatal(err)
	}
	p, err := resolve.Register(e, vpnRule())
	if err != nil {
		t.Fatal(err)
	}
	return e, p
}

func packetEvent(t *testing.T, family bgp.Family, name, peer string, n bgp.NLRI, attrs ...bgp.PathAttributeInterface) cplane.Event {
	t.Helper()
	p, err := gobgppath.Encode(family, n, attrs)
	if err != nil {
		t.Fatal(err)
	}
	p.RouteKey = []byte(n.String())
	return cplane.Event{Kind: cplane.EventRoute, Route: cplane.Route{Family: name, Peer: peer, Contexts: []string{"tenant"}, BGPPath: p}}
}

func vpn(t *testing.T) cplane.Event {
	t.Helper()
	n, err := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"), *bgp.NewMPLSLabelStack(100), bgp.NewRouteDistinguisherTwoOctetAS(65000, 7))
	if err != nil {
		t.Fatal(err)
	}
	sid := bgp.NewPathAttributePrefixSID(bgp.NewSRv6ServiceTLV(bgp.TLVTypeSRv6L3Service, bgp.NewSRv6InformationSubTLV(netip.MustParseAddr("2001:db8:1::7"), bgp.END_DT4)))
	return packetEvent(t, bgp.RF_IPv4_VPN, "vpnv4", "192.0.2.1", n, sid)
}

func underlay(t *testing.T, prefix, peer, next string) cplane.Event {
	t.Helper()
	n, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	if err != nil {
		t.Fatal(err)
	}
	mp, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: n}}, netip.MustParseAddr(next))
	if err != nil {
		t.Fatal(err)
	}
	return packetEvent(t, bgp.RF_IPv6_UC, "ipv6_unicast", peer, n, mp)
}

func replay(events ...cplane.Event) []cplane.Event {
	return append(append([]cplane.Event{{Kind: cplane.EventStartOfReplay, ReplaySource: cplane.BGPSource}}, events...), cplane.Event{Kind: cplane.EventEndOfReplay, ReplaySource: cplane.BGPSource})
}

func issue(e *resolve.Engine, code string) bool {
	for _, i := range e.Status().Issues {
		if i.Code == code {
			return true
		}
	}
	return false
}

func TestVPNAndIPv6UnicastLongestPrefixAndSupporters(t *testing.T) {
	e, p := engine(t, routes.Limits{}, resolve.Limits{})
	wide := underlay(t, "2001:db8::/32", "192.0.2.2", "2001:db8:ffff::1")
	narrow := underlay(t, "2001:db8:1::/48", "192.0.2.3", "2001:db8:ffff::2")
	second := underlay(t, "2001:db8:1::/48", "192.0.2.4", "2001:db8:ffff::2")
	if e.Status().Ready {
		t.Fatal("new engine ready before replay")
	}
	e.Update(replay(vpn(t), wide, narrow, second))
	pairs := p.Results()
	if !e.Status().Ready || len(pairs) != 1 || pairs[0].Right.Prefix.Bits() != 48 || len(pairs[0].RightPaths) != 2 || pairs[0].Revision != e.Status().Revision {
		t.Fatalf("resolution: %+v status=%+v", pairs, e.Status())
	}
	// Caller mutations of result dependency slices do not alter the plan.
	pairs[0].RightPaths[0].Peer = "corrupted"
	if p.Results()[0].RightPaths[0].Peer == "corrupted" {
		t.Fatal("borrowed dependency slice")
	}
	narrow.Route.Withdraw = true
	e.Update([]cplane.Event{narrow})
	if got := p.Results(); len(got) != 1 || len(got[0].RightPaths) != 1 || got[0].Right.Prefix.Bits() != 48 {
		t.Fatalf("supporter withdraw: %+v", got)
	}
	second.Route.Withdraw = true
	e.Update([]cplane.Event{second})
	if got := p.Results(); len(got) != 1 || got[0].Right.Prefix.Bits() != 32 {
		t.Fatalf("fallback: %+v", got)
	}
	wide.Route.Withdraw = true
	e.Update([]cplane.Event{wide})
	if len(p.Results()) != 0 || !issue(e, "unresolved") {
		t.Fatal("missing discovery not diagnosed")
	}
}

func TestDistinctProjectionAmbiguousAndContextIsolated(t *testing.T) {
	e, p := engine(t, routes.Limits{}, resolve.Limits{})
	a := underlay(t, "2001:db8:1::/48", "192.0.2.2", "2001:db8:ffff::1")
	b := underlay(t, "2001:db8:1::/48", "192.0.2.3", "2001:db8:ffff::2")
	e.Update(replay(vpn(t), a, b))
	if len(p.Results()) != 0 || !issue(e, "ambiguous") {
		t.Fatal("different next hops silently coalesced")
	}
	b.Route.Contexts = []string{"other"}
	e.Update([]cplane.Event{b})
	if len(p.Results()) != 1 {
		t.Fatal("unrelated context influenced resolution")
	}
	a.Route.Contexts = nil
	e.Update([]cplane.Event{a})
	if len(p.Results()) != 0 || !issue(e, "unresolved") {
		t.Fatal("lost membership retained old route")
	}
}

func TestReplayAndMalformedReplacementClearResults(t *testing.T) {
	e, p := engine(t, routes.Limits{}, resolve.Limits{})
	a := underlay(t, "2001:db8:1::/48", "192.0.2.2", "2001:db8:ffff::1")
	e.Update(replay(vpn(t), a))
	a.Route.BGPPath.Attributes = [][]byte{{64, 1}}
	results := e.Update([]cplane.Event{a})
	if len(results) != 1 || results[0].Disposition != cplane.Quarantine || len(p.Results()) != 0 {
		t.Fatal("malformed update retained old candidate")
	}
	e.Update([]cplane.Event{{Kind: cplane.EventStartOfReplay, ReplaySource: cplane.BGPSource}})
	if e.Status().Ready || len(p.Results()) != 0 {
		t.Fatal("partial replay was usable")
	}
	e.Update([]cplane.Event{vpn(t)})
	if e.Status().Ready {
		t.Fatal("ready before replay end")
	}
	e.Update(replay())
	if !e.Status().Ready || len(p.Results()) != 0 {
		t.Fatal("empty replay did not recover")
	}
}

func TestQuotasInvalidateAndRecoverWithReplay(t *testing.T) {
	for name, limits := range map[string]struct {
		view   routes.Limits
		engine resolve.Limits
	}{
		"paths": {view: routes.Limits{MaxPaths: 1}},
		"bytes": {view: routes.Limits{MaxBytes: 1}},
		"work":  {engine: resolve.Limits{MaxWork: 1}},
	} {
		t.Run(name, func(t *testing.T) {
			e, p := engine(t, limits.view, limits.engine)
			results := e.Update(replay(vpn(t), underlay(t, "2001:db8::/32", "192.0.2.2", "2001:db8:ffff::1")))
			incomplete := false
			for _, r := range results {
				incomplete = incomplete || r.Disposition == cplane.InputIncomplete
			}
			if e.Status().Ready || len(p.Results()) != 0 || !incomplete {
				t.Fatalf("quota left usable results: %+v %v", e.Status(), results)
			}
			e.Update(nil)
			if e.Status().Ready {
				t.Fatal("incomplete state recovered without replay")
			}
			e.Update(replay())
			if !e.Status().Ready {
				t.Fatal("empty replay did not recover")
			}
		})
	}
}

func TestRuleRegistrationRequiresGrantedFamiliesAndBoundedRules(t *testing.T) {
	e, _ := engine(t, routes.Limits{}, resolve.Limits{MaxRules: 1})
	r := vpnRule()
	r.Name = "second"
	if _, err := resolve.Register(e, r); err == nil {
		t.Fatal("rule quota ignored")
	}
	e, _ = engine(t, routes.Limits{}, resolve.Limits{})
	r.Context = "other"
	if _, err := resolve.Register(e, r); err == nil {
		t.Fatal("ungranted left family accepted")
	}
}
