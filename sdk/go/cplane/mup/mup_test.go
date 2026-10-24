package mup

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/gobgppath"
	"github.com/takehaya/vinbero/sdk/go/cplane/resolve"
	"github.com/takehaya/vinbero/sdk/go/cplane/routes"
)

func rd() bgp.RouteDistinguisherInterface { return bgp.NewRouteDistinguisherTwoOctetAS(65000, 7) }
func addr(s string) netip.Addr            { return netip.MustParseAddr(s) }
func prefix(s string) netip.Prefix        { return netip.MustParsePrefix(s) }
func teid(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}
func sidAttribute(behavior bgp.SRBehavior) *bgp.PathAttributePrefixSID {
	return bgp.NewPathAttributePrefixSID(bgp.NewSRv6ServiceTLV(bgp.TLVTypeSRv6L3Service, bgp.NewSRv6InformationSubTLV(addr("fd00:a:0:100::"), behavior, bgp.NewSRv6SIDStructureSubSubTLV(32, 16, 8, 72, 0, 0))))
}
func entry(n *bgp.MUPNLRI, attrs ...bgp.PathAttributeInterface) routes.Entry {
	family := "mup_ipv4"
	if n.Afi == bgp.AFI_IP6 {
		family = "mup_ipv6"
	}
	return routes.Entry{Family: family, Path: &gobgppath.Path{NLRI: n, Attributes: attrs}}
}
func TestSelectorsAndGTP4Builders(t *testing.T) {
	source := addr("192.0.2.7")
	a := ST1Selector().Project(entry(bgp.NewMUPType1SessionTransformedRoute(rd(), prefix("10.0.0.1/32"), teid(256), 9, addr("172.16.0.1"), &source)))
	b := ISDSelector().Project(entry(bgp.NewMUPInterworkSegmentDiscoveryRoute(rd(), prefix("172.16.0.0/24")), sidAttribute(bgp.ENDM_GTP4E)))
	if a.State != resolve.Present || b.State != resolve.Present || a.Value.Source.State != resolve.Present || a.Value.Source.Value != source {
		t.Fatalf("projection %v %v", a, b)
	}
	pair := resolve.Pair[ST1, ISD]{Left: a.Value, Right: b.Value, Context: "mobile"}
	ctx := DownlinkContext{Source: addr("fd00:feed::1"), ArgsOffset: 7}
	out, err := BuildDownlink(pair, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out.Context != "mobile" || out.Entry.TriggerPrefix != "10.0.0.1/32" || out.Entry.SrcAddr != "fd00:feed::1" || len(out.Entry.Segments) != 1 || out.Entry.Segments[0] != "fd00:a:0:1ac:1000:124:0:100" || out.Entry.Mode != 2 {
		t.Fatalf("unexpected output %+v", out)
	}
	// The projection owns all fields; mutating the borrowed packet source is safe.
	source = addr("192.0.2.8")
	if a.Value.Source.Value == source {
		t.Fatal("projection borrowed source")
	}
	ctx.RQI = 1
	out, err = BuildDownlink(pair, ctx)
	if err != nil || out.Entry.Segments[0] != "fd00:a:0:1ac:1000:126:0:100" {
		t.Fatalf("RQI %v %v", out, err)
	}
	ext := bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{bgp.NewMUPExtended(0, 0)})
	st2 := ST2Selector().Project(entry(bgp.NewMUPType2SessionTransformedRoute(rd(), 56, addr("192.0.2.9"), teid(0xabcdef12)), ext))
	dsd := DSDSelector().Project(entry(bgp.NewMUPDirectSegmentDiscoveryRoute(rd(), addr("192.0.2.10")), ext, sidAttribute(bgp.END_DT4)))
	if st2.State != resolve.Present || dsd.State != resolve.Present || st2.Value.TEID != 0xabcdef00 || st2.Value.TEIDBits != 24 || st2.Value.Direct.State != resolve.Present {
		t.Fatalf("ST2/DSD %v %v", st2, dsd)
	}
	up, err := BuildUplink(resolve.Pair[ST2, DSD]{Left: st2.Value, Right: dsd.Value, Context: "mobile"}, ctx.Source)
	if err != nil || up.TEID != 0xabcdef00 || up.TEIDBits != 24 || up.Endpoint != "192.0.2.9" || len(up.Segments) != 1 || up.Segments[0] != "fd00:a:0:100::" {
		t.Fatalf("uplink %+v %v", up, err)
	}
}
func TestDirectSegmentPresenceAndKinds(t *testing.T) {
	tests := []struct {
		name        string
		communities []bgp.ExtendedCommunityInterface
		state       resolve.State
		reason      string
	}{
		{"missing", nil, resolve.Missing, "ST2+ISD"},
		{"zero", []bgp.ExtendedCommunityInterface{bgp.NewMUPExtended(0, 0)}, resolve.Present, ""},
		{"duplicate", []bgp.ExtendedCommunityInterface{bgp.NewMUPExtended(0, 0), bgp.NewMUPExtended(0, 0)}, resolve.Ambiguous, "duplicate"},
		{"different", []bgp.ExtendedCommunityInterface{bgp.NewMUPExtended(1, 2), bgp.NewMUPExtended(1, 3)}, resolve.Ambiguous, "duplicate"},
		{"mixed", []bgp.ExtendedCommunityInterface{bgp.NewMUPExtended(1, 2), bgp.NewUnknownExtended(bgp.EC_TYPE_MUP, []byte{3})}, resolve.Invalid, "mixed"},
		{"new-direct-format", []bgp.ExtendedCommunityInterface{bgp.NewUnknownExtended(bgp.EC_TYPE_MUP, []byte{1})}, resolve.Invalid, "unsupported"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := ST2Selector().Project(entry(bgp.NewMUPType2SessionTransformedRoute(rd(), 32, addr("192.0.2.1"), teid(0)), bgp.NewPathAttributeExtendedCommunities(tt.communities)))
			if p.State != resolve.Present {
				t.Fatal(p)
			}
			got := ST2DirectSegment.Get(p.Value)
			if got.State != tt.state || !strings.Contains(got.Reason, tt.reason) {
				t.Fatalf("got %v want state %d reason %s", got, tt.state, tt.reason)
			}
			if p.Value.TEID != 0 || p.Value.TEIDBits != 0 {
				t.Fatal("valid wildcard was lost")
			}
		})
	}
	invalid := bgp.NewMUPType2SessionTransformedRoute(rd(), 31, addr("192.0.2.1"), teid(0))
	if x := ST2Selector().Project(entry(invalid)); x.State != resolve.Invalid {
		t.Fatalf("missing endpoint bits became wildcard: %v", x)
	}
	invalid = bgp.NewMUPType2SessionTransformedRoute(rd(), 32, addr("192.0.2.1"), netip.Addr{})
	if x := ST2Selector().Project(entry(invalid)); x.State != resolve.Invalid {
		t.Fatalf("missing TEID became zero: %v", x)
	}
}
func TestDownlinkRejectsUnsafeProfile(t *testing.T) {
	a := ST1Selector().Project(entry(bgp.NewMUPType1SessionTransformedRoute(rd(), prefix("10.0.0.1/32"), teid(256), 9, addr("172.16.0.1"), nil))).Value
	b := ISDSelector().Project(entry(bgp.NewMUPInterworkSegmentDiscoveryRoute(rd(), prefix("172.16.0.0/24")), sidAttribute(bgp.ENDM_GTP4E))).Value
	base := resolve.Pair[ST1, ISD]{Left: a, Right: b, Context: "mobile"}
	ctx := DownlinkContext{Source: addr("fd00:feed::1"), ArgsOffset: 7}
	cases := map[string]func(*resolve.Pair[ST1, ISD], *DownlinkContext){
		"missing-source":    func(_ *resolve.Pair[ST1, ISD], c *DownlinkContext) { c.Source = netip.Addr{} },
		"offset":            func(_ *resolve.Pair[ST1, ISD], c *DownlinkContext) { c.ArgsOffset = 8 },
		"rqi":               func(_ *resolve.Pair[ST1, ISD], c *DownlinkContext) { c.RQI = 2 },
		"qfi":               func(p *resolve.Pair[ST1, ISD], _ *DownlinkContext) { p.Left.QFI = 64 },
		"gtp6":              func(p *resolve.Pair[ST1, ISD], _ *DownlinkContext) { p.Left.Endpoint = addr("2001:db8::1") },
		"function-overlap":  func(p *resolve.Pair[ST1, ISD], _ *DownlinkContext) { p.Right.Service.Value.Structure.Function = 16 },
		"short-argument":    func(p *resolve.Pair[ST1, ISD], _ *DownlinkContext) { p.Right.Service.Value.Structure.Argument = 64 },
		"missing-structure": func(p *resolve.Pair[ST1, ISD], _ *DownlinkContext) { p.Right.Service.Value.HasStructure = false },
		"missing-sid": func(p *resolve.Pair[ST1, ISD], _ *DownlinkContext) {
			p.Right.Service = resolve.Absent[gobgppath.ServiceSID]("missing")
		},
		"wrong-behavior": func(p *resolve.Pair[ST1, ISD], _ *DownlinkContext) {
			p.Right.Service.Value.Behavior = uint16(bgp.END_DT4)
		},
		"wrong-isd": func(p *resolve.Pair[ST1, ISD], _ *DownlinkContext) { p.Right.Prefix = prefix("192.0.2.0/24") },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p, c := base, ctx
			change(&p, &c)
			if _, err := BuildDownlink(p, c); err == nil {
				t.Fatal("unsafe profile accepted")
			}
		})
	}
}
func event(t *testing.T, n *bgp.MUPNLRI, peer string, attrs ...bgp.PathAttributeInterface) cplane.Event {
	t.Helper()
	raw, err := n.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	p := &cplane.BGPPath{Codec: cplane.BGPPathCodec, AFI: n.Afi, SAFI: 85, RouteKey: []byte(n.String()), NLRI: raw}
	for _, a := range attrs {
		data, err := a.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		p.Attributes = append(p.Attributes, data)
	}
	family := "mup_ipv4"
	if n.Afi == bgp.AFI_IP6 {
		family = "mup_ipv6"
	}
	return cplane.Event{Kind: cplane.EventRoute, Route: cplane.Route{Family: family, Peer: peer, BGPPath: p, Contexts: []string{"mobile"}}}
}
func engine(t *testing.T) (*resolve.Engine, *resolve.Plan[ST1, ISD]) {
	t.Helper()
	v, err := routes.NewView(cplane.InputConfig{Version: 1, Codec: cplane.BGPPathCodec, Contexts: []cplane.InputContext{{Name: "mobile", Families: families()}}}, routes.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	e, err := resolve.NewEngine(v, resolve.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	rank := resolve.LongestPrefix(resolve.Right(ISDPrefix))
	p, err := resolve.Register(e, resolve.Rule[ST1, ISD]{Name: "downlink", Context: "mobile", Left: ST1Selector(), Right: ISDSelector(), Match: resolve.Contains(resolve.Right(ISDPrefix), resolve.Left(ST1Endpoint)), Rank: &rank, Choose: resolve.Unique})
	if err != nil {
		t.Fatal(err)
	}
	return e, p
}
func TestRuleSupportersWithdrawalAndNoSIDFallback(t *testing.T) {
	e, p := engine(t)
	st1 := event(t, bgp.NewMUPType1SessionTransformedRoute(rd(), prefix("10.0.0.1/32"), teid(256), 9, addr("172.16.0.1"), nil), "192.0.2.1")
	short := event(t, bgp.NewMUPInterworkSegmentDiscoveryRoute(rd(), prefix("172.16.0.0/24")), "192.0.2.2", sidAttribute(bgp.ENDM_GTP4E))
	long := event(t, bgp.NewMUPInterworkSegmentDiscoveryRoute(rd(), prefix("172.16.0.1/32")), "192.0.2.3")
	e.Update([]cplane.Event{{Kind: cplane.EventStartOfReplay, ReplaySource: cplane.BGPSource}, st1, short, long, {Kind: cplane.EventEndOfReplay, ReplaySource: cplane.BGPSource}})
	pairs := p.Results()
	if !e.Status().Ready || len(pairs) != 1 || pairs[0].Right.Prefix != prefix("172.16.0.1/32") {
		t.Fatalf("wrong LPM result: %v %v", e.Status(), pairs)
	}
	ctx := DownlinkContext{Source: addr("fd00:feed::1"), ArgsOffset: 7}
	if _, err := BuildDownlink(pairs[0], ctx); err == nil {
		t.Fatal("missing SID fell back to shorter prefix")
	}
	long.Route.Withdraw = true
	long.Route.BGPPath.NLRI = nil
	e.Update([]cplane.Event{long})
	duplicate := short
	duplicate.Route.Peer = "192.0.2.4"
	e.Update([]cplane.Event{duplicate})
	pairs = p.Results()
	if len(pairs) != 1 || len(pairs[0].RightPaths) != 2 {
		t.Fatalf("equivalent supporters not retained: %v", pairs)
	}
	other := event(t, bgp.NewMUPInterworkSegmentDiscoveryRoute(rd(), prefix("172.16.0.0/24")), "192.0.2.4", sidAttribute(bgp.END_DT4))
	e.Update([]cplane.Event{other})
	if len(p.Results()) != 0 {
		t.Fatal("different builder behavior was coalesced")
	}
	e.Update([]cplane.Event{{Kind: cplane.EventStartOfReplay, ReplaySource: cplane.BGPSource}})
	if len(p.Results()) != 0 || e.Status().Ready {
		t.Fatal("results survived incomplete replay")
	}
}

func TestDirectRuleUsesTypedSegmentAndUniqueDestination(t *testing.T) {
	e, _ := engine(t)
	plan, err := resolve.Register(e, resolve.Rule[ST2, DSD]{Name: "uplink", Context: "mobile", Left: ST2Selector(), Right: DSDSelector(), Match: resolve.Equal(resolve.Left(ST2DirectSegment), resolve.Right(DSDDirectSegment)), Choose: resolve.Unique})
	if err != nil {
		t.Fatal(err)
	}
	ext := bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{bgp.NewMUPExtended(0, 0)})
	st := event(t, bgp.NewMUPType2SessionTransformedRoute(rd(), 64, addr("192.0.2.1"), teid(7)), "192.0.2.10", ext)
	d1 := event(t, bgp.NewMUPDirectSegmentDiscoveryRoute(rd(), addr("192.0.2.2")), "192.0.2.11", ext, sidAttribute(bgp.END_DT4))
	d2 := d1
	d2.Route.Peer = "192.0.2.12"
	e.Update([]cplane.Event{{Kind: cplane.EventStartOfReplay, ReplaySource: cplane.BGPSource}, st, d1, d2, {Kind: cplane.EventEndOfReplay, ReplaySource: cplane.BGPSource}})
	result := plan.Results()
	if len(result) != 1 || len(result[0].RightPaths) != 2 {
		t.Fatalf("zero-segment supporters %v", result)
	}
	if _, err := BuildUplink(result[0], addr("fd00:feed::1")); err != nil {
		t.Fatal(err)
	}
	other := event(t, bgp.NewMUPDirectSegmentDiscoveryRoute(rd(), addr("192.0.2.3")), "192.0.2.13", ext, sidAttribute(bgp.END_DT4))
	e.Update([]cplane.Event{other})
	if len(plan.Results()) != 0 {
		t.Fatal("equal segment on another destination was silently chosen")
	}
	other.Route.Withdraw = true
	e.Update([]cplane.Event{other})
	if len(plan.Results()) != 1 {
		t.Fatal("withdraw didn't restore unique destination")
	}
	missing := event(t, bgp.NewMUPType2SessionTransformedRoute(rd(), 64, addr("192.0.2.1"), teid(7)), "192.0.2.10")
	e.Update([]cplane.Event{missing})
	if len(plan.Results()) != 0 {
		t.Fatal("missing Direct was treated as zero")
	}
}
