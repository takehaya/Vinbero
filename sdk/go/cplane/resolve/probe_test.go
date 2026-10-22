package resolve_test

import (
	"net/netip"
	"strconv"
	"testing"

	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/resolve"
	"github.com/takehaya/vinbero/sdk/go/cplane/routes"
)

func probeEngine(t *testing.T, rule resolve.Rule[vpnRoute, underlayRoute]) (*resolve.Engine, *resolve.Plan[vpnRoute, underlayRoute]) {
	t.Helper()
	v, err := routes.NewView(cplane.InputConfig{Version: 1, Codec: cplane.BGPPathCodec,
		Contexts: []cplane.InputContext{{Name: "tenant", Families: []string{"vpnv4", "ipv6_unicast"}}}}, routes.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	e, err := resolve.NewEngine(v, resolve.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := resolve.Register(e, rule)
	if err != nil {
		t.Fatal(err)
	}
	return e, p
}

func TestContainsRepeatedAddressPreservesAccessorReadsAndFreshEvaluation(t *testing.T) {
	rule := vpnRule()
	address := netip.MustParseAddr("2001:db8:1::7")
	calls, failAt := 0, 0
	sid := resolve.Field[vpnRoute, netip.Addr]{Name: "dynamic_sid", Get: func(vpnRoute) resolve.Value[netip.Addr] {
		calls++
		if calls == failAt {
			return resolve.Bad[netip.Addr]("accessor failure")
		}
		return resolve.Known(address)
	}}
	prefix := resolve.Field[underlayRoute, netip.Prefix]{Name: "prefix", Get: func(v underlayRoute) resolve.Value[netip.Prefix] { return resolve.Known(v.Prefix) }}
	// All must retain the first condition's index and still execute each match.
	rule.Match = resolve.All(resolve.Contains(resolve.Right(prefix), resolve.Left(sid)))
	e, p := probeEngine(t, rule)
	a, b := vpn(t), vpn(t)
	b.Route.Peer = "192.0.2.5"
	wide := underlay(t, "2001:db8::/32", "192.0.2.2", "2001:db8:ffff::1")
	narrow := underlay(t, "2001:db8:1::/48", "192.0.2.3", "2001:db8:ffff::2")
	e.Update(replay(a, b, wide, narrow))
	if calls != 6 || len(p.Results()) != 2 {
		t.Fatalf("every left probe and both candidate matches must read accessor: calls=%d pairs=%+v", calls, p.Results())
	}
	for _, pair := range p.Results() {
		if pair.Right.Prefix.Bits() != 48 {
			t.Fatal("longest-prefix selection changed")
		}
	}
	// Accessors have no purity contract: unchanged routes must be evaluated
	// again, even when the callback now returns a different address.
	address = netip.MustParseAddr("2001:db8:2::7")
	calls = 0
	e.Update(nil)
	if calls != 4 || len(p.Results()) != 2 {
		t.Fatalf("fresh evaluation: calls=%d pairs=%+v", calls, p.Results())
	}
	for _, pair := range p.Results() {
		if pair.Right.Prefix.Bits() != 32 {
			t.Fatal("stale prefix probes influenced a later evaluation")
		}
	}
	for _, check := range []struct {
		failAt int
		code   string
		calls  int
	}{{3, "invalid_left_field", 3}, {4, "invalid_match", 4}} {
		calls, failAt = 0, check.failAt
		e.Update(nil)
		if calls != check.calls || len(p.Results()) != 1 || !issue(e, check.code) {
			t.Fatalf("failure at %d bypassed: calls=%d pairs=%+v status=%+v", failAt, calls, p.Results(), e.Status())
		}
	}
}

func TestContainsAddressChangesWithinEvaluation(t *testing.T) {
	// The sequence includes repeated, alternate-family, invalid, and mapped
	// addresses; each valid path must resolve through its own address family.
	addresses := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1"),
		{}, netip.MustParseAddr("::ffff:192.0.2.1"), netip.MustParseAddr("192.0.2.1"),
	}
	rule := vpnRule()
	calls := 0
	sid := resolve.Field[vpnRoute, netip.Addr]{Name: "dynamic_sid", Get: func(v vpnRoute) resolve.Value[netip.Addr] {
		calls++
		return resolve.Known(v.Service.Address)
	}}
	prefix := resolve.Field[underlayRoute, netip.Prefix]{Name: "prefix", Get: func(v underlayRoute) resolve.Value[netip.Prefix] { return resolve.Known(v.Prefix) }}
	rule.Match = resolve.Contains(resolve.Right(prefix), resolve.Left(sid))
	leftProject, rightProject := rule.Left.Project, rule.Right.Project
	rule.Left.Project = func(entry routes.Entry) resolve.Value[vpnRoute] {
		x := leftProject(entry)
		x.Value.Service.Address = addresses[entry.Key.PathID]
		return x
	}
	rule.Right.Project = func(entry routes.Entry) resolve.Value[underlayRoute] {
		x := rightProject(entry)
		if entry.Key.PathID == 1 {
			x.Value.Prefix = netip.MustParsePrefix("192.0.2.0/24")
		}
		return x
	}
	e, p := probeEngine(t, rule)
	var events []cplane.Event
	for i := range addresses {
		ev := vpn(t)
		ev.Route.PathID = uint32(i)
		events = append(events, ev)
	}
	right6 := underlay(t, "2001:db8::/32", "192.0.2.2", "2001:db8:ffff::1")
	right4 := underlay(t, "2001:db8:1::/48", "192.0.2.3", "2001:db8:ffff::2")
	right4.Route.PathID = 1
	events = append(events, right6, right4)
	e.Update(replay(events...))
	invalid, unresolved := 0, 0
	for _, i := range e.Status().Issues {
		switch i.Code {
		case "invalid_left_field":
			invalid++
		case "unresolved":
			unresolved++
		}
	}
	if calls != 12 || invalid != 2 || unresolved != 0 || len(p.Results()) != 5 || !e.Status().Ready {
		t.Fatalf("calls=%d status=%+v pairs=%+v", calls, e.Status(), p.Results())
	}
	for _, pair := range p.Results() {
		if !pair.Right.Prefix.Contains(pair.Left.Service.Address) {
			t.Fatalf("wrong address-family match: %+v", pair)
		}
	}
}

func TestContainsRepeatedAddressStillChargesEveryProbe(t *testing.T) {
	for _, maxWork := range []int{262, 263} {
		t.Run(strconv.Itoa(maxWork), func(t *testing.T) {
			e, p := engine(t, routes.Limits{}, resolve.Limits{MaxWork: maxWork})
			a, b := vpn(t), vpn(t)
			b.Route.Peer = "192.0.2.5"
			// One right scan plus two left scans, each spending 1 for the
			// left path, 129 prefix probes, and 1 matching candidate: 263.
			results := e.Update(replay(a, b, underlay(t, "2001:db8::/32", "192.0.2.2", "2001:db8:ffff::1")))
			if maxWork == 263 {
				if len(results) != 0 || !e.Status().Ready || len(p.Results()) != 2 {
					t.Fatalf("exact budget failed: %+v %+v", results, e.Status())
				}
				return
			}
			if len(results) != 1 || results[0].Disposition != cplane.InputIncomplete || e.Status().Ready || len(p.Results()) != 0 {
				t.Fatalf("cached probes bypassed budget: %+v %+v", results, e.Status())
			}
			e.Update(nil)
			if e.Status().Ready {
				t.Fatal("ordinary evaluation recovered an incomplete view")
			}
			e.Update(replay(a))
			if !e.Status().Ready || len(p.Results()) != 0 {
				t.Fatal("fresh smaller replay did not recover")
			}
		})
	}
}
