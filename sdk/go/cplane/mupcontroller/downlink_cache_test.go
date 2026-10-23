package mupcontroller

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/takehaya/vinbero/sdk/go/cplane"
)

func TestDownlinkMemoMatchesFreshBuildsThroughChanges(t *testing.T) {
	clients := []*recorder{{}, {}}
	controllers := make([]*Controller, 2)
	logs := make([][]string, 2)
	for i := range controllers {
		var err error
		controllers[i], err = New(inputConfig(`,"observe_only":false`), clients[i], func(_ cplane.LogLevel, message string) {
			logs[i] = append(logs[i], message)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	check := func(events []cplane.Event) {
		t.Helper()
		// The second controller is the reference that rebuilds every result.
		controllers[1].downCache = nil
		a, b := controllers[0].Update(events), controllers[1].Update(events)
		if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(clients[0].sets, clients[1].sets) || !reflect.DeepEqual(logs[0], logs[1]) {
			t.Fatalf("memo changed statuses or desired sets: %v / %v", a, b)
		}
	}
	initial := fixtures(t, 256)
	check(replay(initial))
	extra := route(t, bgp.NewMUPType1SessionTransformedRoute(bgp.NewRouteDistinguisherTwoOctetAS(65000, 7), netip.MustParsePrefix("10.0.0.0/32"), netip.MustParseAddr("0.0.1.0"), 9, netip.MustParseAddr("172.16.0.1"), nil))
	check([]cplane.Event{extra}) // Insert before the existing result.
	changed := fixtures(t, 512)[0]
	changed.Route.BGPPath.RouteKey = append([]byte(nil), initial[0].Route.BGPPath.RouteKey...)
	check([]cplane.Event{changed})
	extra.Route.Withdraw = true
	check([]cplane.Event{extra}) // Shift the remaining result back.
	reflected := changed
	reflected.Route.Peer = "192.0.2.253"
	check([]cplane.Event{reflected})
	reflected.Route.Withdraw = true
	check([]cplane.Event{reflected})
	bad := initial[1]
	bad.Route.BGPPath = &cplane.BGPPath{Codec: cplane.BGPPathCodec, AFI: 1, SAFI: 85,
		RouteKey: append([]byte(nil), initial[1].Route.BGPPath.RouteKey...), NLRI: []byte{33}}
	check([]cplane.Event{bad}) // A rejected discovery cannot reuse a prior output.
	if !controllers[0].engine.Status().Ready {
		t.Fatal("quarantined replacement invalidated the whole view")
	}
	check(initial[1:2])
	if last := clients[0].sets[len(clients[0].sets)-1]; len(last.Headends) != 1 {
		t.Fatal("discovery was not restored")
	}
	unsupported := route(t, bgp.NewMUPInterworkSegmentDiscoveryRoute(bgp.NewRouteDistinguisherTwoOctetAS(65000, 7), netip.MustParsePrefix("172.16.0.0/24")),
		bgp.NewPathAttributePrefixSID(bgp.NewSRv6ServiceTLV(bgp.TLVTypeSRv6L3Service, bgp.NewSRv6InformationSubTLV(netip.MustParseAddr("fd00:a:0:100::"), bgp.END_DT4))))
	check([]cplane.Event{unsupported})
	check(initial[2:3]) // Repeat builder failure on another revision, including its warning.
	check(initial[1:2])
	if last := clients[0].sets[len(clients[0].sets)-1]; len(last.Headends) != 1 {
		t.Fatal("no warm output before revocation")
	}
	revoked := changed
	revoked.Route.Contexts = nil
	check([]cplane.Event{revoked})
	if last := clients[0].sets[len(clients[0].sets)-1]; len(last.Headends) != 0 {
		t.Fatal("revocation retained a warm projection")
	}
	check([]cplane.Event{marker(cplane.EventStartOfReplay)})
	if controllers[0].downCache != nil {
		t.Fatal("partial replay retained projections")
	}
	check(initial)
	check([]cplane.Event{marker(cplane.EventEndOfReplay)})
	check(replay(nil))
	check(replay(initial))
	check([]cplane.Event{{Kind: cplane.EventRoute}})
	if controllers[0].downCache != nil {
		t.Fatal("incomplete view retained projections")
	}
	check(replay(nil))
}

type editingClient struct {
	sets               []cplane.Composition
	sids               []string
	contexts, prefixes []string
	fail               bool
}

func (c *editingClient) ApplyComposition(set cplane.Composition) error {
	c.sets = append(c.sets, set)
	c.sids = append(c.sids, set.Headends[0].Entry.Segments[0])
	c.contexts = append(c.contexts, set.Headends[0].Context)
	c.prefixes = append(c.prefixes, set.Headends[0].Entry.TriggerPrefix)
	set.Headends[0].Context = "edited"
	set.Headends[0].Entry.TriggerPrefix = "edited"
	set.Headends[0].Entry.Segments[0] = "edited"
	if c.fail {
		return errors.New("edited before failed apply")
	}
	return nil
}

func TestDownlinkMemoDoesNotBorrowClientOutputs(t *testing.T) {
	client := &editingClient{fail: true}
	c, err := New(inputConfig(`,"observe_only":false`), client, nil)
	if err != nil {
		t.Fatal(err)
	}
	events := fixtures(t, 256)
	c.Update(replay(events))
	c.Tick(1)
	if c.handledRevision != 0 {
		t.Fatal("failed apply advanced revision")
	}
	client.fail = false
	c.Tick(2)
	if c.handledRevision == 0 {
		t.Fatal("successful retry did not advance")
	}
	// Editing a retained earlier output must not affect a later cache hit.
	client.sets[0].Headends[0].Entry.Segments[0] = "edited again"
	c.Update(events[2:3]) // The downlink values are unchanged on a new revision.
	if len(client.sids) != 4 {
		t.Fatalf("applies: %d", len(client.sids))
	}
	for i, sid := range client.sids {
		if sid != "fd00:a:0:1ac:1000:124:0:100" || client.contexts[i] != "mobile" || client.prefixes[i] != "10.0.0.1/32" {
			t.Fatalf("client corrupted memo output %d: %q / %q / %q", i, sid, client.contexts[i], client.prefixes[i])
		}
	}
}
