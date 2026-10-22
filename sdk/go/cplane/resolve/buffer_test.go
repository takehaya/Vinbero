package resolve_test

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/resolve"
	"github.com/takehaya/vinbero/sdk/go/cplane/routes"
)

func TestResultsSnapshotSurvivesReplacementAndShrink(t *testing.T) {
	e, p := engine(t, routes.Limits{}, resolve.Limits{})
	a, b := vpn(t), vpn(t)
	b.Route.Peer = "192.0.2.5"
	right := underlay(t, "2001:db8::/32", "192.0.2.2", "2001:db8:ffff::1")
	e.Update(replay(a, b, right))
	saved := p.Results()
	if len(saved) != 2 {
		t.Fatal("initial two results missing")
	}
	before, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	check := func(want int) {
		t.Helper()
		if !e.Status().Ready || len(p.Results()) != want {
			t.Fatalf("want %d fresh results: status=%+v results=%+v", want, e.Status(), p.Results())
		}
		after, err := json.Marshal(saved)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("previous Results snapshot changed: %s, %v", after, err)
		}
	}
	right = underlay(t, "2001:db8::/32", "192.0.2.2", "2001:db8:ffff::2")
	e.Update([]cplane.Event{right})
	check(2)
	for _, pair := range p.Results() {
		if pair.Right.NextHop != netip.MustParseAddr("2001:db8:ffff::2") {
			t.Fatal("replacement retained the old right route")
		}
	}
	b.Route.Withdraw = true
	e.Update([]cplane.Event{b})
	check(1)
	a.Route.Withdraw = true
	e.Update([]cplane.Event{a})
	check(0)
	e.Update(nil)
	check(0)
	a.Route.Withdraw = false
	e.Update([]cplane.Event{a})
	check(1)
	e.Update(replay())
	check(0)
}
