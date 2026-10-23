package routes_test

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/gobgppath"
	"github.com/takehaya/vinbero/sdk/go/cplane/routes"
)

func newView(t *testing.T) *routes.View {
	t.Helper()
	v, err := routes.NewView(cplane.InputConfig{
		Version: 1, Codec: cplane.BGPPathCodec,
		Contexts: []cplane.InputContext{
			{Name: "tenant", Families: []string{"ipv4_unicast", "ipv6_unicast"}},
			{Name: "other", Families: []string{"ipv4_unicast", "ipv6_unicast"}},
		},
	}, routes.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func route(t *testing.T, prefix, peer string, pathID, preference uint32) cplane.Event {
	t.Helper()
	p := netip.MustParsePrefix(prefix)
	n, err := bgp.NewIPAddrPrefix(p)
	if err != nil {
		t.Fatal(err)
	}
	family, name := bgp.RF_IPv4_UC, "ipv4_unicast"
	if p.Addr().Is6() {
		family, name = bgp.RF_IPv6_UC, "ipv6_unicast"
	}
	encoded, err := gobgppath.Encode(family, n, []bgp.PathAttributeInterface{bgp.NewPathAttributeLocalPref(preference)})
	if err != nil {
		t.Fatal(err)
	}
	encoded.RouteKey = []byte(prefix)
	return cplane.Event{Kind: cplane.EventRoute, Route: cplane.Route{
		Family: name, Peer: peer, PathID: pathID, Contexts: []string{"tenant"}, BGPPath: encoded,
	}}
}

func marker(kind cplane.EventKind) cplane.Event {
	return cplane.Event{Kind: kind, ReplaySource: cplane.BGPSource}
}

func update(t *testing.T, v *routes.View, events ...cplane.Event) {
	t.Helper()
	if results := v.Update(events); len(results) != 0 {
		t.Fatalf("unexpected event results: %+v", results)
	}
}

func replay(t *testing.T, v *routes.View, events ...cplane.Event) {
	t.Helper()
	update(t, v, marker(cplane.EventStartOfReplay))
	update(t, v, events...)
	update(t, v, marker(cplane.EventEndOfReplay))
	if !v.Status().Ready {
		t.Fatalf("replay not ready: %+v", v.Status())
	}
}

func entries(v *routes.View) []routes.Entry {
	var out []routes.Entry
	v.Range(func(e routes.Entry) { out = append(out, e) })
	return out
}

func assertOrder(t *testing.T, v *routes.View, want ...cplane.Event) []routes.Entry {
	t.Helper()
	got := entries(v)
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for i, event := range want {
		key, ok := event.Route.BGPKey()
		if !ok || got[i].Key != key {
			t.Fatalf("entry %d key = %+v, want %+v", i, got[i].Key, key)
		}
	}
	return got
}

func TestRangeTracksOrderedChangesAndCurrentEntries(t *testing.T) {
	v := newView(t)
	a := route(t, "10.0.1.0/24", "192.0.2.1", 1, 100)
	b := route(t, "10.0.1.0/24", "192.0.2.1", 2, 100)
	c := route(t, "10.0.1.0/24", "192.0.2.2", 1, 100)
	d := route(t, "10.0.2.0/24", "192.0.2.1", 1, 100)
	e := route(t, "2001:db8::/64", "192.0.2.1", 1, 100)
	replay(t, v, e, c, b, d, a)
	assertOrder(t, v, a, b, c, d, e)
	assertOrder(t, v, a, b, c, d, e)

	first := route(t, "10.0.0.0/24", "192.0.2.1", 1, 100)
	update(t, v, first)
	assertOrder(t, v, first, a, b, c, d, e)
	withdrawal := c
	withdrawal.Route.Withdraw = true
	update(t, v, withdrawal)
	assertOrder(t, v, first, a, b, d, e)
	update(t, v, c)
	assertOrder(t, v, first, a, b, c, d, e)

	replacement := route(t, "10.0.1.0/24", "192.0.2.1", 2, 200)
	replacement.Route.Contexts = []string{"other"}
	update(t, v, replacement)
	got := assertOrder(t, v, first, a, replacement, c, d, e)
	if !reflect.DeepEqual(got[2].Contexts, []string{"other"}) {
		t.Fatalf("replacement contexts are stale: %v", got[2].Contexts)
	}
	if attrs := got[2].Path.Attributes; len(attrs) != 1 {
		t.Fatalf("replacement attributes: %+v", attrs)
	} else if preference, ok := attrs[0].(*bgp.PathAttributeLocalPref); !ok || preference.Value != 200 {
		t.Fatalf("replacement preference is stale: %+v", attrs[0])
	}
}

func TestRangeDoesNotRetainRejectedReplacement(t *testing.T) {
	for _, reason := range []string{"malformed-nlri", "encoding-error", "lost-context"} {
		t.Run(reason, func(t *testing.T) {
			v := newView(t)
			a := route(t, "10.0.0.0/24", "192.0.2.1", 1, 100)
			b := route(t, "10.0.1.0/24", "192.0.2.1", 1, 100)
			replay(t, v, a, b)
			assertOrder(t, v, a, b)
			replacement := route(t, "10.0.0.0/24", "192.0.2.1", 1, 200)
			switch reason {
			case "malformed-nlri":
				replacement.Route.BGPPath.NLRI = []byte{33}
			case "encoding-error":
				replacement.Route.BGPPath.EncodingError = "cannot encode replacement"
			case "lost-context":
				replacement.Route.Contexts = nil
			}
			results := v.Update([]cplane.Event{replacement})
			if reason == "lost-context" {
				if len(results) != 0 {
					t.Fatal(results)
				}
			} else if len(results) != 1 || results[0].Disposition != cplane.Quarantine {
				t.Fatalf("expected quarantine, got %+v", results)
			}
			if !v.Status().Ready || v.Len() != 1 {
				t.Fatalf("invalid post-replacement view: %+v, size %d", v.Status(), v.Len())
			}
			assertOrder(t, v, b)
			update(t, v, a)
			assertOrder(t, v, a, b)
		})
	}
}

func TestRangeHidesIncompleteViewUntilFreshReplay(t *testing.T) {
	v := newView(t)
	a := route(t, "10.0.0.0/24", "192.0.2.1", 1, 100)
	b := route(t, "10.0.1.0/24", "192.0.2.1", 1, 100)
	assertOrder(t, v)
	replay(t, v, a)
	assertOrder(t, v, a)
	v.Invalidate(42, "input lost")
	assertOrder(t, v)
	update(t, v, b, marker(cplane.EventEndOfReplay))
	assertOrder(t, v)
	if v.Status().Ready {
		t.Fatal("ordinary update or end marker recovered incomplete view")
	}
	update(t, v, marker(cplane.EventStartOfReplay), b)
	assertOrder(t, v)
	update(t, v, marker(cplane.EventEndOfReplay))
	assertOrder(t, v, b)

	update(t, v, marker(cplane.EventStartOfReplay), a)
	results := v.Update([]cplane.Event{{Kind: cplane.EventRoute}})
	if len(results) != 1 || results[0].Disposition != cplane.InputIncomplete {
		t.Fatalf("missing identity did not invalidate replay: %+v", results)
	}
	update(t, v, marker(cplane.EventEndOfReplay))
	assertOrder(t, v)
	if v.Status().Ready {
		t.Fatal("incomplete replay became ready")
	}
	replay(t, v, b, a)
	assertOrder(t, v, a, b)
	replay(t, v)
	assertOrder(t, v)
	if v.Len() != 0 {
		t.Fatal("empty replay retained old paths")
	}
}

func TestRangeContextsAreIndependentCopies(t *testing.T) {
	v := newView(t)
	a := route(t, "10.0.0.0/24", "192.0.2.1", 1, 100)
	a.Route.Contexts = []string{"tenant", "other"}
	replay(t, v, a)
	first := assertOrder(t, v, a)
	first[0].Contexts[0] = "changed"
	second := assertOrder(t, v, a)
	if !reflect.DeepEqual(second[0].Contexts, []string{"other", "tenant"}) {
		t.Fatalf("traversal exposed stored contexts: %v", second[0].Contexts)
	}
	second[0].Contexts[1] = "also-changed"
	if first[0].Contexts[1] != "tenant" {
		t.Fatal("separate traversals share contexts")
	}
}

func TestRangeReplacementPreservesPreviouslyVisitedEntries(t *testing.T) {
	v := newView(t)
	a := route(t, "10.0.0.0/24", "192.0.2.1", 1, 100)
	b := route(t, "10.0.1.0/24", "192.0.2.2", 2, 200)
	replay(t, v, b, a)
	before := assertOrder(t, v, a, b)
	replacement := route(t, "10.0.0.0/24", "192.0.2.1", 1, 300)
	replacement.Route.Contexts = []string{"other"}
	update(t, v, replacement)
	after := assertOrder(t, v, replacement, b)
	if !reflect.DeepEqual(after[1], before[1]) {
		t.Fatal("replacement changed an unrelated entry")
	}
	if before[0].Path.Attributes[0].(*bgp.PathAttributeLocalPref).Value != 100 ||
		!reflect.DeepEqual(before[0].Contexts, []string{"tenant"}) {
		t.Fatal("replacement changed a previously visited entry")
	}
	if after[0].Path.Attributes[0].(*bgp.PathAttributeLocalPref).Value != 300 ||
		!reflect.DeepEqual(after[0].Contexts, []string{"other"}) {
		t.Fatal("replacement retained stale attributes or membership")
	}
	after[0].Contexts[0] = "changed"
	if got := assertOrder(t, v, replacement, b); got[0].Contexts[0] != "other" {
		t.Fatal("callback changed stored membership")
	}
	// Removing and restoring the same key in one batch must use its new value.
	for _, reject := range []bool{false, true} {
		removed := a
		if reject {
			removed.Route.BGPPath.NLRI = []byte{33}
		} else {
			removed.Route.Withdraw = true
		}
		results := v.Update([]cplane.Event{removed, replacement})
		if reject && (len(results) != 1 || results[0].Disposition != cplane.Quarantine) {
			t.Fatalf("rejected replacement: %+v", results)
		}
		if !reject && len(results) != 0 {
			t.Fatal(results)
		}
		got := assertOrder(t, v, replacement, b)
		if got[0].Path.Attributes[0].(*bgp.PathAttributeLocalPref).Value != 300 {
			t.Fatal("restored key has stale attributes")
		}
	}
}

func TestReplacementOrderingAfterOtherChangesInSameBatch(t *testing.T) {
	for _, change := range []string{"insert", "withdraw", "reject", "replace"} {
		t.Run(change, func(t *testing.T) {
			v := newView(t)
			a := route(t, "10.0.0.0/24", "192.0.2.1", 1, 100)
			b := route(t, "10.0.1.0/24", "192.0.2.1", 1, 100)
			c := route(t, "10.0.2.0/24", "192.0.2.1", 1, 100)
			replay(t, v, b, a)
			assertOrder(t, v, a, b)
			replacement := route(t, "10.0.1.0/24", "192.0.2.1", 1, 300)
			first, want := c, []cplane.Event{a, replacement, c}
			switch change {
			case "withdraw":
				first = a
				first.Route.Withdraw = true
				want = []cplane.Event{replacement}
			case "reject":
				first = route(t, "10.0.0.0/24", "192.0.2.1", 1, 200)
				first.Route.BGPPath.NLRI = []byte{33}
				want = []cplane.Event{replacement}
			case "replace":
				first = route(t, "10.0.0.0/24", "192.0.2.1", 1, 200)
				want = []cplane.Event{first, replacement}
			}
			results := v.Update([]cplane.Event{first, replacement})
			if change == "reject" {
				if len(results) != 1 || results[0].Disposition != cplane.Quarantine {
					t.Fatalf("quarantine = %+v", results)
				}
			} else if len(results) != 0 {
				t.Fatal(results)
			}
			got := assertOrder(t, v, want...)
			for _, entry := range got {
				key, _ := replacement.Route.BGPKey()
				if entry.Key == key && entry.Path.Attributes[0].(*bgp.PathAttributeLocalPref).Value != 300 {
					t.Fatal("successful replacement retained old value")
				}
			}
			// A later full replay must replace the whole key set, including any
			// ordering retained by a successful replacement in this batch.
			replay(t, v, c)
			assertOrder(t, v, c)
		})
	}
}

func TestReplacementAtPathLimitAndOversizedReplacement(t *testing.T) {
	v, err := routes.NewView(cplane.InputConfig{Version: 1, Codec: cplane.BGPPathCodec,
		Contexts: []cplane.InputContext{{Name: "tenant", Families: []string{"ipv4_unicast"}}}},
		routes.Limits{MaxPaths: 1, MaxBytes: 512})
	if err != nil {
		t.Fatal(err)
	}
	a := route(t, "10.0.0.0/24", "192.0.2.1", 1, 100)
	replay(t, v, a)
	assertOrder(t, v, a)
	replacement := route(t, "10.0.0.0/24", "192.0.2.1", 1, 200)
	update(t, v, replacement)
	assertOrder(t, v, replacement)
	// Duplicate decodable attributes consume the input byte budget.
	for len(replacement.Route.BGPPath.Attributes) < 32 {
		replacement.Route.BGPPath.Attributes = append(replacement.Route.BGPPath.Attributes, replacement.Route.BGPPath.Attributes[0])
	}
	results := v.Update([]cplane.Event{replacement})
	if len(results) != 1 || results[0].Disposition != cplane.InputIncomplete || v.Status().Ready || v.Len() != 0 {
		t.Fatalf("oversized replacement retained a usable path: %+v %+v len=%d", results, v.Status(), v.Len())
	}
	assertOrder(t, v)
	replay(t, v, a)
	assertOrder(t, v, a)
}
