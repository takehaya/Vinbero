package evpncontroller

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/gobgppath"
)

type recorder struct {
	sets []cplane.Composition
	fail bool
}

func (r *recorder) ApplyComposition(set cplane.Composition) error {
	r.sets = append(r.sets, set)
	if r.fail {
		return errors.New("injected failure")
	}
	return nil
}
func config() cplane.InputConfig {
	return cplane.InputConfig{Version: 1, Codec: cplane.BGPPathCodec, Payload: []byte(`{"context":"l2","source":"fd00:feed::1","observe_only":false}`), Contexts: []cplane.InputContext{{Name: "l2", Families: []string{"evpn"}}, {Name: "other", Families: []string{"evpn"}}}}
}
func fixture(t *testing.T, imet bool, rdNumber uint32, remote, sid string, tag uint32) cplane.Event {
	t.Helper()
	rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, rdNumber)
	var n *bgp.EVPNNLRI
	var err error
	behavior := bgp.END_DT2U
	if imet {
		n, err = bgp.NewEVPNMulticastEthernetTagRoute(rd, tag, netip.MustParseAddr("192.0.2.1"))
		behavior = bgp.END_DT2M
	} else {
		n, err = bgp.NewEVPNMacIPAdvertisementRoute(rd, bgp.EthernetSegmentIdentifier{}, tag, "02:00:00:00:00:01", netip.Addr{}, []uint32{0})
	}
	if err != nil {
		t.Fatal(err)
	}
	mp, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_EVPN, []bgp.PathNLRI{{NLRI: n}}, netip.MustParseAddr(remote))
	if err != nil {
		t.Fatal(err)
	}
	prefixSID := bgp.NewPathAttributePrefixSID(bgp.NewSRv6ServiceTLV(bgp.TLVTypeSRv6L2Service, bgp.NewSRv6InformationSubTLV(netip.MustParseAddr(sid), behavior)))
	path, err := gobgppath.Encode(bgp.RF_EVPN, n, []bgp.PathAttributeInterface{mp, prefixSID})
	if err != nil {
		t.Fatal(err)
	}
	path.RouteKey = []byte(n.String())
	return cplane.Event{Kind: cplane.EventRoute, Route: cplane.Route{Family: "evpn", Peer: "192.0.2.254", Contexts: []string{"l2"}, BGPPath: path}}
}
func fixtures(t *testing.T) []cplane.Event {
	return []cplane.Event{fixture(t, false, 7, "2001:db8::1", "fd00:2::1", 0), fixture(t, true, 8, "2001:db8::1", "fd00:3::1", 0)}
}
func marker(k cplane.EventKind) cplane.Event {
	return cplane.Event{Kind: k, ReplaySource: cplane.BGPSource}
}
func replay(events ...cplane.Event) []cplane.Event {
	return append(append([]cplane.Event{marker(cplane.EventStartOfReplay)}, events...), marker(cplane.EventEndOfReplay))
}
func latest(t *testing.T, r *recorder, n int) cplane.Composition {
	t.Helper()
	if len(r.sets) == 0 {
		t.Fatal("no desired set")
	}
	set := r.sets[len(r.sets)-1]
	if len(set.EVPN) != n || len(set.Headends)+len(set.Uplinks)+len(set.Advertisements) != 0 {
		t.Fatalf("unexpected set: %+v", set)
	}
	return set
}
func newController(t *testing.T, r *recorder) *Controller {
	t.Helper()
	c, err := New(config(), r, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestPolicyLifecycle(t *testing.T) {
	r := &recorder{}
	c := newController(t, r)
	events := fixtures(t)
	c.Update(replay(events[0]))
	latest(t, r, 0)
	c.Update(events[1:])
	got := latest(t, r, 1)
	want := cplane.EVPNForward{Context: "l2", MAC: "02:00:00:00:00:01", Segments: []string{"fd00:2::1"}, SrcAddr: "fd00:feed::1", RemoteSrc: "2001:db8::1"}
	if !reflect.DeepEqual(got.EVPN[0], want) {
		t.Fatalf("got %+v want %+v", got.EVPN[0], want)
	}
	duplicate := events[1]
	duplicate.Route.Peer = "192.0.2.253"
	c.Update([]cplane.Event{duplicate})
	latest(t, r, 1)
	duplicate.Route.Withdraw = true
	c.Update([]cplane.Event{duplicate})
	latest(t, r, 1)
	events[1].Route.Withdraw = true
	c.Update(events[1:])
	latest(t, r, 0)
	events[1].Route.Withdraw = false
	c.Update(events[1:])
	latest(t, r, 1)
	events[0].Route.Contexts = nil
	c.Update(events[:1])
	latest(t, r, 0)
	c.Update(replay(fixtures(t)...))
	latest(t, r, 1)
	count := len(r.sets)
	c.Update([]cplane.Event{marker(cplane.EventStartOfReplay)})
	c.Tick(1)
	if len(r.sets) != count {
		t.Fatal("wrote during replay")
	}
	c.Update([]cplane.Event{marker(cplane.EventEndOfReplay)})
	latest(t, r, 0)
}
func TestPolicyRefusesMismatchesAndAmbiguity(t *testing.T) {
	for name, change := range map[string]func([]cplane.Event) []cplane.Event{
		"IMET only":     func(e []cplane.Event) []cplane.Event { return e[1:] },
		"other context": func(e []cplane.Event) []cplane.Event { e[1].Route.Contexts = []string{"other"}; return e },
		"other peer": func(e []cplane.Event) []cplane.Event {
			e[1] = fixture(t, true, 8, "2001:db8::2", "fd00:3::1", 0)
			return e
		},
		"other tag": func(e []cplane.Event) []cplane.Event {
			e[1] = fixture(t, true, 8, "2001:db8::1", "fd00:3::1", 1)
			return e
		},
		"invalid peer": func(e []cplane.Event) []cplane.Event { e[1] = fixture(t, true, 8, "fe80::1", "fd00:3::1", 0); return e },
		"invalid IMET SID": func(e []cplane.Event) []cplane.Event {
			e[1] = fixture(t, true, 8, "2001:db8::1", "ff00::1", 0)
			return e
		},
		"ambiguous IMET": func(e []cplane.Event) []cplane.Event {
			return append(e, fixture(t, true, 9, "2001:db8::1", "fd00:3::2", 0))
		},
		"MAC collision": func(e []cplane.Event) []cplane.Event {
			return append(e, fixture(t, false, 9, "2001:db8::1", "fd00:2::2", 0))
		},
		"malformed replacement": func(e []cplane.Event) []cplane.Event {
			bad := e[1]
			p := *bad.Route.BGPPath
			p.NLRI = []byte{0xff}
			bad.Route.BGPPath = &p
			return append(e, bad)
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := &recorder{}
			c := newController(t, r)
			c.Update(replay(change(fixtures(t))...))
			latest(t, r, 0)
		})
	}
}
func TestRetryOwnsOutputsAndUsesLatestView(t *testing.T) {
	r := &recorder{fail: true}
	c := newController(t, r)
	c.Update(replay(fixtures(t)...))
	original := latest(t, r, 1)
	r.sets[0].EVPN[0].Segments[0] = "fd00:bad::1"
	r.sets[0].EVPN[0].MAC = "02:00:00:00:ff:ff"
	c.Tick(1)
	retried := latest(t, r, 1)
	if retried.Revision != original.Revision || retried.EVPN[0].Segments[0] != "fd00:2::1" || retried.EVPN[0].MAC != "02:00:00:00:00:01" {
		t.Fatal("retry borrowed client output")
	}
	changed := fixture(t, false, 7, "2001:db8::1", "fd00:2::9", 0)
	c.Update([]cplane.Event{changed})
	latest(t, r, 1)
	r.fail = false
	c.Tick(2)
	last := latest(t, r, 1)
	if last.Revision <= original.Revision || last.EVPN[0].Segments[0] != "fd00:2::9" {
		t.Fatal("retry did not use latest revision")
	}
	count := len(r.sets)
	c.Tick(3)
	if len(r.sets) != count {
		t.Fatal("successful revision retried")
	}
}
func TestObserveAndConfigAdmission(t *testing.T) {
	cfg := config()
	cfg.Payload = []byte(`{"context":"l2","source":"fd00:feed::1"}`)
	r := &recorder{}
	c, err := New(cfg, r, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Update(replay(fixtures(t)...))
	if len(r.sets) != 0 {
		t.Fatal("default observation wrote")
	}
	for _, payload := range []string{`{}`, `{"context":"unknown","source":"fd00:feed::1"}`, `{"context":"l2","source":"fe80::1"}`, `{"context":"l2","source":"fd00:feed::1","extra":1}`, `{"context":"l2","source":"fd00:feed::1"} {}`} {
		cfg.Payload = []byte(payload)
		if _, err := New(cfg, r, nil); err == nil {
			t.Fatalf("accepted %s", payload)
		}
	}
	if _, err := New(config(), nil, nil); err == nil {
		t.Fatal("accepted writing without client")
	}
}

func TestIncompleteInputSuspendsFailedRetry(t *testing.T) {
	r := &recorder{fail: true}
	c := newController(t, r)
	c.Update(replay(fixtures(t)...))
	latest(t, r, 1)
	count := len(r.sets)
	results := c.Update([]cplane.Event{{Kind: cplane.EventRoute, Sequence: 91}})
	if len(results) != 1 || results[0].Disposition != cplane.InputIncomplete {
		t.Fatalf("not incomplete: %+v", results)
	}
	c.Tick(1)
	c.Update(fixtures(t))
	if len(r.sets) != count {
		t.Fatal("retried an incomplete view")
	}
	r.fail = false
	c.Update(replay(fixtures(t)...))
	latest(t, r, 1)
	if len(r.sets) != count+1 {
		t.Fatal("fresh replay did not recover")
	}
}
func TestBadIMETBehaviorAndStickyCollisionOrder(t *testing.T) {
	events := fixtures(t)
	attr := bgp.NewPathAttributePrefixSID(bgp.NewSRv6ServiceTLV(bgp.TLVTypeSRv6L2Service, bgp.NewSRv6InformationSubTLV(netip.MustParseAddr("fd00:3::1"), bgp.END_DT2U)))
	raw, err := attr.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	events[1].Route.BGPPath.Attributes[1] = raw
	r := &recorder{}
	newController(t, r).Update(replay(events...))
	latest(t, r, 0)
	a := fixture(t, false, 7, "2001:db8::1", "fd00:2::1", 0)
	b := fixture(t, false, 9, "2001:db8::1", "fd00:2::2", 0)
	again := fixture(t, false, 10, "2001:db8::1", "fd00:2::1", 0)
	for _, order := range [][]cplane.Event{{a, b, again}, {again, b, a}, {b, again, a}} {
		r := &recorder{}
		c := newController(t, r)
		c.Update(replay(append(order, fixtures(t)[1])...))
		latest(t, r, 0)
		// Removing the conflicting claimant must recover one coalesced MAC.
		withdraw := b
		withdraw.Route.Withdraw = true
		c.Update([]cplane.Event{withdraw})
		latest(t, r, 1)
	}
}
