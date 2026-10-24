package apply

import (
	"net/netip"
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/demux"
)

type identityRouteSource struct{ handler bgp.RouteHandler }

func (s *identityRouteSource) Subscribe(_ bgp.Family, h bgp.RouteHandler) (func(), error) {
	s.handler = h
	return func() {}, nil
}

func TestDemuxSRPolicyWithdrawalPreservesOtherNLRI(t *testing.T) {
	tbl, fm := newTestTable()
	src := &identityRouteSource{}
	d := demux.New(src, nil, nil)
	_, err := d.RegisterBuiltin("applier", nil, func(ev bgp.RouteEvent) { tbl.apply(*ev.SRPolicy, ev.IsWithdraw) })
	if err != nil {
		t.Fatal(err)
	}
	if err = d.Start(); err != nil {
		t.Fatal(err)
	}
	first := policy(100, "2001:db8::2", bgpCand(1, 200, "fd00:1::"))
	second := policy(100, "2001:db8::2", bgpCand(2, 100, "fd00:2::"))
	ev := bgp.RouteEvent{Family: bgp.FamilySRPolicyIPv6, Source: bgp.PathSource{Peer: netip.MustParseAddr("192.0.2.1")}, SRPolicy: &first}
	src.handler(ev)
	ev.SRPolicy = &second
	src.handler(ev)
	id := tbl.idOf(100, first.Endpoint)
	if got := fm.current[id]; len(got) != 1 || got[0] != netip.MustParseAddr("fd00:1::") {
		t.Fatalf("initial selected path: %v", got)
	}
	ev.SRPolicy = &first
	ev.IsWithdraw = true
	src.handler(ev)
	if got := fm.current[id]; len(got) != 1 || got[0] != netip.MustParseAddr("fd00:2::") {
		t.Fatalf("withdraw candidate 1 should promote live candidate 2; actual installed transport = %v", got)
	}
}

func TestDemuxMUPWithdrawalPreservesOtherNLRI(t *testing.T) {
	fh := newFakeHeadend()
	a := newMUPApplier(t, fh)
	src := &identityRouteSource{}
	d := demux.New(src, nil, nil)
	if _, err := d.RegisterBuiltin("applier", nil, a.Apply); err != nil {
		t.Fatal(err)
	}
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	first := bgp.MUPRoute{Type: bgp.MUPRouteTypeT2ST, RD: "65000:100", Endpoint: "192.0.2.100", TEID: 100, TEIDLen: 32, SRv6SID: "fd00:3:3:c::"}
	second := first
	second.Endpoint = "192.0.2.101"
	ev := bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, Source: bgp.PathSource{Peer: netip.MustParseAddr("192.0.2.1")}, MUP: &first}
	src.handler(ev)
	ev.MUP = &second
	src.handler(ev)
	if len(fh.mupUplink) != 2 {
		t.Fatalf("initial uplink entries = %v", fh.mupUplink)
	}
	ev.MUP = &first
	ev.IsWithdraw = true
	src.handler(ev)
	if _, ok := fh.mupUplink[mupUplinkKey{0, second.Endpoint, 100, 32}]; !ok {
		t.Errorf("live endpoint %s was incorrectly deleted", second.Endpoint)
	}
	if _, ok := fh.mupUplink[mupUplinkKey{0, first.Endpoint, 100, 32}]; ok {
		t.Errorf("withdrawn endpoint %s incorrectly remains", first.Endpoint)
	}
}
