package export

import (
	"net/netip"
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// An auto-advertised VPN route carries the SID Structure of the binding's
// locator: a classic locator's own layout, and 32/16/16/0 for a uSID
// locator, which is what marks the SID as NEXT-C-SID for the peer.
func TestOnRouteFillsSIDStructure(t *testing.T) {
	t.Run("classic locator", func(t *testing.T) {
		e, adv, _ := newTestExporter(t)
		if _, err := e.EnableVRF(testBinding()); err != nil {
			t.Fatalf("EnableVRF: %v", err)
		}
		e.OnRoute(testTable, netip.MustParsePrefix("10.0.0.0/24"), true)
		if len(adv.advertised) == 0 {
			t.Fatal("nothing advertised")
		}
		// ArgumentLen is 0 even though the classic locator reserves argument
		// space: End.DT4/DT6 behaviors take no argument (RFC 9252 §3.2.1.1).
		want := bgp.SIDStructure{LocatorBlockLen: 32, LocatorNodeLen: 16, FunctionLen: 16}
		if got := adv.advertised[0].SIDStructure; got != want {
			t.Errorf("structure = %+v, want %+v", got, want)
		}
	})

	t.Run("uSID locator", func(t *testing.T) {
		locs := locator.NewManager()
		if err := locs.Add(&locator.Locator{
			Name:              "LOCU",
			Prefix:            netip.MustParsePrefix("fd00:aaaa:b002::/48"),
			BlockLen:          32,
			NodeLen:           16,
			FunctionLen:       16,
			ArgumentLen:       0,
			Behavior:          locator.BehaviorUSID,
			FunctionAutoStart: 0x10,
			FunctionAutoEnd:   0xfffe,
		}); err != nil {
			t.Fatalf("add locator: %v", err)
		}
		adv := &fakeAdvertiser{}
		e := New(adv, &fakeSidOps{}, locs, vrfbgp.NewManager(),
			fakeResolver{ifindex: 10, table: testTable}, "2001:db8:ff::1", UnderlayConfig{}, zap.NewNop())
		b := testBinding()
		b.DefaultLocator = "LOCU"
		if _, err := e.EnableVRF(b); err != nil {
			t.Fatalf("EnableVRF: %v", err)
		}
		e.OnRoute(testTable, netip.MustParsePrefix("10.0.0.0/24"), true)
		if len(adv.advertised) == 0 {
			t.Fatal("nothing advertised")
		}
		got := adv.advertised[0].SIDStructure
		want := bgp.SIDStructure{LocatorBlockLen: 32, LocatorNodeLen: 16, FunctionLen: 16, ArgumentLen: 0}
		if got != want {
			t.Errorf("structure = %+v, want %+v", got, want)
		}
		if !got.IsUSID() {
			t.Errorf("uSID locator's structure must classify as uSID")
		}
	})
}
