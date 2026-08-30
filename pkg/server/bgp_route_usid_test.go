package server

import (
	"context"
	"net/netip"
	"testing"

	"connectrpc.com/connect"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/locator"
)

// The operator-explicit advertise path derives the SID Structure from the
// containing locator but always advertises ArgumentLen 0: End.DT4/DT6 take
// no argument, so the locator's argument space (layout) must not leak into
// the behavior's structure (RFC 9252 Sec.3.2.1.1).
func TestBgpAdvertiseVpn_SIDStructureArgumentZeroed(t *testing.T) {
	locs := locator.NewManager()
	if err := locs.Add(&locator.Locator{
		Name:              "LOCC",
		Prefix:            netip.MustParsePrefix("fd00:cccc::/48"),
		BlockLen:          32,
		NodeLen:           16,
		FunctionLen:       16,
		ArgumentLen:       64,
		Behavior:          locator.BehaviorClassic,
		FunctionAutoStart: 0x10,
		FunctionAutoEnd:   0xfffe,
	}); err != nil {
		t.Fatalf("add locator: %v", err)
	}
	fa := &fakeAdvertiser{}
	s := NewBgpRouteServer(fa, nil, nil, nil, nil, locs)
	resp, err := s.BgpAdvertiseVpn(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseVpnRequest{Routes: []*v1.BgpVpnRoute{{
			Family: "vpnv4", Prefix: "10.40.0.0/24", Rd: "65000:40",
			RouteTargets: []string{"65000:40"},
			Srv6Sid:      "fd00:cccc:0:1::", NextHop: "2001:db8::1",
		}}}))
	if err != nil {
		t.Fatalf("BgpAdvertiseVpn: %v", err)
	}
	if len(resp.Msg.Advertised) != 1 || len(fa.vpn) != 1 {
		t.Fatalf("advertised=%d fake.vpn=%d, want 1/1", len(resp.Msg.Advertised), len(fa.vpn))
	}
	want := bgp.SIDStructure{LocatorBlockLen: 32, LocatorNodeLen: 16, FunctionLen: 16}
	if got := fa.vpn[0].SIDStructure; got != want {
		t.Errorf("structure = %+v, want %+v (ArgumentLen zeroed)", got, want)
	}
}
