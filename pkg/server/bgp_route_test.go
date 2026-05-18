package server

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
)

// fakeAdvertiser records RouteAdvertiser calls instead of touching gobgp.
type fakeAdvertiser struct {
	vpn       []bgp.VPNRoute
	unicast   []bgp.UnicastRoute
	withdrawn []bgp.RouteKey
	err       error
}

var _ bgp.RouteAdvertiser = (*fakeAdvertiser)(nil)

func (f *fakeAdvertiser) Advertise(_ context.Context, r bgp.VPNRoute) error {
	if f.err != nil {
		return f.err
	}
	f.vpn = append(f.vpn, r)
	return nil
}

func (f *fakeAdvertiser) AdvertiseUnicast(_ context.Context, r bgp.UnicastRoute) error {
	if f.err != nil {
		return f.err
	}
	f.unicast = append(f.unicast, r)
	return nil
}

func (f *fakeAdvertiser) Withdraw(_ context.Context, k bgp.RouteKey) error {
	if f.err != nil {
		return f.err
	}
	f.withdrawn = append(f.withdrawn, k)
	return nil
}

func TestBgpRoute_DisabledWithoutAdvertiser(t *testing.T) {
	s := NewBgpRouteServer(nil)
	_, err := s.BgpAdvertiseVpn(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseVpnRequest{}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("nil advertiser: got code %v, want FailedPrecondition", connect.CodeOf(err))
	}
}

func TestBgpRoute_AdvertiseVpn(t *testing.T) {
	fa := &fakeAdvertiser{}
	s := NewBgpRouteServer(fa)
	resp, err := s.BgpAdvertiseVpn(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseVpnRequest{Routes: []*v1.BgpVpnRoute{{
			Family:       "vpnv4",
			Prefix:       "10.0.0.0/24",
			Rd:           "65000:100",
			RouteTargets: []string{"65000:100"},
			Srv6Sid:      "fd00:1:1:a::",
			NextHop:      "2001:db8::1",
		}}}))
	if err != nil {
		t.Fatalf("BgpAdvertiseVpn: %v", err)
	}
	if len(resp.Msg.Advertised) != 1 || len(fa.vpn) != 1 {
		t.Fatalf("advertised=%d fake.vpn=%d, want 1/1", len(resp.Msg.Advertised), len(fa.vpn))
	}
	if fa.vpn[0].Family != bgp.FamilyVPNv4 || fa.vpn[0].SRv6SID != "fd00:1:1:a::" {
		t.Errorf("forwarded VPNRoute = %+v", fa.vpn[0])
	}
}

func TestBgpRoute_AdvertiseVpn_BadFamilyIsPerItemError(t *testing.T) {
	fa := &fakeAdvertiser{}
	s := NewBgpRouteServer(fa)
	resp, err := s.BgpAdvertiseVpn(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseVpnRequest{Routes: []*v1.BgpVpnRoute{{
			Family: "bogus", Prefix: "10.0.0.0/24",
		}}}))
	if err != nil {
		t.Fatalf("BgpAdvertiseVpn: %v", err)
	}
	if len(resp.Msg.Errors) != 1 {
		t.Errorf("an unknown family must produce one per-item error, got %d", len(resp.Msg.Errors))
	}
	if len(fa.vpn) != 0 {
		t.Errorf("a rejected route must not reach the advertiser")
	}
}

func TestBgpRoute_AdvertiseUnicast(t *testing.T) {
	fa := &fakeAdvertiser{}
	s := NewBgpRouteServer(fa)
	if _, err := s.BgpAdvertiseUnicast(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseUnicastRequest{Routes: []*v1.BgpUnicastRoute{{
			Prefix: "2001:db8:dead::/64", NextHop: "fd00:f1b::2",
		}}})); err != nil {
		t.Fatalf("BgpAdvertiseUnicast: %v", err)
	}
	if len(fa.unicast) != 1 || fa.unicast[0].Prefix != "2001:db8:dead::/64" {
		t.Errorf("forwarded UnicastRoute = %+v", fa.unicast)
	}
}

func TestBgpRoute_Withdraw(t *testing.T) {
	fa := &fakeAdvertiser{}
	s := NewBgpRouteServer(fa)
	resp, err := s.BgpWithdraw(context.Background(),
		connect.NewRequest(&v1.BgpWithdrawRequest{Keys: []*v1.BgpRouteKey{{
			Family: "vpnv4", Prefix: "10.0.0.0/24", Rd: "65000:100",
		}}}))
	if err != nil {
		t.Fatalf("BgpWithdraw: %v", err)
	}
	if len(resp.Msg.Withdrawn) != 1 || len(fa.withdrawn) != 1 {
		t.Errorf("withdrawn=%d fake=%d, want 1/1", len(resp.Msg.Withdrawn), len(fa.withdrawn))
	}
	if fa.withdrawn[0].Family != bgp.FamilyVPNv4 {
		t.Errorf("forwarded RouteKey = %+v", fa.withdrawn[0])
	}
}

func TestBgpRoute_AdvertiserErrorIsPerItem(t *testing.T) {
	fa := &fakeAdvertiser{err: errors.New("gobgp boom")}
	s := NewBgpRouteServer(fa)
	resp, err := s.BgpAdvertiseVpn(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseVpnRequest{Routes: []*v1.BgpVpnRoute{{
			Family: "vpnv4", Prefix: "10.0.0.0/24", Rd: "65000:1", Srv6Sid: "fd00::1", NextHop: "2001:db8::1",
		}}}))
	if err != nil {
		t.Fatalf("BgpAdvertiseVpn returned a top-level error, want per-item: %v", err)
	}
	if len(resp.Msg.Errors) != 1 {
		t.Errorf("advertiser failure must surface as a per-item error, got %d", len(resp.Msg.Errors))
	}
}
