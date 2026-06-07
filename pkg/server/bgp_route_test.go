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

// fakeSRPolicyAdv records SRPolicyController calls instead of touching gobgp.
type fakeSRPolicyAdv struct {
	pushed    []bgp.SRPolicy
	withdrawn []bgp.SRPolicyKey
	err       error
}

var _ bgp.SRPolicyController = (*fakeSRPolicyAdv)(nil)

func (f *fakeSRPolicyAdv) PushPolicy(_ context.Context, p bgp.SRPolicy) error {
	if f.err != nil {
		return f.err
	}
	f.pushed = append(f.pushed, p)
	return nil
}

func (f *fakeSRPolicyAdv) WithdrawPolicy(_ context.Context, k bgp.SRPolicyKey) error {
	if f.err != nil {
		return f.err
	}
	f.withdrawn = append(f.withdrawn, k)
	return nil
}

// fakeEvpnAdv records EVPNController calls instead of touching gobgp.
type fakeEvpnAdv struct {
	pushed         []bgp.EVPNRoute
	withdrawn      []bgp.EVPNMACKey
	mcastPushed    []bgp.EVPNRoute
	mcastWithdrawn []bgp.EVPNMcastKey
	esPushed       []bgp.EVPNRoute
	esWithdrawn    []bgp.EVPNESKey
	err            error
}

var _ bgp.EVPNController = (*fakeEvpnAdv)(nil)

func (f *fakeEvpnAdv) PushEVPNMac(_ context.Context, r bgp.EVPNRoute) error {
	if f.err != nil {
		return f.err
	}
	f.pushed = append(f.pushed, r)
	return nil
}

func (f *fakeEvpnAdv) WithdrawEVPNMac(_ context.Context, k bgp.EVPNMACKey) error {
	if f.err != nil {
		return f.err
	}
	f.withdrawn = append(f.withdrawn, k)
	return nil
}

func (f *fakeEvpnAdv) PushEVPNInclusiveMulticast(_ context.Context, r bgp.EVPNRoute) error {
	if f.err != nil {
		return f.err
	}
	f.mcastPushed = append(f.mcastPushed, r)
	return nil
}

func (f *fakeEvpnAdv) WithdrawEVPNInclusiveMulticast(_ context.Context, k bgp.EVPNMcastKey) error {
	if f.err != nil {
		return f.err
	}
	f.mcastWithdrawn = append(f.mcastWithdrawn, k)
	return nil
}

func (f *fakeEvpnAdv) PushEVPNEthernetSegment(_ context.Context, r bgp.EVPNRoute) error {
	if f.err != nil {
		return f.err
	}
	f.esPushed = append(f.esPushed, r)
	return nil
}

func (f *fakeEvpnAdv) WithdrawEVPNEthernetSegment(_ context.Context, k bgp.EVPNESKey) error {
	if f.err != nil {
		return f.err
	}
	f.esWithdrawn = append(f.esWithdrawn, k)
	return nil
}

func TestBgpRoute_EvpnDisabledWithoutController(t *testing.T) {
	s := NewBgpRouteServer(nil, nil, nil, nil, nil)
	if _, err := s.BgpAdvertiseEvpnMac(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseEvpnMacRequest{})); err == nil {
		t.Error("BgpAdvertiseEvpnMac must fail when the EVPN controller is nil")
	}
}

func TestBgpRoute_AdvertiseEvpnMac(t *testing.T) {
	fe := &fakeEvpnAdv{}
	s := NewBgpRouteServer(nil, nil, fe, nil, nil)
	resp, err := s.BgpAdvertiseEvpnMac(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseEvpnMacRequest{Macs: []*v1.BgpEvpnMac{{
			Rd: "65000:100", RouteTargets: []string{"65000:100"},
			Mac: "aa:bb:cc:00:00:01", Sid: "fd00:2:2:d2::", NextHop: "2001:db8::1",
		}}}))
	if err != nil {
		t.Fatalf("BgpAdvertiseEvpnMac: %v", err)
	}
	if len(resp.Msg.Advertised) != 1 || len(fe.pushed) != 1 {
		t.Fatalf("advertised=%d pushed=%d, want 1/1", len(resp.Msg.Advertised), len(fe.pushed))
	}
	if fe.pushed[0].MAC != "aa:bb:cc:00:00:01" || fe.pushed[0].SRv6SID != "fd00:2:2:d2::" {
		t.Errorf("forwarded EVPN route = %+v", fe.pushed[0])
	}
}

// An invalid MAC is a per-item error and never reaches the controller.
func TestBgpRoute_AdvertiseEvpnMac_BadMacIsPerItemError(t *testing.T) {
	fe := &fakeEvpnAdv{}
	s := NewBgpRouteServer(nil, nil, fe, nil, nil)
	resp, err := s.BgpAdvertiseEvpnMac(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseEvpnMacRequest{Macs: []*v1.BgpEvpnMac{{
			Rd: "65000:100", Mac: "zz", Sid: "fd00:2:2:d2::", NextHop: "2001:db8::1",
		}}}))
	if err != nil {
		t.Fatalf("BgpAdvertiseEvpnMac: %v", err)
	}
	if len(resp.Msg.Errors) != 1 || len(fe.pushed) != 0 {
		t.Errorf("a bad MAC must be a per-item error and not reach the controller")
	}
}

func TestBgpRoute_WithdrawEvpnMac(t *testing.T) {
	fe := &fakeEvpnAdv{}
	s := NewBgpRouteServer(nil, nil, fe, nil, nil)
	resp, err := s.BgpWithdrawEvpnMac(context.Background(),
		connect.NewRequest(&v1.BgpWithdrawEvpnMacRequest{Keys: []*v1.BgpEvpnMacKey{{
			Rd: "65000:100", Mac: "aa:bb:cc:00:00:01",
		}}}))
	if err != nil {
		t.Fatalf("BgpWithdrawEvpnMac: %v", err)
	}
	if len(resp.Msg.Withdrawn) != 1 || len(fe.withdrawn) != 1 {
		t.Fatalf("withdrawn=%d fake=%d, want 1/1", len(resp.Msg.Withdrawn), len(fe.withdrawn))
	}
	if fe.withdrawn[0].MAC != "aa:bb:cc:00:00:01" {
		t.Errorf("forwarded key = %+v", fe.withdrawn[0])
	}
}

// Advertise and withdraw must derive the same tracking key even when the MAC is
// given in a different textual form (gobgp keys advertised paths on the MAC
// string, so a format mismatch would make withdraw a no-op and strand the
// route). Both the advertise route and the withdraw key must carry the
// canonical net.HardwareAddr.String() form.
func TestBgpRoute_EvpnMac_NormalizedForTracking(t *testing.T) {
	const canonical = "aa:bb:cc:00:00:01"
	fe := &fakeEvpnAdv{}
	s := NewBgpRouteServer(nil, nil, fe, nil, nil)

	// Advertise with upper-case, withdraw with a dotted form: both denote the
	// same MAC and must normalize to the same key.
	if _, err := s.BgpAdvertiseEvpnMac(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseEvpnMacRequest{Macs: []*v1.BgpEvpnMac{{
			Rd: "65000:100", RouteTargets: []string{"65000:100"},
			Mac: "AA:BB:CC:00:00:01", Sid: "fd00:2:2:d2::", NextHop: "2001:db8::1",
		}}})); err != nil {
		t.Fatalf("BgpAdvertiseEvpnMac: %v", err)
	}
	if len(fe.pushed) != 1 || fe.pushed[0].MAC != canonical {
		t.Fatalf("advertised MAC = %q, want canonical %q", fe.pushed[0].MAC, canonical)
	}

	if _, err := s.BgpWithdrawEvpnMac(context.Background(),
		connect.NewRequest(&v1.BgpWithdrawEvpnMacRequest{Keys: []*v1.BgpEvpnMacKey{{
			Rd: "65000:100", Mac: "aabb.cc00.0001",
		}}})); err != nil {
		t.Fatalf("BgpWithdrawEvpnMac: %v", err)
	}
	if len(fe.withdrawn) != 1 || fe.withdrawn[0].MAC != canonical {
		t.Fatalf("withdrawn MAC = %q, want canonical %q", fe.withdrawn[0].MAC, canonical)
	}
}

func TestBgpRoute_AdvertiseEvpnImet(t *testing.T) {
	fe := &fakeEvpnAdv{}
	s := NewBgpRouteServer(nil, nil, fe, nil, nil)
	resp, err := s.BgpAdvertiseEvpnImet(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseEvpnImetRequest{Imets: []*v1.BgpEvpnImet{{
			Rd: "65000:100", RouteTargets: []string{"65000:100"},
			Sid: "fd00:200:0:24::", NextHop: "2001:db8::1",
		}}}))
	if err != nil {
		t.Fatalf("BgpAdvertiseEvpnImet: %v", err)
	}
	if len(resp.Msg.Advertised) != 1 || len(fe.mcastPushed) != 1 {
		t.Fatalf("advertised=%d pushed=%d, want 1/1", len(resp.Msg.Advertised), len(fe.mcastPushed))
	}
	if fe.mcastPushed[0].Type != bgp.EVPNRouteTypeInclusiveMulticast || fe.mcastPushed[0].SRv6SID != "fd00:200:0:24::" {
		t.Errorf("forwarded RT3 route = %+v", fe.mcastPushed[0])
	}
}

func TestBgpRoute_WithdrawEvpnImet(t *testing.T) {
	fe := &fakeEvpnAdv{}
	s := NewBgpRouteServer(nil, nil, fe, nil, nil)
	resp, err := s.BgpWithdrawEvpnImet(context.Background(),
		connect.NewRequest(&v1.BgpWithdrawEvpnImetRequest{Keys: []*v1.BgpEvpnImetKey{{
			Rd: "65000:100", EthernetTag: 7,
		}}}))
	if err != nil {
		t.Fatalf("BgpWithdrawEvpnImet: %v", err)
	}
	if len(resp.Msg.Withdrawn) != 1 || len(fe.mcastWithdrawn) != 1 {
		t.Fatalf("withdrawn=%d fake=%d, want 1/1", len(resp.Msg.Withdrawn), len(fe.mcastWithdrawn))
	}
	if fe.mcastWithdrawn[0].RD != "65000:100" || fe.mcastWithdrawn[0].EthernetTag != 7 {
		t.Errorf("forwarded key = %+v", fe.mcastWithdrawn[0])
	}
}

func TestBgpRoute_AdvertiseEvpnEs(t *testing.T) {
	fe := &fakeEvpnAdv{}
	s := NewBgpRouteServer(nil, nil, fe, nil, nil)
	resp, err := s.BgpAdvertiseEvpnEs(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseEvpnEsRequest{Segments: []*v1.BgpEvpnEs{{
			Rd: "65000:1", Esi: "00:11:22:33:44:55:66:77:88:99",
			EsImportRt: "aa:bb:cc:dd:ee:ff", NextHop: "2001:db8::1",
		}}}))
	if err != nil {
		t.Fatalf("BgpAdvertiseEvpnEs: %v", err)
	}
	if len(resp.Msg.Advertised) != 1 || len(fe.esPushed) != 1 {
		t.Fatalf("advertised=%d pushed=%d, want 1/1", len(resp.Msg.Advertised), len(fe.esPushed))
	}
	if fe.esPushed[0].Type != bgp.EVPNRouteTypeEthernetSegment || fe.esPushed[0].ESImportRT != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("forwarded RT4 route = %+v", fe.esPushed[0])
	}
}

// An invalid ESI is a per-item error and never reaches the controller.
func TestBgpRoute_AdvertiseEvpnEs_BadEsiIsPerItemError(t *testing.T) {
	fe := &fakeEvpnAdv{}
	s := NewBgpRouteServer(nil, nil, fe, nil, nil)
	resp, err := s.BgpAdvertiseEvpnEs(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseEvpnEsRequest{Segments: []*v1.BgpEvpnEs{{
			Rd: "65000:1", Esi: "zz", EsImportRt: "aa:bb:cc:dd:ee:ff", NextHop: "2001:db8::1",
		}}}))
	if err != nil {
		t.Fatalf("BgpAdvertiseEvpnEs: %v", err)
	}
	if len(resp.Msg.Errors) != 1 || len(fe.esPushed) != 0 {
		t.Errorf("a bad ESI must be a per-item error and not reach the controller")
	}
}

func TestBgpRoute_WithdrawEvpnEs(t *testing.T) {
	fe := &fakeEvpnAdv{}
	s := NewBgpRouteServer(nil, nil, fe, nil, nil)
	resp, err := s.BgpWithdrawEvpnEs(context.Background(),
		connect.NewRequest(&v1.BgpWithdrawEvpnEsRequest{Keys: []*v1.BgpEvpnEsKey{{
			Rd: "65000:1", Esi: "00:11:22:33:44:55:66:77:88:99",
		}}}))
	if err != nil {
		t.Fatalf("BgpWithdrawEvpnEs: %v", err)
	}
	if len(resp.Msg.Withdrawn) != 1 || len(fe.esWithdrawn) != 1 {
		t.Fatalf("withdrawn=%d fake=%d, want 1/1", len(resp.Msg.Withdrawn), len(fe.esWithdrawn))
	}
	if fe.esWithdrawn[0].RD != "65000:1" {
		t.Errorf("forwarded key = %+v", fe.esWithdrawn[0])
	}
}

func TestBgpRoute_DisabledWithoutAdvertiser(t *testing.T) {
	s := NewBgpRouteServer(nil, nil, nil, nil, nil)
	_, err := s.BgpAdvertiseVpn(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseVpnRequest{}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("nil advertiser: got code %v, want FailedPrecondition", connect.CodeOf(err))
	}
}

func TestBgpRoute_SrPolicyDisabledWithoutController(t *testing.T) {
	s := NewBgpRouteServer(&fakeAdvertiser{}, nil, nil, nil, nil)
	_, err := s.BgpAdvertiseSrPolicy(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseSrPolicyRequest{}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("nil SR Policy controller: got code %v, want FailedPrecondition", connect.CodeOf(err))
	}
}

func TestBgpRoute_AdvertiseSrPolicy(t *testing.T) {
	fp := &fakeSRPolicyAdv{}
	s := NewBgpRouteServer(nil, fp, nil, nil, nil)
	resp, err := s.BgpAdvertiseSrPolicy(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseSrPolicyRequest{Policies: []*v1.BgpSrPolicy{{
			Color:         100,
			Endpoint:      "2001:db8::2",
			Segments:      []string{"fd00:200:0:1::", "fd00:200:0:2::"},
			Preference:    200,
			Distinguisher: 1,
			NextHop:       "2001:db8::1",
		}}}))
	if err != nil {
		t.Fatalf("BgpAdvertiseSrPolicy: %v", err)
	}
	if len(resp.Msg.Advertised) != 1 || len(fp.pushed) != 1 {
		t.Fatalf("advertised=%d fake.pushed=%d, want 1/1", len(resp.Msg.Advertised), len(fp.pushed))
	}
	got := fp.pushed[0]
	if got.Color != 100 || got.Endpoint.String() != "2001:db8::2" || got.AdvertiseNextHop.String() != "2001:db8::1" {
		t.Errorf("forwarded SRPolicy key = {%d, %s, nh %s}", got.Color, got.Endpoint, got.AdvertiseNextHop)
	}
	if len(got.Candidates) != 1 || got.Candidates[0].Preference != 200 || len(got.Candidates[0].SegmentList) != 2 {
		t.Errorf("forwarded candidate = %+v", got.Candidates)
	}
}

// A zero preference must map to the RFC 9256 default.
func TestBgpRoute_AdvertiseSrPolicy_DefaultPreference(t *testing.T) {
	fp := &fakeSRPolicyAdv{}
	s := NewBgpRouteServer(nil, fp, nil, nil, nil)
	if _, err := s.BgpAdvertiseSrPolicy(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseSrPolicyRequest{Policies: []*v1.BgpSrPolicy{{
			Color: 1, Endpoint: "2001:db8::2", Segments: []string{"fd00::1"}, NextHop: "2001:db8::1",
		}}})); err != nil {
		t.Fatalf("BgpAdvertiseSrPolicy: %v", err)
	}
	if len(fp.pushed) != 1 || fp.pushed[0].Candidates[0].Preference != bgp.SRPolicyDefaultPreference {
		t.Errorf("zero preference must default to %d", bgp.SRPolicyDefaultPreference)
	}
}

// A bad endpoint is a per-item error and must not reach the controller.
func TestBgpRoute_AdvertiseSrPolicy_BadEndpointIsPerItemError(t *testing.T) {
	fp := &fakeSRPolicyAdv{}
	s := NewBgpRouteServer(nil, fp, nil, nil, nil)
	resp, err := s.BgpAdvertiseSrPolicy(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseSrPolicyRequest{Policies: []*v1.BgpSrPolicy{{
			Color: 1, Endpoint: "not-an-ip", Segments: []string{"fd00::1"}, NextHop: "2001:db8::1",
		}}}))
	if err != nil {
		t.Fatalf("BgpAdvertiseSrPolicy: %v", err)
	}
	if len(resp.Msg.Errors) != 1 || len(fp.pushed) != 0 {
		t.Errorf("bad endpoint must be a per-item error and not reach the controller")
	}
}

// A non-IPv6 transport segment is a per-item error, not a silent create that
// the data-plane write would later refuse.
func TestBgpRoute_AdvertiseSrPolicy_IPv4SegmentIsPerItemError(t *testing.T) {
	fp := &fakeSRPolicyAdv{}
	s := NewBgpRouteServer(nil, fp, nil, nil, nil)
	resp, err := s.BgpAdvertiseSrPolicy(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseSrPolicyRequest{Policies: []*v1.BgpSrPolicy{{
			Color: 1, Endpoint: "2001:db8::2", Segments: []string{"10.0.0.1"}, NextHop: "2001:db8::1",
		}}}))
	if err != nil {
		t.Fatalf("BgpAdvertiseSrPolicy: %v", err)
	}
	if len(resp.Msg.Errors) != 1 || len(fp.pushed) != 0 {
		t.Errorf("an IPv4 transport segment must be a per-item error and not reach the controller")
	}
}

// An IPv4 next hop is a per-item error at the RPC boundary, matching the
// endpoint/segment constraint, rather than failing later in the controller.
func TestBgpRoute_AdvertiseSrPolicy_IPv4NextHopIsPerItemError(t *testing.T) {
	fp := &fakeSRPolicyAdv{}
	s := NewBgpRouteServer(nil, fp, nil, nil, nil)
	resp, err := s.BgpAdvertiseSrPolicy(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseSrPolicyRequest{Policies: []*v1.BgpSrPolicy{{
			Color: 1, Endpoint: "2001:db8::2", Segments: []string{"2001:db8::3"}, NextHop: "10.0.0.1",
		}}}))
	if err != nil {
		t.Fatalf("BgpAdvertiseSrPolicy: %v", err)
	}
	if len(resp.Msg.Errors) != 1 || len(fp.pushed) != 0 {
		t.Errorf("an IPv4 next hop must be a per-item error and not reach the controller")
	}
}

func TestBgpRoute_WithdrawSrPolicy(t *testing.T) {
	fp := &fakeSRPolicyAdv{}
	s := NewBgpRouteServer(nil, fp, nil, nil, nil)
	resp, err := s.BgpWithdrawSrPolicy(context.Background(),
		connect.NewRequest(&v1.BgpWithdrawSrPolicyRequest{Keys: []*v1.BgpSrPolicyKey{{
			Color: 100, Endpoint: "2001:db8::2", Distinguisher: 1,
		}}}))
	if err != nil {
		t.Fatalf("BgpWithdrawSrPolicy: %v", err)
	}
	if len(resp.Msg.Withdrawn) != 1 || len(fp.withdrawn) != 1 {
		t.Fatalf("withdrawn=%d fake=%d, want 1/1", len(resp.Msg.Withdrawn), len(fp.withdrawn))
	}
	if fp.withdrawn[0].Color != 100 || fp.withdrawn[0].Distinguisher != 1 {
		t.Errorf("forwarded SR Policy key = %+v", fp.withdrawn[0])
	}
}

// An IPv4 withdraw endpoint is a per-item error, matching the advertise/create
// constraint, rather than a no-op reported as success.
func TestBgpRoute_WithdrawSrPolicy_IPv4EndpointIsPerItemError(t *testing.T) {
	fp := &fakeSRPolicyAdv{}
	s := NewBgpRouteServer(nil, fp, nil, nil, nil)
	resp, err := s.BgpWithdrawSrPolicy(context.Background(),
		connect.NewRequest(&v1.BgpWithdrawSrPolicyRequest{Keys: []*v1.BgpSrPolicyKey{{
			Color: 100, Endpoint: "10.0.0.1", Distinguisher: 1,
		}}}))
	if err != nil {
		t.Fatalf("BgpWithdrawSrPolicy: %v", err)
	}
	if len(resp.Msg.Errors) != 1 || len(resp.Msg.Withdrawn) != 0 || len(fp.withdrawn) != 0 {
		t.Errorf("an IPv4 endpoint must be a per-item error, not a no-op success")
	}
}

func TestBgpRoute_AdvertiseVpn(t *testing.T) {
	fa := &fakeAdvertiser{}
	s := NewBgpRouteServer(fa, nil, nil, nil, nil)
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
	s := NewBgpRouteServer(fa, nil, nil, nil, nil)
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
	s := NewBgpRouteServer(fa, nil, nil, nil, nil)
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
	s := NewBgpRouteServer(fa, nil, nil, nil, nil)
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
	s := NewBgpRouteServer(fa, nil, nil, nil, nil)
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

// fakeMup records pushed MUP routes so tests can assert what reached the
// controller (and what was rejected before it).
type fakeMup struct {
	isd, dsd, t1st, t2st []bgp.MUPRoute
}

func (f *fakeMup) PushMUPISD(_ context.Context, r bgp.MUPRoute) error {
	f.isd = append(f.isd, r)
	return nil
}
func (f *fakeMup) PushMUPDSD(_ context.Context, r bgp.MUPRoute) error {
	f.dsd = append(f.dsd, r)
	return nil
}
func (f *fakeMup) PushMUPT1ST(_ context.Context, r bgp.MUPRoute) error {
	f.t1st = append(f.t1st, r)
	return nil
}
func (f *fakeMup) PushMUPT2ST(_ context.Context, r bgp.MUPRoute) error {
	f.t2st = append(f.t2st, r)
	return nil
}
func (f *fakeMup) WithdrawMUPISD(context.Context, bgp.MUPISDKey) error   { return nil }
func (f *fakeMup) WithdrawMUPDSD(context.Context, bgp.MUPDSDKey) error   { return nil }
func (f *fakeMup) WithdrawMUPT1ST(context.Context, bgp.MUPT1STKey) error { return nil }
func (f *fakeMup) WithdrawMUPT2ST(context.Context, bgp.MUPT2STKey) error { return nil }

func TestBgpRoute_MupDisabledWithoutController(t *testing.T) {
	s := NewBgpRouteServer(nil, nil, nil, nil, nil)
	if _, err := s.BgpAdvertiseMup(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseMupRequest{})); err == nil {
		t.Error("BgpAdvertiseMup must fail when the MUP controller is nil")
	}
}

func TestBgpRoute_AdvertiseMup_T2ST(t *testing.T) {
	fm := &fakeMup{}
	s := NewBgpRouteServer(&fakeAdvertiser{}, nil, nil, fm, nil)
	resp, err := s.BgpAdvertiseMup(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseMupRequest{Routes: []*v1.BgpMupRoute{{
			RouteType: "t2st", Rd: "65100:1", Endpoint: "172.16.0.254",
			Teid: 256, TeidLen: 32, SegmentId2: 1, SegmentId4: 2, NextHop: "2001:db8:ff::d",
		}}}))
	if err != nil {
		t.Fatalf("BgpAdvertiseMup: %v", err)
	}
	if len(resp.Msg.Advertised) != 1 || len(fm.t2st) != 1 {
		t.Fatalf("advertised=%d fake.t2st=%d, want 1/1", len(resp.Msg.Advertised), len(fm.t2st))
	}
	if fm.t2st[0].Type != bgp.MUPRouteTypeT2ST || fm.t2st[0].TEIDLen != 32 || fm.t2st[0].SegmentID2 != 1 {
		t.Errorf("forwarded T2ST = %+v", fm.t2st[0])
	}
}

// An out-of-range proto value (teid_len=288) would wrap to uint8 32 and slip
// past the downstream "TEIDLen > 32" guard. It must be a per-item error and
// must never reach the controller.
func TestBgpRoute_AdvertiseMup_OutOfRangeIsPerItemError(t *testing.T) {
	fm := &fakeMup{}
	s := NewBgpRouteServer(&fakeAdvertiser{}, nil, nil, fm, nil)
	resp, err := s.BgpAdvertiseMup(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseMupRequest{Routes: []*v1.BgpMupRoute{{
			RouteType: "t2st", Rd: "65100:1", Endpoint: "172.16.0.254",
			Teid: 256, TeidLen: 288, NextHop: "2001:db8:ff::d",
		}}}))
	if err != nil {
		t.Fatalf("BgpAdvertiseMup returned a top-level error, want per-item: %v", err)
	}
	if len(resp.Msg.Errors) != 1 {
		t.Errorf("out-of-range teid_len must be a per-item error, got %d", len(resp.Msg.Errors))
	}
	if len(fm.t2st) != 0 {
		t.Errorf("a rejected route must not reach the controller: %+v", fm.t2st)
	}
}
