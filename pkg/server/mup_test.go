package server

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// fakeMUPController records the per-type advertise / withdraw calls so a test
// can assert what MupServer originated.
type fakeMUPController struct {
	pushedISD  []bgp.MUPRoute
	pushedDSD  []bgp.MUPRoute
	pushedT1ST []bgp.MUPRoute
	pushedT2ST []bgp.MUPRoute
	wdISD      []bgp.MUPISDKey
	wdDSD      []bgp.MUPDSDKey
	wdT1ST     []bgp.MUPT1STKey
	wdT2ST     []bgp.MUPT2STKey
	err        error // when set, every Push/Withdraw fails
}

var _ bgp.MUPController = (*fakeMUPController)(nil)

func (f *fakeMUPController) PushMUPISD(_ context.Context, r bgp.MUPRoute) error {
	if f.err != nil {
		return f.err
	}
	f.pushedISD = append(f.pushedISD, r)
	return nil
}
func (f *fakeMUPController) PushMUPDSD(_ context.Context, r bgp.MUPRoute) error {
	if f.err != nil {
		return f.err
	}
	f.pushedDSD = append(f.pushedDSD, r)
	return nil
}
func (f *fakeMUPController) PushMUPT1ST(_ context.Context, r bgp.MUPRoute) error {
	if f.err != nil {
		return f.err
	}
	f.pushedT1ST = append(f.pushedT1ST, r)
	return nil
}
func (f *fakeMUPController) PushMUPT2ST(_ context.Context, r bgp.MUPRoute) error {
	if f.err != nil {
		return f.err
	}
	f.pushedT2ST = append(f.pushedT2ST, r)
	return nil
}
func (f *fakeMUPController) WithdrawMUPISD(_ context.Context, k bgp.MUPISDKey) error {
	f.wdISD = append(f.wdISD, k)
	return f.err
}
func (f *fakeMUPController) WithdrawMUPDSD(_ context.Context, k bgp.MUPDSDKey) error {
	f.wdDSD = append(f.wdDSD, k)
	return f.err
}
func (f *fakeMUPController) WithdrawMUPT1ST(_ context.Context, k bgp.MUPT1STKey) error {
	f.wdT1ST = append(f.wdT1ST, k)
	return f.err
}
func (f *fakeMUPController) WithdrawMUPT2ST(_ context.Context, k bgp.MUPT2STKey) error {
	f.wdT2ST = append(f.wdT2ST, k)
	return f.err
}

const mupTestNH = "2001:db8:ff::1"

func mupCreate(t *testing.T, s *MupServer, routes ...*v1.BgpMupRoute) *v1.MupCreateResponse {
	t.Helper()
	resp, err := s.MupCreate(context.Background(), connect.NewRequest(&v1.MupCreateRequest{Routes: routes}))
	if err != nil {
		t.Fatalf("MupCreate: %v", err)
	}
	return resp.Msg
}

func mupListRoutes(t *testing.T, s *MupServer) []*v1.BgpMupRoute {
	t.Helper()
	resp, err := s.MupList(context.Background(), connect.NewRequest(&v1.MupListRequest{}))
	if err != nil {
		t.Fatalf("MupList: %v", err)
	}
	return resp.Msg.Routes
}

// A nil advertiser (BGP disabled) makes every RPC fail FailedPrecondition.
func TestMupServer_DisabledWhenNoBGP(t *testing.T) {
	s := NewMupServer(nil, "", 0, nil)
	if _, err := s.MupList(context.Background(), connect.NewRequest(&v1.MupListRequest{})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("MupList err = %v, want FailedPrecondition", err)
	}
	if _, err := s.MupCreate(context.Background(), connect.NewRequest(&v1.MupCreateRequest{})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("MupCreate err = %v, want FailedPrecondition", err)
	}
	if _, err := s.MupUpdate(context.Background(), connect.NewRequest(&v1.MupUpdateRequest{})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("MupUpdate err = %v, want FailedPrecondition", err)
	}
	if _, err := s.MupDelete(context.Background(), connect.NewRequest(&v1.MupDeleteRequest{})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("MupDelete err = %v, want FailedPrecondition", err)
	}
}

// Create originates each route through the matching per-type Push method and
// defaults an empty next hop to the server's configured value.
func TestMupServer_CreateAdvertisesPerType(t *testing.T) {
	adv := &fakeMUPController{}
	s := NewMupServer(adv, mupTestNH, 0, nil)
	msg := mupCreate(t, s,
		&v1.BgpMupRoute{RouteType: "isd", Rd: "65000:1", Prefix: "172.16.0.0/24", Srv6Sid: "fd00:a:0:1::"},
		&v1.BgpMupRoute{RouteType: "dsd", Rd: "65000:1", Address: "10.0.0.1"},
		&v1.BgpMupRoute{RouteType: "t1st", Rd: "65000:1", Prefix: "10.0.0.2/32", Teid: 100},
		&v1.BgpMupRoute{RouteType: "t2st", Rd: "65000:1", Endpoint: "2001:db8::9", Teid: 200, TeidLen: 32},
	)
	if len(msg.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", msg.Errors)
	}
	if len(adv.pushedISD) != 1 || len(adv.pushedDSD) != 1 || len(adv.pushedT1ST) != 1 || len(adv.pushedT2ST) != 1 {
		t.Fatalf("each route type should push once; isd=%d dsd=%d t1st=%d t2st=%d",
			len(adv.pushedISD), len(adv.pushedDSD), len(adv.pushedT1ST), len(adv.pushedT2ST))
	}
	if adv.pushedISD[0].NextHop != mupTestNH {
		t.Errorf("empty next hop must default to the configured %s, got %q", mupTestNH, adv.pushedISD[0].NextHop)
	}
	if adv.pushedISD[0].Type != bgp.MUPRouteTypeISD || adv.pushedT2ST[0].Type != bgp.MUPRouteTypeT2ST {
		t.Errorf("route Type must be set before push")
	}
	if got := mupListRoutes(t, s); len(got) != 4 {
		t.Errorf("List should show all 4 originated routes, got %d", len(got))
	}
}

// advertise with no usable next hop is a per-item error: not pushed, not stored.
func TestMupServer_RequiresIPv6NextHop(t *testing.T) {
	adv := &fakeMUPController{}
	s := NewMupServer(adv, "", 0, nil) // no configured next hop
	msg := mupCreate(t, s,
		&v1.BgpMupRoute{RouteType: "isd", Rd: "65000:1", Prefix: "172.16.0.0/24"},                   // empty + no default
		&v1.BgpMupRoute{RouteType: "dsd", Rd: "65000:1", Address: "10.0.0.1", NextHop: "192.0.2.1"}, // IPv4
		&v1.BgpMupRoute{RouteType: "t1st", Rd: "65000:1", Prefix: "10.0.0.2/32", NextHop: "::"},     // unspecified -> blackhole
	)
	if len(msg.Errors) != 3 {
		t.Fatalf("each bad next hop should error; errors=%v", msg.Errors)
	}
	if len(adv.pushedISD) != 0 || len(adv.pushedDSD) != 0 || len(adv.pushedT1ST) != 0 {
		t.Errorf("nothing should be pushed without a valid next hop")
	}
	if got := mupListRoutes(t, s); len(got) != 0 {
		t.Errorf("nothing should be stored; List=%d", len(got))
	}
}

// An out-of-range teid_len is rejected per-item and not stored.
func TestMupServer_FieldValidation(t *testing.T) {
	adv := &fakeMUPController{}
	s := NewMupServer(adv, mupTestNH, 0, nil)
	msg := mupCreate(t, s,
		&v1.BgpMupRoute{RouteType: "t2st", Rd: "65000:1", Endpoint: "2001:db8::9", Teid: 1, TeidLen: 33},
	)
	if len(msg.Errors) != 1 {
		t.Fatalf("teid_len > 32 must be a per-item error; errors=%v", msg.Errors)
	}
	if len(adv.pushedT2ST) != 0 || len(mupListRoutes(t, s)) != 0 {
		t.Errorf("an invalid route must not be pushed or stored")
	}
}

// A Push failure surfaces as a per-item error and the route is NOT stored, so
// List never reports a route BGP rejected.
func TestMupServer_PushFailureNotStored(t *testing.T) {
	adv := &fakeMUPController{err: context.Canceled}
	s := NewMupServer(adv, mupTestNH, 0, nil)
	msg := mupCreate(t, s, &v1.BgpMupRoute{RouteType: "isd", Rd: "65000:1", Prefix: "172.16.0.0/24"})
	if len(msg.Errors) != 1 {
		t.Fatalf("a push failure must be a per-item error; errors=%v", msg.Errors)
	}
	adv.err = nil
	if got := mupListRoutes(t, s); len(got) != 0 {
		t.Errorf("a route whose push failed must not be stored; List=%d", len(got))
	}
}

// Delete derives the right per-type withdraw key and drops the route from the
// local table.
func TestMupServer_DeleteWithdrawsAndDrops(t *testing.T) {
	adv := &fakeMUPController{}
	s := NewMupServer(adv, mupTestNH, 0, nil)
	t2st := &v1.BgpMupRoute{RouteType: "t2st", Rd: "65000:1", Endpoint: "2001:db8::9", Teid: 200, TeidLen: 24}
	mupCreate(t, s, t2st)
	resp, err := s.MupDelete(context.Background(), connect.NewRequest(&v1.MupDeleteRequest{Routes: []*v1.BgpMupRoute{t2st}}))
	if err != nil {
		t.Fatalf("MupDelete: %v", err)
	}
	if len(resp.Msg.Errors) != 0 {
		t.Fatalf("unexpected delete errors: %v", resp.Msg.Errors)
	}
	if len(adv.wdT2ST) != 1 {
		t.Fatalf("delete must withdraw the t2st route; wdT2ST=%d", len(adv.wdT2ST))
	}
	if k := adv.wdT2ST[0]; k.RD != "65000:1" || k.Endpoint != "2001:db8::9" || k.TEID != 200 || k.TEIDLen != 24 {
		t.Errorf("withdraw key = %+v, want {65000:1, 2001:db8::9, 200, 24}", k)
	}
	if got := mupListRoutes(t, s); len(got) != 0 {
		t.Errorf("the deleted route must be dropped from the table; List=%d", len(got))
	}
}

// Update is an idempotent re-originate: the same key replaces in place, so List
// still shows exactly one route.
func TestMupServer_UpdateReplacesInPlace(t *testing.T) {
	adv := &fakeMUPController{}
	s := NewMupServer(adv, mupTestNH, 0, nil)
	r := &v1.BgpMupRoute{RouteType: "isd", Rd: "65000:1", Prefix: "172.16.0.0/24", Srv6Sid: "fd00:a:0:1::"}
	mupCreate(t, s, r)
	r.Srv6Sid = "fd00:a:0:2::" // change a non-key field
	if _, err := s.MupUpdate(context.Background(), connect.NewRequest(&v1.MupUpdateRequest{Routes: []*v1.BgpMupRoute{r}})); err != nil {
		t.Fatalf("MupUpdate: %v", err)
	}
	got := mupListRoutes(t, s)
	if len(got) != 1 {
		t.Fatalf("an unchanged-key update must replace in place; List=%d", len(got))
	}
	if got[0].GetSrv6Sid() != "fd00:a:0:2::" {
		t.Errorf("update must reflect the new SID; got %q", got[0].GetSrv6Sid())
	}
	if len(adv.pushedISD) != 2 {
		t.Errorf("update re-pushes; pushedISD=%d, want 2", len(adv.pushedISD))
	}
}

// The route type is part of the local key, so an ISD {rd,prefix} and a T1ST
// {rd,prefix,teid=0} with the same rd+prefix are two distinct entries.
func TestMupServer_TypeDisambiguatesKey(t *testing.T) {
	adv := &fakeMUPController{}
	s := NewMupServer(adv, mupTestNH, 0, nil)
	mupCreate(t, s,
		&v1.BgpMupRoute{RouteType: "isd", Rd: "65000:1", Prefix: "10.0.0.0/24"},
		&v1.BgpMupRoute{RouteType: "t1st", Rd: "65000:1", Prefix: "10.0.0.0/24", Teid: 0},
	)
	if got := mupListRoutes(t, s); len(got) != 2 {
		t.Errorf("ISD and T1ST with the same rd+prefix must be distinct; List=%d, want 2", len(got))
	}
}

// The origination cap rejects a NEW route once the limit is reached, but an
// update of an existing route is always allowed.
func TestMupServer_OriginationCap(t *testing.T) {
	adv := &fakeMUPController{}
	s := NewMupServer(adv, mupTestNH, 2, nil)
	if msg := mupCreate(t, s,
		&v1.BgpMupRoute{RouteType: "isd", Rd: "65000:1", Prefix: "10.0.0.0/24"},
		&v1.BgpMupRoute{RouteType: "dsd", Rd: "65000:1", Address: "10.0.0.1"},
	); len(msg.Errors) != 0 {
		t.Fatalf("two routes within the cap must succeed; errors=%v", msg.Errors)
	}
	// A third NEW route is over the cap: per-item error, not stored.
	msg := mupCreate(t, s, &v1.BgpMupRoute{RouteType: "t1st", Rd: "65000:1", Prefix: "10.0.0.2/32", Teid: 5})
	if len(msg.Errors) != 1 {
		t.Fatalf("a new route beyond the cap must be a per-item error; errors=%v", msg.Errors)
	}
	if got := mupListRoutes(t, s); len(got) != 2 {
		t.Errorf("a capped route must not be stored; List=%d", len(got))
	}
	// Updating an existing route at the cap is allowed.
	if msg := mupCreate(t, s, &v1.BgpMupRoute{RouteType: "isd", Rd: "65000:1", Prefix: "10.0.0.0/24", Srv6Sid: "fd00:a::"}); len(msg.Errors) != 0 {
		t.Errorf("updating an existing route at the cap must be allowed; errors=%v", msg.Errors)
	}
}

// List round-trips every field through mupRouteToProto, including the uint8 ->
// uint32 widening (qfi/rqi/teid_len/segment_id2) and the route_type string.
func TestMupServer_ListRoundTrips(t *testing.T) {
	adv := &fakeMUPController{}
	s := NewMupServer(adv, mupTestNH, 0, nil)
	mupCreate(t, s,
		&v1.BgpMupRoute{RouteType: "isd", Rd: "65000:1", Prefix: "172.16.0.0/24"},
		&v1.BgpMupRoute{RouteType: "dsd", Rd: "65000:1", Address: "10.0.0.1"},
		&v1.BgpMupRoute{RouteType: "t1st", Rd: "65000:1", Prefix: "10.0.0.2/32", Teid: 100, Qfi: 5, Rqi: 1},
		&v1.BgpMupRoute{RouteType: "t2st", Rd: "65000:1", Endpoint: "2001:db8::9", Teid: 200, TeidLen: 24, SegmentId2: 7},
	)
	byType := map[string]*v1.BgpMupRoute{}
	for _, r := range mupListRoutes(t, s) {
		byType[r.GetRouteType()] = r
		if r.GetNextHop() != mupTestNH {
			t.Errorf("route %s missing defaulted next hop", r.GetRouteType())
		}
	}
	for _, want := range []string{"isd", "dsd", "t1st", "t2st"} {
		if byType[want] == nil {
			t.Errorf("List missing route_type %q", want)
		}
	}
	// Pin the narrowing/widening round-trip so a wrong cast in mupRouteToProto fails.
	if r := byType["t1st"]; r != nil && (r.GetQfi() != 5 || r.GetRqi() != 1 || r.GetTeid() != 100) {
		t.Errorf("t1st fields did not round-trip: qfi=%d rqi=%d teid=%d", r.GetQfi(), r.GetRqi(), r.GetTeid())
	}
	if r := byType["t2st"]; r != nil && (r.GetTeidLen() != 24 || r.GetSegmentId2() != 7) {
		t.Errorf("t2st fields did not round-trip: teid_len=%d segment_id2=%d", r.GetTeidLen(), r.GetSegmentId2())
	}
}

// mupBindingMgrWithVRF returns a fresh Manager pre-bound with one VRF whose
// RD and export RTs are supplied. Tests use it to point a Create at a
// matching binding so the auto-fill path fires.
func mupBindingMgrWithVRF(t *testing.T, vrfName, rd string, families map[bgp.Family]vrfbgp.FamilyPolicy) *vrfbgp.Manager {
	t.Helper()
	m := vrfbgp.NewManager()
	if err := m.Bind(vrfbgp.Binding{
		VRFName:  vrfName,
		RD:       rd,
		Families: families,
	}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	return m
}

// When mr.RTs is empty and a binding with matching RD declares the route's
// mup_ipv* family with export RTs, MupCreate fills the RTs from the binding
// before Push. The operator can stop repeating --route-targets on every call.
func TestMupServer_AutoFillRTsFromBinding(t *testing.T) {
	adv := &fakeMUPController{}
	mgr := mupBindingMgrWithVRF(t, "vrf-mup", "65000:1", map[bgp.Family]vrfbgp.FamilyPolicy{
		bgp.FamilyMUPIPv4: {RouteTargets: []vrfbgp.RouteTarget{{RT: "100:6000", Direction: vrfbgp.DirectionBoth}}},
	})
	s := NewMupServer(adv, mupTestNH, 0, mgr)
	mupCreate(t, s,
		&v1.BgpMupRoute{RouteType: "dsd", Rd: "65000:1", Address: "10.0.0.1"},
	)
	if len(adv.pushedDSD) != 1 || len(adv.pushedDSD[0].RTs) != 1 || adv.pushedDSD[0].RTs[0] != "100:6000" {
		t.Errorf("DSD must be advertised with binding-derived RT [100:6000]; got %v", adv.pushedDSD)
	}
}

// Explicit RTs on the request win over the binding's export RTs so an operator
// can still override the binding-driven default on a single call.
func TestMupServer_ExplicitRTsBeatBinding(t *testing.T) {
	adv := &fakeMUPController{}
	mgr := mupBindingMgrWithVRF(t, "vrf-mup", "65000:1", map[bgp.Family]vrfbgp.FamilyPolicy{
		bgp.FamilyMUPIPv4: {RouteTargets: []vrfbgp.RouteTarget{{RT: "100:6000", Direction: vrfbgp.DirectionBoth}}},
	})
	s := NewMupServer(adv, mupTestNH, 0, mgr)
	mupCreate(t, s,
		&v1.BgpMupRoute{RouteType: "dsd", Rd: "65000:1", Address: "10.0.0.1", RouteTargets: []string{"100:9999"}},
	)
	if len(adv.pushedDSD) != 1 || len(adv.pushedDSD[0].RTs) != 1 || adv.pushedDSD[0].RTs[0] != "100:9999" {
		t.Errorf("explicit RT must beat binding-derived RT; got %v", adv.pushedDSD)
	}
}

// A binding whose RD does not match the route is not consulted, so the route's
// empty RTs go on the wire verbatim (matching the legacy behavior).
func TestMupServer_NoMatchingBindingKeepsEmptyRTs(t *testing.T) {
	adv := &fakeMUPController{}
	mgr := mupBindingMgrWithVRF(t, "vrf-mup", "65000:1", map[bgp.Family]vrfbgp.FamilyPolicy{
		bgp.FamilyMUPIPv4: {RouteTargets: []vrfbgp.RouteTarget{{RT: "100:6000", Direction: vrfbgp.DirectionBoth}}},
	})
	s := NewMupServer(adv, mupTestNH, 0, mgr)
	mupCreate(t, s,
		&v1.BgpMupRoute{RouteType: "dsd", Rd: "65000:999", Address: "10.0.0.1"},
	)
	if len(adv.pushedDSD) != 1 || len(adv.pushedDSD[0].RTs) != 0 {
		t.Errorf("non-matching RD must leave RTs empty; got %v", adv.pushedDSD)
	}
}

// Two bindings sharing the same RD is ambiguous; BindingByRD returns ok=false
// so the auto-fill backs off and leaves the route's RTs untouched. Without
// this, the route would be advertised under one binding's RTs while the
// operator believed it was the other's.
func TestMupServer_AmbiguousRDLeavesRTsEmpty(t *testing.T) {
	adv := &fakeMUPController{}
	mgr := vrfbgp.NewManager()
	for _, name := range []string{"vrf-a", "vrf-b"} {
		if err := mgr.Bind(vrfbgp.Binding{
			VRFName: name, RD: "65000:1",
			Families: map[bgp.Family]vrfbgp.FamilyPolicy{
				bgp.FamilyMUPIPv4: {RouteTargets: []vrfbgp.RouteTarget{{RT: "100:6000", Direction: vrfbgp.DirectionBoth}}},
			},
		}); err != nil {
			t.Fatalf("Bind: %v", err)
		}
	}
	s := NewMupServer(adv, mupTestNH, 0, mgr)
	mupCreate(t, s,
		&v1.BgpMupRoute{RouteType: "dsd", Rd: "65000:1", Address: "10.0.0.1"},
	)
	if len(adv.pushedDSD) != 1 || len(adv.pushedDSD[0].RTs) != 0 {
		t.Errorf("ambiguous RD must not auto-fill; got %v", adv.pushedDSD)
	}
}

// A binding whose Families map does not declare mup_ipv* leaves the RTs empty
// even when its RD matches: the auto-fill is family-scoped, so an L3VPN-only
// binding cannot leak its vpnv4 RTs onto a MUP route.
func TestMupServer_BindingWithoutMUPFamilyKeepsEmptyRTs(t *testing.T) {
	adv := &fakeMUPController{}
	mgr := mupBindingMgrWithVRF(t, "vrf-l3", "65000:1", map[bgp.Family]vrfbgp.FamilyPolicy{
		bgp.FamilyVPNv4: {RouteTargets: []vrfbgp.RouteTarget{{RT: "100:6000", Direction: vrfbgp.DirectionBoth}}},
	})
	s := NewMupServer(adv, mupTestNH, 0, mgr)
	mupCreate(t, s,
		&v1.BgpMupRoute{RouteType: "dsd", Rd: "65000:1", Address: "10.0.0.1"},
	)
	if len(adv.pushedDSD) != 1 || len(adv.pushedDSD[0].RTs) != 0 {
		t.Errorf("binding without mup_ipv4 family must not auto-fill from vpnv4 RTs; got %v", adv.pushedDSD)
	}
}

// IPv6-family MUP routes (Address / Endpoint / Prefix are v6) auto-fill from
// the binding's mup_ipv6 family — not mup_ipv4. This guards against the
// regression where Family() detection is the wrong AF.
func TestMupServer_AutoFillUsesIPv6FamilyForV6Endpoint(t *testing.T) {
	adv := &fakeMUPController{}
	mgr := mupBindingMgrWithVRF(t, "vrf-mup6", "65000:1", map[bgp.Family]vrfbgp.FamilyPolicy{
		bgp.FamilyMUPIPv4: {RouteTargets: []vrfbgp.RouteTarget{{RT: "100:4444", Direction: vrfbgp.DirectionBoth}}},
		bgp.FamilyMUPIPv6: {RouteTargets: []vrfbgp.RouteTarget{{RT: "100:6666", Direction: vrfbgp.DirectionBoth}}},
	})
	s := NewMupServer(adv, mupTestNH, 0, mgr)
	mupCreate(t, s,
		&v1.BgpMupRoute{RouteType: "t2st", Rd: "65000:1", Endpoint: "2001:db8::9", Teid: 1, TeidLen: 24},
	)
	if len(adv.pushedT2ST) != 1 || len(adv.pushedT2ST[0].RTs) != 1 || adv.pushedT2ST[0].RTs[0] != "100:6666" {
		t.Errorf("v6 endpoint must auto-fill from mup_ipv6 (100:6666); got %v", adv.pushedT2ST)
	}
}
