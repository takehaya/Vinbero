package server

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/apply"
)

type fakeSRPolicyCtrl struct {
	applied  []appliedPolicy
	hasLocal map[srPolicyTestKey]bool
	list     []apply.SRPolicySnapshot
	local    int // value returned by LocalSRPolicyCount (origination cap tests)
}

// srPolicyTestKey mirrors the {color, endpoint} identity HasLocalSRPolicy
// keys on, so a Delete handler that drops color would be caught.
type srPolicyTestKey struct {
	color    uint32
	endpoint string
}

type appliedPolicy struct {
	p        bgp.SRPolicy
	withdraw bool
}

func (f *fakeSRPolicyCtrl) ApplyLocalSRPolicy(p bgp.SRPolicy, withdraw bool) {
	f.applied = append(f.applied, appliedPolicy{p, withdraw})
}

// ApplyLocalSRPolicyCapped mirrors the applier: reject a NEW local policy beyond
// max (using f.local as the current count and f.hasLocal for "is this new").
func (f *fakeSRPolicyCtrl) ApplyLocalSRPolicyCapped(p bgp.SRPolicy, max uint32) error {
	if max > 0 && !f.hasLocal[srPolicyTestKey{p.Color, p.Endpoint.String()}] && uint32(f.local) >= max {
		return errors.New("local SR Policy limit reached")
	}
	f.applied = append(f.applied, appliedPolicy{p, false})
	return nil
}
func (f *fakeSRPolicyCtrl) ListSRPolicies() []apply.SRPolicySnapshot { return f.list }
func (f *fakeSRPolicyCtrl) HasLocalSRPolicy(color uint32, endpoint netip.Addr) bool {
	return f.hasLocal[srPolicyTestKey{color, endpoint.String()}]
}

// A nil controller (BGP disabled) makes every RPC fail FailedPrecondition.
func TestSrPolicyServer_DisabledWhenNoBGP(t *testing.T) {
	s := NewSrPolicyServer(nil, nil, "", 0)
	_, err := s.SrPolicyList(context.Background(), connect.NewRequest(&v1.SrPolicyListRequest{}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("SrPolicyList err = %v, want FailedPrecondition", err)
	}
	_, err = s.SrPolicyCreate(context.Background(), connect.NewRequest(&v1.SrPolicyCreateRequest{}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("SrPolicyCreate err = %v, want FailedPrecondition", err)
	}
}

func TestSrPolicyServer_CreateAppliesLocalCandidate(t *testing.T) {
	ctrl := &fakeSRPolicyCtrl{}
	s := NewSrPolicyServer(ctrl, nil, "", 0)
	resp, err := s.SrPolicyCreate(context.Background(), connect.NewRequest(&v1.SrPolicyCreateRequest{
		Policies: []*v1.SrPolicyDef{{
			Color:    100,
			Endpoint: "2001:db8::2",
			Segments: []string{"fd00:2::1", "fd00:2::2"},
		}},
	}))
	if err != nil {
		t.Fatalf("SrPolicyCreate: %v", err)
	}
	if len(resp.Msg.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", resp.Msg.Errors)
	}
	if len(ctrl.applied) != 1 {
		t.Fatalf("ApplyLocalSRPolicy called %d times, want 1", len(ctrl.applied))
	}
	got := ctrl.applied[0]
	if got.withdraw {
		t.Error("create should not be a withdraw")
	}
	if got.p.Color != 100 || got.p.Endpoint != netip.MustParseAddr("2001:db8::2") {
		t.Errorf("applied key = {%d,%s}, want {100, 2001:db8::2}", got.p.Color, got.p.Endpoint)
	}
	if len(got.p.Candidates) != 1 || got.p.Candidates[0].Origin != bgp.OriginLocal {
		t.Errorf("applied candidate = %+v, want one local candidate", got.p.Candidates)
	}
	if n := len(got.p.Candidates[0].SegmentList); n != 2 {
		t.Errorf("segment count = %d, want 2", n)
	}
}

// A bad endpoint / empty segments surface as a per-item error, not a call.
func TestSrPolicyServer_CreateValidation(t *testing.T) {
	ctrl := &fakeSRPolicyCtrl{}
	s := NewSrPolicyServer(ctrl, nil, "", 0)
	resp, err := s.SrPolicyCreate(context.Background(), connect.NewRequest(&v1.SrPolicyCreateRequest{
		Policies: []*v1.SrPolicyDef{
			{Color: 1, Endpoint: "not-an-ip", Segments: []string{"fd00:2::1"}},
			{Color: 2, Endpoint: "2001:db8::2", Segments: nil},
		},
	}))
	if err != nil {
		t.Fatalf("SrPolicyCreate: %v", err)
	}
	if len(resp.Msg.Errors) != 2 {
		t.Fatalf("errors = %d, want 2", len(resp.Msg.Errors))
	}
	if len(ctrl.applied) != 0 {
		t.Errorf("no candidate should have been applied, got %d", len(ctrl.applied))
	}
}

// Delete of a key with no local candidate is rejected (BGP-learned policies
// are read-only).
func TestSrPolicyServer_DeleteRejectsNonLocal(t *testing.T) {
	ctrl := &fakeSRPolicyCtrl{hasLocal: map[srPolicyTestKey]bool{{2, "2001:db8::9"}: true}}
	s := NewSrPolicyServer(ctrl, nil, "", 0)
	resp, err := s.SrPolicyDelete(context.Background(), connect.NewRequest(&v1.SrPolicyDeleteRequest{
		Keys: []*v1.SrPolicyKey{
			{Color: 1, Endpoint: "2001:db8::2"}, // no local -> rejected
			{Color: 2, Endpoint: "2001:db8::9"}, // local -> applied
		},
	}))
	if err != nil {
		t.Fatalf("SrPolicyDelete: %v", err)
	}
	if len(resp.Msg.Errors) != 1 {
		t.Fatalf("errors = %d, want 1 (the non-local key)", len(resp.Msg.Errors))
	}
	if len(ctrl.applied) != 1 || !ctrl.applied[0].withdraw {
		t.Fatalf("want exactly one withdraw for the local key, got %+v", ctrl.applied)
	}
}

// A local policy created with advertise=true is originated into BGP (SAFI 73)
// with the configured next hop; one without the flag is not.
func TestSrPolicyServer_CreateAdvertises(t *testing.T) {
	ctrl := &fakeSRPolicyCtrl{}
	adv := &fakeSRPolicyAdv{}
	s := NewSrPolicyServer(ctrl, adv, "2001:db8:ff::1", 0)
	resp, err := s.SrPolicyCreate(context.Background(), connect.NewRequest(&v1.SrPolicyCreateRequest{
		Policies: []*v1.SrPolicyDef{
			{Color: 100, Endpoint: "2001:db8::2", Segments: []string{"fd00:2::1"}, Advertise: true},
			{Color: 200, Endpoint: "2001:db8::3", Segments: []string{"fd00:3::1"}}, // advertise=false
		},
	}))
	if err != nil {
		t.Fatalf("SrPolicyCreate: %v", err)
	}
	if len(resp.Msg.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", resp.Msg.Errors)
	}
	if len(ctrl.applied) != 2 {
		t.Fatalf("both policies should install locally regardless of advertise; got %d", len(ctrl.applied))
	}
	if len(adv.pushed) != 1 {
		t.Fatalf("only the advertise=true policy should originate into BGP; pushed=%d", len(adv.pushed))
	}
	p := adv.pushed[0]
	if p.Color != 100 || p.Endpoint != netip.MustParseAddr("2001:db8::2") {
		t.Errorf("advertised key = {%d,%s}, want {100, 2001:db8::2}", p.Color, p.Endpoint)
	}
	if p.AdvertiseNextHop != netip.MustParseAddr("2001:db8:ff::1") {
		t.Errorf("advertised next hop = %s, want the configured 2001:db8:ff::1", p.AdvertiseNextHop)
	}
	if len(p.Candidates) != 1 || p.Candidates[0].Origin != bgp.OriginLocal {
		t.Errorf("advertised candidate = %+v, want one local candidate", p.Candidates)
	}
}

// advertise=true with no / invalid configured next hop is a per-item error, and
// the policy is NOT originated (but still installed locally).
func TestSrPolicyServer_AdvertiseRequiresIPv6NextHop(t *testing.T) {
	ctrl := &fakeSRPolicyCtrl{}
	adv := &fakeSRPolicyAdv{}
	s := NewSrPolicyServer(ctrl, adv, "", 0) // no next hop configured
	resp, err := s.SrPolicyCreate(context.Background(), connect.NewRequest(&v1.SrPolicyCreateRequest{
		Policies: []*v1.SrPolicyDef{{Color: 100, Endpoint: "2001:db8::2", Segments: []string{"fd00:2::1"}, Advertise: true}},
	}))
	if err != nil {
		t.Fatalf("SrPolicyCreate: %v", err)
	}
	if len(resp.Msg.Errors) != 1 {
		t.Fatalf("advertise with no next hop must be a per-item error; errors=%v", resp.Msg.Errors)
	}
	if len(adv.pushed) != 0 {
		t.Errorf("no policy should be originated without a valid next hop; pushed=%d", len(adv.pushed))
	}
	if len(ctrl.applied) != 1 {
		t.Errorf("the local install still happens; applied=%d", len(ctrl.applied))
	}
}

// Updating a previously-advertised policy with advertise=false withdraws it.
func TestSrPolicyServer_UpdateToggleOffWithdraws(t *testing.T) {
	ctrl := &fakeSRPolicyCtrl{}
	adv := &fakeSRPolicyAdv{}
	s := NewSrPolicyServer(ctrl, adv, "2001:db8:ff::1", 0)
	def := &v1.SrPolicyDef{Color: 100, Endpoint: "2001:db8::2", Segments: []string{"fd00:2::1"}, Advertise: true}
	if _, err := s.SrPolicyCreate(context.Background(), connect.NewRequest(&v1.SrPolicyCreateRequest{Policies: []*v1.SrPolicyDef{def}})); err != nil {
		t.Fatalf("create: %v", err)
	}
	def.Advertise = false
	if _, err := s.SrPolicyUpdate(context.Background(), connect.NewRequest(&v1.SrPolicyUpdateRequest{Policies: []*v1.SrPolicyDef{def}})); err != nil {
		t.Fatalf("update: %v", err)
	}
	if len(adv.withdrawn) != 1 {
		t.Fatalf("toggling advertise off must withdraw; withdrawn=%d", len(adv.withdrawn))
	}
	if k := adv.withdrawn[0]; k.Color != 100 || k.Endpoint != netip.MustParseAddr("2001:db8::2") {
		t.Errorf("withdraw key = {%d,%s}, want {100, 2001:db8::2}", k.Color, k.Endpoint)
	}
}

// Deleting a local policy also withdraws its BGP advertisement.
func TestSrPolicyServer_DeleteWithdraws(t *testing.T) {
	ctrl := &fakeSRPolicyCtrl{hasLocal: map[srPolicyTestKey]bool{{100, "2001:db8::2"}: true}}
	adv := &fakeSRPolicyAdv{}
	s := NewSrPolicyServer(ctrl, adv, "2001:db8:ff::1", 0)
	resp, err := s.SrPolicyDelete(context.Background(), connect.NewRequest(&v1.SrPolicyDeleteRequest{
		Keys: []*v1.SrPolicyKey{{Color: 100, Endpoint: "2001:db8::2"}},
	}))
	if err != nil {
		t.Fatalf("SrPolicyDelete: %v", err)
	}
	if len(resp.Msg.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", resp.Msg.Errors)
	}
	if len(adv.withdrawn) != 1 || adv.withdrawn[0].Color != 100 {
		t.Errorf("delete must withdraw the advertisement; withdrawn=%+v", adv.withdrawn)
	}
}

// The origination cap rejects a NEW local policy once the limit is reached, but
// an update of an existing {color, endpoint} is always allowed.
func TestSrPolicyServer_OriginationCap(t *testing.T) {
	// At the cap (2 local), creating a new policy is rejected and nothing applied.
	ctrl := &fakeSRPolicyCtrl{local: 2}
	s := NewSrPolicyServer(ctrl, nil, "", 2)
	resp, err := s.SrPolicyCreate(context.Background(), connect.NewRequest(&v1.SrPolicyCreateRequest{
		Policies: []*v1.SrPolicyDef{{Color: 9, Endpoint: "2001:db8::9", Segments: []string{"fd00:9::1"}}},
	}))
	if err != nil {
		t.Fatalf("SrPolicyCreate: %v", err)
	}
	if len(resp.Msg.Errors) != 1 {
		t.Fatalf("a new policy beyond the cap must be a per-item error; errors=%v", resp.Msg.Errors)
	}
	if len(ctrl.applied) != 0 {
		t.Errorf("nothing should be applied when capped; applied=%d", len(ctrl.applied))
	}
	// Updating an EXISTING local policy at the cap is allowed (not a new policy).
	ctrl2 := &fakeSRPolicyCtrl{local: 2, hasLocal: map[srPolicyTestKey]bool{{1, "2001:db8::1"}: true}}
	s2 := NewSrPolicyServer(ctrl2, nil, "", 2)
	resp2, err := s2.SrPolicyUpdate(context.Background(), connect.NewRequest(&v1.SrPolicyUpdateRequest{
		Policies: []*v1.SrPolicyDef{{Color: 1, Endpoint: "2001:db8::1", Segments: []string{"fd00:1::1"}}},
	}))
	if err != nil {
		t.Fatalf("SrPolicyUpdate: %v", err)
	}
	if len(resp2.Msg.Errors) != 0 || len(ctrl2.applied) != 1 {
		t.Errorf("updating an existing policy at the cap must be allowed; errors=%v applied=%d", resp2.Msg.Errors, len(ctrl2.applied))
	}
}

func TestSrPolicyServer_ListTranslatesSnapshot(t *testing.T) {
	ctrl := &fakeSRPolicyCtrl{list: []apply.SRPolicySnapshot{{
		Color:    100,
		Endpoint: netip.MustParseAddr("2001:db8::2"),
		PolicyID: 5,
		Candidates: []apply.CandidateSnapshot{{
			Origin:      bgp.OriginBGP,
			Preference:  200,
			SegmentList: []netip.Addr{netip.MustParseAddr("fd00:2::1")},
			Active:      true,
		}},
	}}}
	s := NewSrPolicyServer(ctrl, nil, "", 0)
	resp, err := s.SrPolicyList(context.Background(), connect.NewRequest(&v1.SrPolicyListRequest{}))
	if err != nil {
		t.Fatalf("SrPolicyList: %v", err)
	}
	if len(resp.Msg.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(resp.Msg.Entries))
	}
	e := resp.Msg.Entries[0]
	if e.Color != 100 || e.Endpoint != "2001:db8::2" || e.PolicyId != 5 {
		t.Errorf("entry key = {%d,%s,%d}", e.Color, e.Endpoint, e.PolicyId)
	}
	if len(e.Candidates) != 1 || e.Candidates[0].Origin != v1.SrPolicyOrigin_SR_POLICY_ORIGIN_BGP || !e.Candidates[0].Active {
		t.Errorf("candidate = %+v, want one active BGP candidate", e.Candidates)
	}
}
