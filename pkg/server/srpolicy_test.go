package server

import (
	"context"
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
func (f *fakeSRPolicyCtrl) ListSRPolicies() []apply.SRPolicySnapshot { return f.list }
func (f *fakeSRPolicyCtrl) HasLocalSRPolicy(color uint32, endpoint netip.Addr) bool {
	return f.hasLocal[srPolicyTestKey{color, endpoint.String()}]
}

// A nil controller (BGP disabled) makes every RPC fail FailedPrecondition.
func TestSrPolicyServer_DisabledWhenNoBGP(t *testing.T) {
	s := NewSrPolicyServer(nil)
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
	s := NewSrPolicyServer(ctrl)
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
	s := NewSrPolicyServer(ctrl)
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
	s := NewSrPolicyServer(ctrl)
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
	s := NewSrPolicyServer(ctrl)
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
