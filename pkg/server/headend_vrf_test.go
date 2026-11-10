package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/vrf"
)

// A headend request naming a VRF that does not exist is refused before any
// map is touched (the servers here have none), and creates no VRF: Create
// per entry, the other RPCs as NotFound. A vrf_id in a request is refused.
func TestHeadendRPCRefusesUnknownVRF(t *testing.T) {
	ctx := context.Background()
	mgr := vrf.NewManager()
	if _, err := mgr.Ensure("tenant-a"); err != nil {
		t.Fatal(err)
	}
	s4, s6 := NewHeadendv4Server(nil, mgr), NewHeadendv6Server(nil, mgr)
	notFound := func(t *testing.T, what string, err error) {
		t.Helper()
		if connect.CodeOf(err) != connect.CodeNotFound || !strings.Contains(err.Error(), "unknown VRF") {
			t.Errorf("%s: %v, want NotFound unknown VRF", what, err)
		}
	}

	c4, err := s4.Headendv4Create(ctx, connect.NewRequest(&v1.Headendv4CreateRequest{Headendv4S: []*v1.Headendv4{
		{Mode: v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS, TriggerPrefix: "10.0.0.0/24", SrcAddr: "fc00::1", Segments: []string{"fc00::2"}, VrfName: "tenant-x"},
		{Mode: v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS, TriggerPrefix: "10.0.0.0/24", SrcAddr: "fc00::1", Segments: []string{"fc00::2"}, VrfId: 1},
	}}))
	if err != nil || len(c4.Msg.Created) != 0 || len(c4.Msg.Errors) != 2 ||
		!strings.Contains(c4.Msg.Errors[0].Reason, "unknown VRF") || !strings.Contains(c4.Msg.Errors[1].Reason, "server-assigned") {
		t.Errorf("v4 create = %v %v", c4, err)
	}
	c6, err := s6.Headendv6Create(ctx, connect.NewRequest(&v1.Headendv6CreateRequest{Headendv6S: []*v1.Headendv6{
		{Mode: v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS, TriggerPrefix: "2001:db8::/32", SrcAddr: "fc00::1", Segments: []string{"fc00::2"}, VrfName: "tenant-x"},
	}}))
	if err != nil || len(c6.Msg.Created) != 0 || len(c6.Msg.Errors) != 1 || !strings.Contains(c6.Msg.Errors[0].Reason, "unknown VRF") {
		t.Errorf("v6 create = %v %v", c6, err)
	}
	_, err = s4.Headendv4Delete(ctx, connect.NewRequest(&v1.Headendv4DeleteRequest{TriggerPrefixes: []string{"10.0.0.0/24"}, VrfName: "tenant-x"}))
	notFound(t, "v4 delete", err)
	_, err = s4.Headendv4Get(ctx, connect.NewRequest(&v1.Headendv4GetRequest{TriggerPrefix: "10.0.0.0/24", VrfName: "tenant-x"}))
	notFound(t, "v4 get", err)
	_, err = s4.Headendv4List(ctx, connect.NewRequest(&v1.Headendv4ListRequest{VrfName: "tenant-x"}))
	notFound(t, "v4 list", err)
	_, err = s4.Headendv4Flush(ctx, connect.NewRequest(&v1.Headendv4FlushRequest{VrfName: "tenant-x"}))
	notFound(t, "v4 flush", err)
	_, err = s6.Headendv6Delete(ctx, connect.NewRequest(&v1.Headendv6DeleteRequest{TriggerPrefixes: []string{"2001:db8::/32"}, VrfName: "tenant-x"}))
	notFound(t, "v6 delete", err)
	_, err = s6.Headendv6Get(ctx, connect.NewRequest(&v1.Headendv6GetRequest{TriggerPrefix: "2001:db8::/32", VrfName: "tenant-x"}))
	notFound(t, "v6 get", err)
	_, err = s6.Headendv6List(ctx, connect.NewRequest(&v1.Headendv6ListRequest{VrfName: "tenant-x"}))
	notFound(t, "v6 list", err)
	_, err = s6.Headendv6Flush(ctx, connect.NewRequest(&v1.Headendv6FlushRequest{VrfName: "tenant-x"}))
	notFound(t, "v6 flush", err)
	if _, ok := mgr.Get("tenant-x"); ok {
		t.Error("a headend request created the VRF it named")
	}

	// A server with no VRF directory takes the global VRF only.
	bare := NewHeadendv4Server(nil, nil)
	_, err = bare.Headendv4Get(ctx, connect.NewRequest(&v1.Headendv4GetRequest{TriggerPrefix: "10.0.0.0/24", VrfName: "tenant-a"}))
	notFound(t, "get without a VRF directory", err)
}

// resolveHeadendVRF holds a named VRF against deletion until the write is
// done, and takes no hold for the global VRF.
func TestResolveHeadendVRFHoldsTheVRF(t *testing.T) {
	mgr := vrf.NewManager()
	a, err := mgr.Ensure("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", vrf.GlobalVRFName} {
		id, release, err := resolveHeadendVRF(mgr, name, true)
		if err != nil || id != 0 {
			t.Fatalf("resolve %q = %d %v", name, id, err)
		}
		unlock := mgr.LockIDs() // would block if a hold were taken
		unlock()
		release()
	}
	id, release, err := resolveHeadendVRF(mgr, "tenant-a", true)
	if err != nil || id != a.ID {
		t.Fatalf("resolve tenant-a = %d %v", id, err)
	}
	locked := make(chan func())
	go func() { locked <- mgr.LockIDs() }()
	select {
	case <-locked:
		t.Fatal("a VRF delete went ahead of a headend write that resolved it")
	case <-time.After(50 * time.Millisecond):
	}
	release()
	(<-locked)()
}

// A VRF holding headend entries is not deleted, as one holding ACs or a
// binding is not: its id is never given out again, so the entries would
// stay with no name to remove them by. The count runs under the lock a
// headend write's hold excludes.
func TestVrfDeleteRefusesWhileHeadendEntriesRemain(t *testing.T) {
	s, _ := newTestVrfServer()
	a, err := s.mgr.Ensure("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	sids := &fakeSidTable{headends: map[uint32]int{a.ID: 2}}
	s.sids = sids
	sids.headendHook = func() {
		release := make(chan func(), 1)
		go func() { release <- s.mgr.HoldIDs() }()
		select {
		case r := <-release:
			r()
			t.Error("a headend write could resolve the VRF during the delete's entry count")
		case <-time.After(50 * time.Millisecond):
			go func() { (<-release)() }()
		}
	}
	resp, err := s.VrfDelete(context.Background(), connect.NewRequest(&v1.VrfDeleteRequest{Names: []string{"tenant-a"}}))
	if err != nil || len(resp.Msg.DeletedNames) != 0 || len(resp.Msg.Errors) != 1 ||
		!strings.Contains(resp.Msg.Errors[0].Reason, "headend entries remain in this VRF (2)") {
		t.Fatalf("delete with entries = %+v %v", resp, err)
	}
	if _, ok := s.mgr.Get("tenant-a"); !ok {
		t.Fatal("the VRF was deleted")
	}
	sids.headendHook = nil
	sids.headends[a.ID] = 0
	resp, err = s.VrfDelete(context.Background(), connect.NewRequest(&v1.VrfDeleteRequest{Names: []string{"tenant-a"}}))
	if err != nil || len(resp.Msg.DeletedNames) != 1 {
		t.Fatalf("delete without entries = %+v %v", resp, err)
	}
}

// A VrfAcAdd that created its VRF and then fails rolls the VRF back, unless
// a headend entry was written under the new id in the meantime.
func TestVrfAcAddRollbackKeepsVRFWithHeadendEntries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries int
		keep    bool
	}{{"no entries", 0, false}, {"entries", 1, true}} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestVrfServer()
			sids := &fakeSidTable{headends: map[uint32]int{}}
			s.sids = sids
			sids.headendHook = func() {
				if id, ok := s.mgr.IDForName("tenant-new"); ok {
					sids.headends[id] = tc.entries
				}
			}
			_, err := s.VrfAcAdd(context.Background(), connect.NewRequest(&v1.VrfAcAddRequest{
				// An interface that does not resolve fails the reconcile.
				Name: "tenant-new", Ac: &v1.VrfAc{InterfaceName: "eth9"},
			}))
			if err == nil {
				t.Fatal("ac-add with a failing reconcile succeeded")
			}
			if _, ok := s.mgr.Get("tenant-new"); ok != tc.keep {
				t.Errorf("VRF kept = %v, want %v", ok, tc.keep)
			}
		})
	}
}
