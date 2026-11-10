package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/vrf"
)

// A headend request naming a VRF that does not exist is refused before any
// map is touched (the servers here have none), and creates no VRF: Create
// per entry, the other RPCs as NotFound. A vrf_id that does not match the
// VRF named is refused; vrf_name and all_vrfs together are refused.
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
		{Mode: v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS, TriggerPrefix: "10.0.0.0/24", SrcAddr: "fc00::1", Segments: []string{"fc00::2"}, VrfName: "tenant-a", VrfId: 9},
	}}))
	if err != nil || len(c4.Msg.Created) != 0 || len(c4.Msg.Errors) != 3 ||
		!strings.Contains(c4.Msg.Errors[0].Reason, "unknown VRF") ||
		!strings.Contains(c4.Msg.Errors[1].Reason, "does not match") ||
		!strings.Contains(c4.Msg.Errors[2].Reason, "does not match") {
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
	for what, err := range map[string]error{
		"v4 list": func() error {
			_, err := s4.Headendv4List(ctx, connect.NewRequest(&v1.Headendv4ListRequest{VrfName: "tenant-a", AllVrfs: true}))
			return err
		}(),
		"v4 flush": func() error {
			_, err := s4.Headendv4Flush(ctx, connect.NewRequest(&v1.Headendv4FlushRequest{VrfName: "tenant-a", AllVrfs: true}))
			return err
		}(),
		"v6 list": func() error {
			_, err := s6.Headendv6List(ctx, connect.NewRequest(&v1.Headendv6ListRequest{VrfName: "global", AllVrfs: true}))
			return err
		}(),
		"v6 flush": func() error {
			_, err := s6.Headendv6Flush(ctx, connect.NewRequest(&v1.Headendv6FlushRequest{VrfName: "global", AllVrfs: true}))
			return err
		}(),
	} {
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s with vrf_name and all_vrfs: %v, want InvalidArgument", what, err)
		}
	}

	// A server with no VRF directory takes the global VRF only.
	bare := NewHeadendv4Server(nil, nil)
	_, err = bare.Headendv4Get(ctx, connect.NewRequest(&v1.Headendv4GetRequest{TriggerPrefix: "10.0.0.0/24", VrfName: "tenant-a"}))
	notFound(t, "get without a VRF directory", err)
}

// resolveHeadendVRF holds a named VRF against the start of its deletion
// until the write is done, and takes no hold for the global VRF.
func TestResolveHeadendVRFHoldsTheVRF(t *testing.T) {
	mgr := vrf.NewManager()
	a, err := mgr.Ensure("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	noop := func(uint32) error { return nil }
	for _, name := range []string{"", vrf.GlobalVRFName} {
		id, release, err := resolveHeadendVRF(mgr, name, true)
		if err != nil || id != 0 {
			t.Fatalf("resolve %q = %d %v", name, id, err)
		}
		// Would block if a hold were taken; tenant-b does not exist.
		if _, err := mgr.StartDelete("tenant-b", noop); err != nil {
			t.Fatal(err)
		}
		release()
	}
	id, release, err := resolveHeadendVRF(mgr, "tenant-a", true)
	if err != nil || id != a.ID {
		t.Fatalf("resolve tenant-a = %d %v", id, err)
	}
	started := make(chan struct{})
	go func() {
		abort, _ := mgr.StartDelete("tenant-a", noop)
		close(started)
		abort()
	}()
	select {
	case <-started:
		t.Fatal("a VRF delete started between a headend write's lookup and its write")
	case <-time.After(50 * time.Millisecond):
	}
	release()
	<-started
}

func vrfWithDevice(t *testing.T, s *VrfServer, name string) uint32 {
	t.Helper()
	resp, err := s.VrfCreate(context.Background(), connect.NewRequest(&v1.VrfCreateRequest{Vrfs: []*v1.Vrf{{Name: name, TableId: 100}}}))
	if err != nil || len(resp.Msg.Errors) != 0 {
		t.Fatalf("vrf create: %v %v", resp, err)
	}
	return resp.Msg.Created[0].VrfId
}

func deleteVRF(t *testing.T, s *VrfServer, name string) *v1.VrfDeleteResponse {
	t.Helper()
	resp, err := s.VrfDelete(context.Background(), connect.NewRequest(&v1.VrfDeleteRequest{Names: []string{name}}))
	if err != nil {
		t.Fatal(err)
	}
	return resp.Msg
}

// A VRF holding headend state an API can show or remove is not deleted,
// as one holding ACs or a binding is not, and the refusal says per owner
// what removes it. Owner records of other owners left without an entry
// do not block; they go with the VRF.
func TestVrfDeleteRefusesWhileHeadendEntriesRemain(t *testing.T) {
	s, _, _ := newTestVrfServerFull()
	id := vrfWithDevice(t, s, "tenant-a")
	sids := &fakeSidTable{headends: map[uint32]bpf.HeadendVRFRefs{id: {
		Entries: map[bpf.OwnerTag]int{bpf.OwnerRPC: 2, bpf.OwnerPluginBundle("p1"): 1, "": 1},
		OwnerOnly: map[bpf.OwnerTag]int{bpf.OwnerRPC: 1, bpf.OwnerPluginBundle("p1"): 1,
			"bgp:v1:asn=65000:vpngroup": 1},
	}}}
	s.sids = sids
	sids.headendHook = func() {
		got := make(chan func(), 1)
		go func() { got <- s.mgr.HoldIDs() }()
		select {
		case r := <-got:
			r()
			t.Error("a headend write could hold the VRF during the delete's check")
		case <-time.After(50 * time.Millisecond):
			go func() { (<-got)() }()
		}
	}
	resp := deleteVRF(t, s, "tenant-a")
	if len(resp.DeletedNames) != 0 || len(resp.Errors) != 1 {
		t.Fatalf("delete with entries = %+v", resp)
	}
	reason := resp.Errors[0].Reason
	for _, want := range []string{
		"3 of the operator (headend-v4 / headend-v6 delete or flush --vrf tenant-a)",
		`2 of control-plane plugin "p1" (change its declaration, or cplane unregister --name p1)`,
		"1 with no owner (headend-v4 / headend-v6 flush --vrf tenant-a)",
	} {
		if !strings.Contains(reason, want) {
			t.Errorf("refusal %q lacks %q", reason, want)
		}
	}
	if strings.Contains(reason, "bgp:") {
		t.Errorf("refusal %q counts an owner record no API removes", reason)
	}
	if _, err := s.mgr.LookupID("tenant-a"); err != nil {
		t.Errorf("a refused delete left the VRF unresolvable: %v", err)
	}

	// With only the record no API removes left, the delete goes ahead and
	// takes it along.
	sids.headendHook = nil
	sids.headends[id] = bpf.HeadendVRFRefs{OwnerOnly: map[bpf.OwnerTag]int{"bgp:v1:asn=65000:vpngroup": 1}}
	resp = deleteVRF(t, s, "tenant-a")
	if len(resp.DeletedNames) != 1 || len(sids.purged) != 1 || sids.purged[0] != id {
		t.Fatalf("delete = %+v, purged %v", resp, sids.purged)
	}
}

// The slow part of a delete (device teardown, the state save) runs with
// no hold blocked: a headend write to another VRF goes ahead, and one to
// the VRF being deleted is refused as unknown instead of waiting.
func TestVrfDeleteDoesNotBlockHeadendWrites(t *testing.T) {
	s, _, dev := newTestVrfServerFull()
	vrfWithDevice(t, s, "tenant-a")
	if _, err := s.mgr.Ensure("tenant-b"); err != nil {
		t.Fatal(err)
	}
	s.sids = &fakeSidTable{}
	dev.deleteHook = func() {
		done := make(chan error, 1)
		go func() {
			release := s.mgr.HoldIDs()
			defer release()
			if _, err := s.mgr.LookupID("tenant-b"); err != nil {
				done <- err
				return
			}
			_, err := s.mgr.LookupID("tenant-a")
			if !errors.Is(err, vrf.ErrUnknownVRF) {
				done <- errors.New("tenant-a resolved during its deletion")
				return
			}
			done <- nil
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("a headend write waited for a VRF device teardown")
		}
	}
	if resp := deleteVRF(t, s, "tenant-a"); len(resp.DeletedNames) != 1 {
		t.Fatalf("delete = %+v", resp)
	}

	// A teardown that fails keeps the VRF resolvable.
	vrfWithDevice(t, s, "tenant-c")
	dev.deleteHook = nil
	dev.deleteErr = errors.New("netlink: busy")
	if resp := deleteVRF(t, s, "tenant-c"); len(resp.DeletedNames) != 0 {
		t.Fatalf("delete with a failing teardown = %+v", resp)
	}
	if _, err := s.mgr.LookupID("tenant-c"); err != nil {
		t.Errorf("a failed delete left the VRF unresolvable: %v", err)
	}
}

// A VrfAcAdd that created its VRF and then fails rolls the VRF back, unless
// a headend entry was written under its id in the meantime.
func TestVrfAcAddRollbackKeepsVRFWithHeadendEntries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries int
		keep    bool
	}{{"no entries", 0, false}, {"entries", 1, true}} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestVrfServer()
			sids := &fakeSidTable{headends: map[uint32]bpf.HeadendVRFRefs{}}
			s.sids = sids
			sids.headendHook = func() {
				if id, ok := s.mgr.IDForName("tenant-new"); ok && tc.entries > 0 {
					sids.headends[id] = bpf.HeadendVRFRefs{Entries: map[bpf.OwnerTag]int{bpf.OwnerRPC: tc.entries}}
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
