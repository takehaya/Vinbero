package server

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/vrf"
)

// One trigger prefix in the global VRF and in two named VRFs, through the
// RPCs: three entries, listed with their VRF, read and removed one VRF at
// a time, flushed per VRF. A request without vrf_name is the global VRF,
// written under the same key the prefix-only map API uses.
func TestHeadendv4RPCSamePrefixAcrossVRFs(t *testing.T) {
	ctx := context.Background()
	m := headendRPCMapOps(t)
	t.Cleanup(func() { _, _ = m.ForceFlushHeadendV4() })
	mgr := vrf.NewManager()
	a, _ := mgr.Ensure("tenant-a")
	b, _ := mgr.Ensure("tenant-b")
	s := NewHeadendv4Server(m, mgr)
	const prefix = "10.20.0.0/16"
	mk := func(vrfName, seg string) *v1.Headendv4 {
		return &v1.Headendv4{
			Mode: v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS, TriggerPrefix: prefix,
			SrcAddr: "fc00::1", DstAddr: "::", Segments: []string{seg}, VrfName: vrfName,
		}
	}
	created, err := s.Headendv4Create(ctx, connect.NewRequest(&v1.Headendv4CreateRequest{Headendv4S: []*v1.Headendv4{
		mk("", "fc00:a::1"), mk("tenant-a", "fc00:b::1"), mk("tenant-b", "fc00:c::1"),
	}}))
	if err != nil || len(created.Msg.Errors) != 0 || len(created.Msg.Created) != 3 {
		t.Fatalf("create: %v %v", created, err)
	}
	if c := created.Msg.Created; c[0].VrfId != 0 || c[1].VrfId != a.ID || c[2].VrfId != b.ID || c[1].VrfName != "tenant-a" {
		t.Errorf("created = %v", c)
	}
	// "global" names the same entry as no name.
	if again, err := s.Headendv4Create(ctx, connect.NewRequest(&v1.Headendv4CreateRequest{Headendv4S: []*v1.Headendv4{mk("global", "fc00:a::1")}})); err != nil || len(again.Msg.Errors) != 0 {
		t.Fatalf("create in global: %v %v", again, err)
	}
	ids, err := m.ListHeadendV4IDs()
	if err != nil || len(ids) != 3 || ids[bpf.HeadendID{VRF: 0, Prefix: prefix}] == nil {
		t.Fatalf("map ids = %v %v", ids, err)
	}
	if e, err := m.GetHeadendV4(prefix); err != nil || bpf.FormatSegments(e.Segments, e.NumSegments)[0] != "fc00:a::1" {
		t.Errorf("prefix-only read of the request without vrf_name = %v %v", e, err)
	}

	list, err := s.Headendv4List(ctx, connect.NewRequest(&v1.Headendv4ListRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, h := range list.Msg.Headendv4S {
		got[h.VrfName] = h.Segments[0]
		if h.TriggerPrefix != prefix {
			t.Errorf("listed %s", h.TriggerPrefix)
		}
	}
	if len(got) != 3 || got[""] != "fc00:a::1" || got["tenant-a"] != "fc00:b::1" || got["tenant-b"] != "fc00:c::1" {
		t.Errorf("list = %v", got)
	}
	for name, seg := range map[string]string{"global": "fc00:a::1", "tenant-a": "fc00:b::1"} {
		only, err := s.Headendv4List(ctx, connect.NewRequest(&v1.Headendv4ListRequest{VrfName: name}))
		if err != nil || len(only.Msg.Headendv4S) != 1 || only.Msg.Headendv4S[0].Segments[0] != seg {
			t.Errorf("list --vrf %s = %v %v", name, only, err)
		}
		g, err := s.Headendv4Get(ctx, connect.NewRequest(&v1.Headendv4GetRequest{TriggerPrefix: prefix, VrfName: name}))
		if err != nil || g.Msg.Headendv4.Segments[0] != seg {
			t.Errorf("get --vrf %s = %v %v", name, g, err)
		}
	}

	del, err := s.Headendv4Delete(ctx, connect.NewRequest(&v1.Headendv4DeleteRequest{TriggerPrefixes: []string{prefix}, VrfName: "tenant-a"}))
	if err != nil || len(del.Msg.DeletedTriggerPrefixes) != 1 {
		t.Fatalf("delete tenant-a: %v %v", del, err)
	}
	if _, err := s.Headendv4Get(ctx, connect.NewRequest(&v1.Headendv4GetRequest{TriggerPrefix: prefix, VrfName: "tenant-a"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("get of the deleted tenant-a entry: %v", err)
	}
	if n, err := m.HeadendEntriesInVRF(b.ID); err != nil || n != 1 {
		t.Errorf("tenant-b entries = %d %v", n, err)
	}
	flush, err := s.Headendv4Flush(ctx, connect.NewRequest(&v1.Headendv4FlushRequest{VrfName: "tenant-b"}))
	if err != nil || flush.Msg.DeletedCount != 1 {
		t.Fatalf("flush tenant-b: %v %v", flush, err)
	}
	ids, _ = m.ListHeadendV4IDs()
	if len(ids) != 1 || ids[bpf.HeadendID{VRF: 0, Prefix: prefix}] == nil {
		t.Errorf("after the tenant deletes: %v, want the global entry alone", ids)
	}
	flush, err = s.Headendv4Flush(ctx, connect.NewRequest(&v1.Headendv4FlushRequest{}))
	if err != nil || flush.Msg.DeletedCount != 1 {
		t.Fatalf("flush: %v %v", flush, err)
	}
}

// The IPv6 counterpart, shorter: the same prefix in two VRFs coexists and
// is removed per VRF.
func TestHeadendv6RPCSamePrefixAcrossVRFs(t *testing.T) {
	ctx := context.Background()
	m := headendRPCMapOps(t)
	t.Cleanup(func() { _, _ = m.ForceFlushHeadendV6() })
	mgr := vrf.NewManager()
	a, _ := mgr.Ensure("tenant-a")
	s := NewHeadendv6Server(m, mgr)
	const prefix = "2001:db8:20::/48"
	mk := func(vrfName, seg string) *v1.Headendv6 {
		return &v1.Headendv6{
			Mode: v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS, TriggerPrefix: prefix,
			SrcAddr: "fc00::1", DstAddr: "::", Segments: []string{seg}, VrfName: vrfName,
		}
	}
	created, err := s.Headendv6Create(ctx, connect.NewRequest(&v1.Headendv6CreateRequest{Headendv6S: []*v1.Headendv6{
		mk("", "fc00:a::1"), mk("tenant-a", "fc00:b::1"),
	}}))
	if err != nil || len(created.Msg.Errors) != 0 {
		t.Fatalf("create: %v %v", created, err)
	}
	list, err := s.Headendv6List(ctx, connect.NewRequest(&v1.Headendv6ListRequest{}))
	if err != nil || len(list.Msg.Headendv6S) != 2 {
		t.Fatalf("list: %v %v", list, err)
	}
	for _, h := range list.Msg.Headendv6S {
		if (h.VrfId == a.ID) != (h.VrfName == "tenant-a") {
			t.Errorf("listed %v", h)
		}
	}
	if del, err := s.Headendv6Delete(ctx, connect.NewRequest(&v1.Headendv6DeleteRequest{TriggerPrefixes: []string{prefix}})); err != nil || len(del.Msg.DeletedTriggerPrefixes) != 1 {
		t.Fatalf("delete global: %v %v", del, err)
	}
	g, err := s.Headendv6Get(ctx, connect.NewRequest(&v1.Headendv6GetRequest{TriggerPrefix: prefix, VrfName: "tenant-a"}))
	if err != nil || g.Msg.Headendv6.Segments[0] != "fc00:b::1" || g.Msg.Headendv6.VrfId != a.ID {
		t.Errorf("tenant-a entry after the global delete = %v %v", g, err)
	}
}
