package server

import (
	"context"
	"slices"
	"sort"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"google.golang.org/protobuf/proto"
)

// sameMessages reports whether two lists hold equal messages in order.
func sameMessages[M proto.Message](a, b []M) bool {
	return slices.EqualFunc(a, b, func(x, y M) bool { return proto.Equal(x, y) })
}

func headendRPCMapOps(t *testing.T) *bpf.MapOperations {
	t.Helper()
	objs, err := bpf.ReadCollection(nil, nil)
	if err != nil {
		t.Skipf("BPF collection load failed (needs sudo): %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	return bpf.NewMapOperations(objs)
}

// The headend RPCs speak plain CIDRs over the {vrf_id, prefix} map key:
// what Create took is what List and Get return, with the address prefix
// length (not the stored one, which counts the VRF), and Delete and Flush
// take the same strings. The headend-group view reads the same prefixes.
func TestHeadendv4RPCRoundTrip(t *testing.T) {
	ctx := context.Background()
	m := headendRPCMapOps(t)
	s := NewHeadendv4Server(m)
	want := []*v1.Headendv4{
		{
			Mode:          v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS,
			TriggerPrefix: "10.1.2.0/24",
			SrcAddr:       "fc00::1",
			DstAddr:       "::",
			Segments:      []string{"fc00:2::1", "fc00:3::1"},
		},
		{
			Mode:          v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_RED,
			TriggerPrefix: "192.0.2.7/32",
			SrcAddr:       "fc00::1",
			DstAddr:       "::",
			Segments:      []string{"fc00:4::1"},
		},
		{
			Mode:          v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS,
			TriggerPrefix: "0.0.0.0/0",
			SrcAddr:       "fc00::1",
			DstAddr:       "::",
			Segments:      []string{"fc00:5::1"},
		},
	}
	created, err := s.Headendv4Create(ctx, connect.NewRequest(&v1.Headendv4CreateRequest{Headendv4S: want}))
	if err != nil || len(created.Msg.Errors) != 0 || len(created.Msg.Created) != len(want) {
		t.Fatalf("create: %v %v", created, err)
	}
	t.Cleanup(func() { _, _ = m.ForceFlushHeadendV4() })

	list, err := s.Headendv4List(ctx, connect.NewRequest(&v1.Headendv4ListRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	got := list.Msg.Headendv4S
	for _, l := range [][]*v1.Headendv4{want, got} {
		sort.Slice(l, func(i, j int) bool { return l[i].TriggerPrefix < l[j].TriggerPrefix })
	}
	if !sameMessages(want, got) {
		t.Errorf("list = %v, want %v", got, want)
	}
	for _, h := range want {
		resp, err := s.Headendv4Get(ctx, connect.NewRequest(&v1.Headendv4GetRequest{TriggerPrefix: h.TriggerPrefix}))
		if err != nil {
			t.Fatalf("get %s: %v", h.TriggerPrefix, err)
		}
		if !proto.Equal(h, resp.Msg.Headendv4) {
			t.Errorf("get %s = %v, want %v", h.TriggerPrefix, resp.Msg.Headendv4, h)
		}
	}

	del, err := s.Headendv4Delete(ctx, connect.NewRequest(&v1.Headendv4DeleteRequest{TriggerPrefixes: []string{"192.0.2.7/32"}}))
	if err != nil || len(del.Msg.Errors) != 0 || len(del.Msg.DeletedTriggerPrefixes) != 1 {
		t.Fatalf("delete: %v %v", del, err)
	}
	flush, err := s.Headendv4Flush(ctx, connect.NewRequest(&v1.Headendv4FlushRequest{}))
	if err != nil || flush.Msg.DeletedCount != 2 {
		t.Fatalf("flush: %v %v", flush, err)
	}
	list, err = s.Headendv4List(ctx, connect.NewRequest(&v1.Headendv4ListRequest{}))
	if err != nil || len(list.Msg.Headendv4S) != 0 {
		t.Fatalf("list after flush: %v %v", list, err)
	}
}

func TestHeadendv6RPCRoundTrip(t *testing.T) {
	ctx := context.Background()
	m := headendRPCMapOps(t)
	s := NewHeadendv6Server(m)
	want := []*v1.Headendv6{
		{
			Mode:          v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS,
			TriggerPrefix: "2001:db8::/64",
			SrcAddr:       "fc00::1",
			DstAddr:       "::",
			Segments:      []string{"fc00:2::1"},
		},
		{
			Mode:          v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS,
			TriggerPrefix: "2001:db8:1::1/128",
			SrcAddr:       "fc00::1",
			DstAddr:       "::",
			Segments:      []string{"fc00:3::1", "fc00:4::1"},
		},
	}
	created, err := s.Headendv6Create(ctx, connect.NewRequest(&v1.Headendv6CreateRequest{Headendv6S: want}))
	if err != nil || len(created.Msg.Errors) != 0 || len(created.Msg.Created) != len(want) {
		t.Fatalf("create: %v %v", created, err)
	}
	t.Cleanup(func() { _, _ = m.ForceFlushHeadendV6() })

	list, err := s.Headendv6List(ctx, connect.NewRequest(&v1.Headendv6ListRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	got := list.Msg.Headendv6S
	for _, l := range [][]*v1.Headendv6{want, got} {
		sort.Slice(l, func(i, j int) bool { return l[i].TriggerPrefix < l[j].TriggerPrefix })
	}
	if !sameMessages(want, got) {
		t.Errorf("list = %v, want %v", got, want)
	}
	for _, h := range want {
		resp, err := s.Headendv6Get(ctx, connect.NewRequest(&v1.Headendv6GetRequest{TriggerPrefix: h.TriggerPrefix}))
		if err != nil {
			t.Fatalf("get %s: %v", h.TriggerPrefix, err)
		}
		if !proto.Equal(h, resp.Msg.Headendv6) {
			t.Errorf("get %s = %v, want %v", h.TriggerPrefix, resp.Msg.Headendv6, h)
		}
	}

	// A group's trigger prefixes come from the same scan.
	const groupID = 9
	path := &bpf.HeadendEntry{Mode: uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS), NumSegments: 1}
	if err := m.PutEcmpGroup(groupID, []bpf.EcmpPath{{Entry: path, Weight: 1}}, bpf.OwnerRPC); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.DeleteEcmpGroup(groupID, bpf.OwnerRPC) })
	trigger := &bpf.HeadendEntry{Mode: path.Mode, GroupId: groupID}
	if err := m.CreateHeadendV6("2001:db8:2::/48", trigger, bpf.OwnerRPC); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateHeadendV4("10.9.0.0/16", trigger, bpf.OwnerRPC); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.ForceFlushHeadendV4() })
	prefixes, err := NewHeadendGroupServer(m).groupPrefixes()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.9.0.0/16", "2001:db8:2::/48"}; !slices.Equal(prefixes[groupID], want) {
		t.Errorf("group prefixes = %v, want %v", prefixes[groupID], want)
	}
}

// A trigger prefix of the other address family is refused before the map is
// touched: Create and Delete report it per prefix, Get as InvalidArgument.
func TestHeadendRPCRefusesOtherFamily(t *testing.T) {
	ctx := context.Background()
	s4, s6 := NewHeadendv4Server(nil), NewHeadendv6Server(nil)
	for _, p := range []string{"fd00::/64", "::ffff:10.0.0.0/120", "nonsense"} {
		c, err := s4.Headendv4Create(ctx, connect.NewRequest(&v1.Headendv4CreateRequest{Headendv4S: []*v1.Headendv4{{
			Mode: v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS, TriggerPrefix: p, SrcAddr: "fc00::1", Segments: []string{"fc00::2"},
		}}}))
		if err != nil || len(c.Msg.Created) != 0 || len(c.Msg.Errors) != 1 {
			t.Errorf("v4 create %s: %v %v", p, c, err)
		}
		d, err := s4.Headendv4Delete(ctx, connect.NewRequest(&v1.Headendv4DeleteRequest{TriggerPrefixes: []string{p}}))
		if err != nil || len(d.Msg.Errors) != 1 {
			t.Errorf("v4 delete %s: %v %v", p, d, err)
		}
		if _, err := s4.Headendv4Get(ctx, connect.NewRequest(&v1.Headendv4GetRequest{TriggerPrefix: p})); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("v4 get %s: %v, want InvalidArgument", p, err)
		}
	}
	for _, p := range []string{"10.0.0.0/8", "10.0.0.1", "nonsense"} {
		c, err := s6.Headendv6Create(ctx, connect.NewRequest(&v1.Headendv6CreateRequest{Headendv6S: []*v1.Headendv6{{
			Mode: v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS, TriggerPrefix: p, SrcAddr: "fc00::1", Segments: []string{"fc00::2"},
		}}}))
		if err != nil || len(c.Msg.Created) != 0 || len(c.Msg.Errors) != 1 {
			t.Errorf("v6 create %s: %v %v", p, c, err)
		}
		d, err := s6.Headendv6Delete(ctx, connect.NewRequest(&v1.Headendv6DeleteRequest{TriggerPrefixes: []string{p}}))
		if err != nil || len(d.Msg.Errors) != 1 {
			t.Errorf("v6 delete %s: %v %v", p, d, err)
		}
		if _, err := s6.Headendv6Get(ctx, connect.NewRequest(&v1.Headendv6GetRequest{TriggerPrefix: p})); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("v6 get %s: %v, want InvalidArgument", p, err)
		}
	}
}
