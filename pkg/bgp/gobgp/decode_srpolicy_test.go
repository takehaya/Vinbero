package gobgp

import (
	"net/netip"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// srPolicyPath builds a received IPv6 SR Policy path with the given
// distinguisher/color/endpoint and SR Policy tunnel sub-TLVs.
func srPolicyPath(t *testing.T, dist, color uint32, endpoint string, subTLVs ...gobgppkt.TunnelEncapSubTLVInterface) *apiutil.Path {
	t.Helper()
	ep := netip.MustParseAddr(endpoint)
	nlri, err := gobgppkt.NewSRPolicy(gobgppkt.RF_SR_POLICY_IPv6, gobgppkt.SRPolicyIPv6NLRILen, dist, color, ep.AsSlice())
	if err != nil {
		t.Fatalf("NewSRPolicy: %v", err)
	}
	var attrs []gobgppkt.PathAttributeInterface
	if len(subTLVs) > 0 {
		attrs = []gobgppkt.PathAttributeInterface{
			&gobgppkt.PathAttributeTunnelEncap{
				Value: []*gobgppkt.TunnelEncapTLV{{
					Type:  gobgppkt.TUNNEL_TYPE_SR_POLICY,
					Value: subTLVs,
				}},
			},
		}
	}
	return &apiutil.Path{Family: gobgppkt.RF_SR_POLICY_IPv6, Nlri: nlri, Attrs: attrs}
}

func typeB(t *testing.T, sid string) *gobgppkt.SegmentTypeB {
	t.Helper()
	return &gobgppkt.SegmentTypeB{SID: netip.MustParseAddr(sid).AsSlice()}
}

func TestDecodeSRPolicy(t *testing.T) {
	p := srPolicyPath(t, 1, 100, "2001:db8::2",
		gobgppkt.NewTunnelEncapSubTLVSRPreference(0, 200),
		&gobgppkt.TunnelEncapSubTLVSRSegmentList{
			Segments: []gobgppkt.TunnelEncapSubTLVInterface{
				typeB(t, "fd00:200:0:1::"),
				typeB(t, "fd00:200:0:2::"),
			},
		},
	)
	got := decodeSRPolicy(p)
	if got == nil {
		t.Fatal("decodeSRPolicy returned nil")
	}
	if got.Color != 100 || got.Endpoint != netip.MustParseAddr("2001:db8::2") {
		t.Errorf("key = {%d, %s}, want {100, 2001:db8::2}", got.Color, got.Endpoint)
	}
	if len(got.Candidates) != 1 {
		t.Fatalf("candidates = %d, want 1", len(got.Candidates))
	}
	cp := got.Candidates[0]
	if cp.Origin != bgp.OriginBGP || cp.Distinguisher != 1 || cp.Preference != 200 {
		t.Errorf("candidate meta = {%s, %d, %d}, want {bgp, 1, 200}", cp.Origin, cp.Distinguisher, cp.Preference)
	}
	want := []netip.Addr{netip.MustParseAddr("fd00:200:0:1::"), netip.MustParseAddr("fd00:200:0:2::")}
	if len(cp.SegmentList) != len(want) {
		t.Fatalf("segments = %v, want %v", cp.SegmentList, want)
	}
	for i := range want {
		if cp.SegmentList[i] != want[i] {
			t.Errorf("segment[%d] = %s, want %s", i, cp.SegmentList[i], want[i])
		}
	}
}

// Absent Preference sub-TLV -> RFC default of 100.
func TestDecodeSRPolicy_DefaultPreference(t *testing.T) {
	p := srPolicyPath(t, 7, 50, "2001:db8::9",
		&gobgppkt.TunnelEncapSubTLVSRSegmentList{
			Segments: []gobgppkt.TunnelEncapSubTLVInterface{typeB(t, "fd00:300::")},
		},
	)
	got := decodeSRPolicy(p)
	if got == nil || len(got.Candidates) != 1 {
		t.Fatalf("decodeSRPolicy = %+v", got)
	}
	if got.Candidates[0].Preference != bgp.SRPolicyDefaultPreference {
		t.Errorf("preference = %d, want %d", got.Candidates[0].Preference, bgp.SRPolicyDefaultPreference)
	}
}

// Non-Type-B segments (I/J/K, or here a Type A stand-in) are skipped.
func TestDecodeSRPolicy_SkipNonTypeB(t *testing.T) {
	p := srPolicyPath(t, 1, 100, "2001:db8::2",
		&gobgppkt.TunnelEncapSubTLVSRSegmentList{
			Segments: []gobgppkt.TunnelEncapSubTLVInterface{
				&gobgppkt.SegmentTypeA{Label: 16000}, // unsupported -> skip
				typeB(t, "fd00:200:0:1::"),
			},
		},
	)
	got := decodeSRPolicy(p)
	if got == nil || len(got.Candidates) != 1 {
		t.Fatalf("decodeSRPolicy = %+v", got)
	}
	segs := got.Candidates[0].SegmentList
	if len(segs) != 1 || segs[0] != netip.MustParseAddr("fd00:200:0:1::") {
		t.Errorf("segments = %v, want [fd00:200:0:1::]", segs)
	}
}

// A non-IPv6 (IPv4) transport SID makes the whole segment list unusable: the
// candidate must end up with empty segments so it is ineligible rather than
// installed with a wrong path.
func TestDecodeSRPolicy_RejectsNonIPv6SID(t *testing.T) {
	p := srPolicyPath(t, 1, 100, "2001:db8::2",
		&gobgppkt.TunnelEncapSubTLVSRSegmentList{
			Segments: []gobgppkt.TunnelEncapSubTLVInterface{
				typeB(t, "fd00:200:0:1::"),
				typeB(t, "10.0.0.1"), // IPv4 SID -> invalidates the list
			},
		},
	)
	got := decodeSRPolicy(p)
	if got == nil || len(got.Candidates) != 1 {
		t.Fatalf("decodeSRPolicy = %+v", got)
	}
	if segs := got.Candidates[0].SegmentList; len(segs) != 0 {
		t.Errorf("segments = %v, want empty (ineligible candidate)", segs)
	}
}

// Multiple Segment List sub-TLVs (weighted ECMP): only the first wins.
// The single-list view is the FIRST list, not an arbitrary one: it is what
// gets programmed today, so which list it names is observable. The other
// lists are no longer discarded (see the weighted tests below) -- this pins
// only which one leads.
func TestDecodeSRPolicy_FirstSegmentListLeads(t *testing.T) {
	p := srPolicyPath(t, 1, 100, "2001:db8::2",
		&gobgppkt.TunnelEncapSubTLVSRSegmentList{
			Segments: []gobgppkt.TunnelEncapSubTLVInterface{typeB(t, "fd00:200:0:1::")},
		},
		&gobgppkt.TunnelEncapSubTLVSRSegmentList{
			Segments: []gobgppkt.TunnelEncapSubTLVInterface{typeB(t, "fd00:200:0:99::")},
		},
	)
	got := decodeSRPolicy(p)
	if got == nil || len(got.Candidates) != 1 {
		t.Fatalf("decodeSRPolicy = %+v", got)
	}
	segs := got.Candidates[0].SegmentList
	if len(segs) != 1 || segs[0] != netip.MustParseAddr("fd00:200:0:1::") {
		t.Errorf("segments = %v, want the first list [fd00:200:0:1::]", segs)
	}
	if n := len(got.Candidates[0].SegmentLists); n != 2 {
		t.Errorf("decoded %d lists, want both retained", n)
	}
}

// A non-SR-Policy NLRI yields nil so the caller skips it.
func TestDecodeSRPolicy_NotSRPolicyNLRI(t *testing.T) {
	nlri, err := gobgppkt.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	if err != nil {
		t.Fatalf("NewIPAddrPrefix: %v", err)
	}
	p := &apiutil.Path{Family: gobgppkt.RF_SR_POLICY_IPv6, Nlri: nlri}
	if got := decodeSRPolicy(p); got != nil {
		t.Errorf("decodeSRPolicy(non-SR-Policy NLRI) = %+v, want nil", got)
	}
}

// An IPv4 endpoint on the IPv6 SR Policy family is rejected: it could
// never match the always-IPv6 VPN next hop, so the policy must not decode.
func TestDecodeSRPolicy_RejectsIPv4Endpoint(t *testing.T) {
	nlri, err := gobgppkt.NewSRPolicy(gobgppkt.RF_SR_POLICY_IPv6, gobgppkt.SRPolicyIPv6NLRILen, 1, 100, []byte{10, 0, 0, 1})
	if err != nil {
		t.Fatalf("NewSRPolicy: %v", err)
	}
	p := &apiutil.Path{Family: gobgppkt.RF_SR_POLICY_IPv6, Nlri: nlri}
	if got := decodeSRPolicy(p); got != nil {
		t.Errorf("decodeSRPolicy(IPv4 endpoint) = %+v, want nil", got)
	}
}

// A withdrawal carries the NLRI key but no attributes: the candidate
// comes back with the default preference and no segments, enough for the
// applier to remove it by {color, endpoint, distinguisher}.
func TestDecodeSRPolicy_Withdraw(t *testing.T) {
	p := srPolicyPath(t, 3, 100, "2001:db8::2") // no sub-TLVs
	got := decodeSRPolicy(p)
	if got == nil || len(got.Candidates) != 1 {
		t.Fatalf("decodeSRPolicy = %+v", got)
	}
	if got.Candidates[0].Distinguisher != 3 || len(got.Candidates[0].SegmentList) != 0 {
		t.Errorf("withdraw candidate = %+v, want dist 3 and no segments", got.Candidates[0])
	}
}

// segList builds a Segment List sub-TLV. weight 0 means "no Weight sub-TLV
// at all"; use segListExplicitWeight to emit one carrying a given value,
// including 0, which is a different thing on the wire.
func segList(t *testing.T, weight uint32, sids ...string) *gobgppkt.TunnelEncapSubTLVSRSegmentList {
	t.Helper()
	sl := &gobgppkt.TunnelEncapSubTLVSRSegmentList{}
	for _, sid := range sids {
		sl.Segments = append(sl.Segments, typeB(t, sid))
	}
	if weight != 0 {
		sl.Weight = &gobgppkt.SegmentListWeight{Weight: weight}
	}
	return sl
}

func segListExplicitWeight(t *testing.T, weight uint32, sids ...string) *gobgppkt.TunnelEncapSubTLVSRSegmentList {
	t.Helper()
	sl := segList(t, 0, sids...)
	sl.Weight = &gobgppkt.SegmentListWeight{Weight: weight}
	return sl
}

// A candidate path may carry several Segment Lists, which together form a
// weighted ECMP set (RFC 9256 2.2). The decoder used to keep only the first
// and discard the rest.
func TestDecodeSRPolicy_MultipleWeightedSegmentLists(t *testing.T) {
	p := srPolicyPath(t, 1, 100, "2001:db8::2",
		segList(t, 1, "fd00:1::1"),
		segList(t, 3, "fd00:2::1", "fd00:2::2"),
	)
	got := decodeSRPolicy(p)
	if got == nil {
		t.Fatal("decodeSRPolicy returned nil")
	}
	cp := got.Candidates[0]
	if len(cp.SegmentLists) != 2 {
		t.Fatalf("decoded %d lists, want 2", len(cp.SegmentLists))
	}
	if cp.SegmentLists[0].Weight != 1 || cp.SegmentLists[1].Weight != 3 {
		t.Errorf("weights = %d,%d want 1,3",
			cp.SegmentLists[0].Weight, cp.SegmentLists[1].Weight)
	}
	if len(cp.SegmentLists[1].Segments) != 2 {
		t.Errorf("second list segments = %v", cp.SegmentLists[1].Segments)
	}
	// The single-list view stays the first list, which is what is programmed
	// until the data plane selects over the set.
	if len(cp.SegmentList) != 1 || cp.SegmentList[0].String() != "fd00:1::1" {
		t.Errorf("SegmentList = %v, want the first list", cp.SegmentList)
	}
}

// RFC 9256 leaves an absent Weight sub-TLV to the implementation. Reading it
// as zero would retire the list from the ECMP set, which is the opposite of
// what every deployment means by omitting it.
func TestDecodeSRPolicy_AbsentWeightIsAnEqualShare(t *testing.T) {
	p := srPolicyPath(t, 1, 100, "2001:db8::2",
		segList(t, 0, "fd00:1::1"),
		segList(t, 0, "fd00:2::1"),
	)
	cp := decodeSRPolicy(p).Candidates[0]
	if len(cp.SegmentLists) != 2 {
		t.Fatalf("decoded %d lists, want 2", len(cp.SegmentLists))
	}
	for i, l := range cp.SegmentLists {
		if l.Weight != bgp.SRPolicyDefaultWeight {
			t.Errorf("list %d weight = %d, want the default %d",
				i, l.Weight, bgp.SRPolicyDefaultWeight)
		}
	}
}

// One bad list must not take the usable ones with it: they are independent
// statements about how to reach the same endpoint.
func TestDecodeSRPolicy_MalformedListDropsOnlyItself(t *testing.T) {
	bad := &gobgppkt.TunnelEncapSubTLVSRSegmentList{
		Segments: []gobgppkt.TunnelEncapSubTLVInterface{
			// An IPv4 SID cannot be an SRv6 transport SID.
			&gobgppkt.SegmentTypeB{SID: netip.MustParseAddr("10.0.0.1").AsSlice()},
		},
	}
	p := srPolicyPath(t, 1, 100, "2001:db8::2", bad, segList(t, 2, "fd00:2::1"))
	cp := decodeSRPolicy(p).Candidates[0]
	if len(cp.SegmentLists) != 1 {
		t.Fatalf("decoded %d lists, want only the usable one", len(cp.SegmentLists))
	}
	if cp.SegmentLists[0].Weight != 2 {
		t.Errorf("surviving list weight = %d, want 2", cp.SegmentLists[0].Weight)
	}
	if len(cp.SegmentList) != 1 {
		t.Errorf("SegmentList = %v, want the surviving list", cp.SegmentList)
	}
}

// With every list unusable the candidate must still come out ineligible,
// which is the behaviour the single-list decoder had.
func TestDecodeSRPolicy_AllListsUnusableLeavesNoSegments(t *testing.T) {
	bad := &gobgppkt.TunnelEncapSubTLVSRSegmentList{
		Segments: []gobgppkt.TunnelEncapSubTLVInterface{
			&gobgppkt.SegmentTypeB{SID: netip.MustParseAddr("10.0.0.1").AsSlice()},
		},
	}
	cp := decodeSRPolicy(srPolicyPath(t, 1, 100, "2001:db8::2", bad)).Candidates[0]
	if len(cp.SegmentLists) != 0 || len(cp.SegmentList) != 0 {
		t.Errorf("expected no usable segments, got lists=%v single=%v",
			cp.SegmentLists, cp.SegmentList)
	}
}

// A list naming no usable segment carries no path. Treating it as an
// empty-but-valid list would install a policy that encapsulates to nothing.
func TestDecodeSRPolicy_EmptyListIsNotUsable(t *testing.T) {
	empty := &gobgppkt.TunnelEncapSubTLVSRSegmentList{}
	cp := decodeSRPolicy(srPolicyPath(t, 1, 100, "2001:db8::2", empty, segList(t, 1, "fd00:2::1"))).Candidates[0]
	if len(cp.SegmentLists) != 1 {
		t.Fatalf("decoded %d lists, want only the non-empty one", len(cp.SegmentLists))
	}
}

// RFC 9256 declares a segment list invalid when "its weight is 0", which is
// the advertiser withdrawing that list from the ECMP set. It is NOT the same
// as omitting the Weight sub-TLV, where the default of 1 applies. Reading an
// explicit 0 as the default would put a list the sender disabled back into
// service -- and if it came first, that is the list actually programmed.
func TestDecodeSRPolicy_ExplicitZeroWeightInvalidatesTheList(t *testing.T) {
	t.Run("zero-weight list is dropped", func(t *testing.T) {
		p := srPolicyPath(t, 1, 100, "2001:db8::2",
			segListExplicitWeight(t, 0, "fd00:1::1"),
			segList(t, 2, "fd00:2::1"),
		)
		cp := decodeSRPolicy(p).Candidates[0]
		if len(cp.SegmentLists) != 1 {
			t.Fatalf("decoded %d lists, want only the non-zero-weight one", len(cp.SegmentLists))
		}
		if cp.SegmentLists[0].Weight != 2 {
			t.Errorf("surviving weight = %d, want 2", cp.SegmentLists[0].Weight)
		}
		// The disabled list came first, so this is what would have been
		// programmed had the zero been read as a default.
		if len(cp.SegmentList) != 1 || cp.SegmentList[0].String() != "fd00:2::1" {
			t.Errorf("SegmentList = %v, want the enabled list", cp.SegmentList)
		}
	})

	t.Run("an absent sub-TLV still means an equal share", func(t *testing.T) {
		cp := decodeSRPolicy(srPolicyPath(t, 1, 100, "2001:db8::2",
			segList(t, 0, "fd00:1::1"))).Candidates[0]
		if len(cp.SegmentLists) != 1 {
			t.Fatalf("decoded %d lists, want the list kept", len(cp.SegmentLists))
		}
		if cp.SegmentLists[0].Weight != bgp.SRPolicyDefaultWeight {
			t.Errorf("weight = %d, want the default %d",
				cp.SegmentLists[0].Weight, bgp.SRPolicyDefaultWeight)
		}
	})

	t.Run("every list disabled leaves the candidate ineligible", func(t *testing.T) {
		cp := decodeSRPolicy(srPolicyPath(t, 1, 100, "2001:db8::2",
			segListExplicitWeight(t, 0, "fd00:1::1"))).Candidates[0]
		if len(cp.SegmentLists) != 0 || len(cp.SegmentList) != 0 {
			t.Errorf("expected no usable segments, got lists=%v single=%v",
				cp.SegmentLists, cp.SegmentList)
		}
	})
}
