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

// Multiple Segment List sub-TLVs (weighted ECMP): only the first wins.
func TestDecodeSRPolicy_FirstSegmentListWins(t *testing.T) {
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
		t.Errorf("segments = %v, want first list only [fd00:200:0:1::]", segs)
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
