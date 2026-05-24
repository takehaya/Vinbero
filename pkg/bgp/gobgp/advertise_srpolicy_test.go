package gobgp

import (
	"net/netip"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

func advSRPolicy(color, dist, pref uint32, endpoint, nh string, sids ...string) bgp.SRPolicy {
	segs := make([]netip.Addr, len(sids))
	for i, s := range sids {
		segs[i] = netip.MustParseAddr(s)
	}
	return bgp.SRPolicy{
		Color:            color,
		Endpoint:         netip.MustParseAddr(endpoint),
		AdvertiseNextHop: netip.MustParseAddr(nh),
		Candidates: []bgp.CandidatePath{{
			Origin: bgp.OriginLocal, Distinguisher: dist, Preference: pref, SegmentList: segs,
		}},
	}
}

// Encoding a local SR Policy then serializing the path to the wire and
// decoding it back through the receive path must reproduce the original
// {color, endpoint, distinguisher, preference, segments}. This proves the
// Tunnel Encapsulation attribute and NLRI serialize to valid RFC 9830 wire
// bytes (encode is the inverse of decode).
func TestEncodeSRPolicyPath_RoundTrip(t *testing.T) {
	in := advSRPolicy(100, 1, 200, "2001:db8::2", "2001:db8::1",
		"fd00:200:0:1::", "fd00:200:0:2::")

	path, err := encodeSRPolicyPath(in)
	if err != nil {
		t.Fatalf("encodeSRPolicyPath: %v", err)
	}

	// Serialize the SR Policy Tunnel Encapsulation attribute and decode it
	// back from the wire bytes.
	var teRaw []byte
	for _, a := range path.Attrs {
		te, ok := a.(*gobgppkt.PathAttributeTunnelEncap)
		if !ok {
			continue
		}
		b, serr := te.Serialize()
		if serr != nil {
			t.Fatalf("serialize tunnel encap: %v", serr)
		}
		teRaw = b
	}
	if teRaw == nil {
		t.Fatal("encoded path has no Tunnel Encapsulation attribute")
	}
	te2 := &gobgppkt.PathAttributeTunnelEncap{}
	if err := te2.DecodeFromBytes(teRaw); err != nil {
		t.Fatalf("decode tunnel encap from wire: %v", err)
	}

	// Reassemble a received-style path (original NLRI + wire-decoded attr)
	// and run the receive decoder.
	got := decodeSRPolicy(&apiutil.Path{Family: gobgppkt.RF_SR_POLICY_IPv6, Nlri: path.Nlri, Attrs: []gobgppkt.PathAttributeInterface{te2}})
	if got == nil {
		t.Fatal("decodeSRPolicy returned nil for an encoded path")
	}
	if got.Color != 100 || got.Endpoint != netip.MustParseAddr("2001:db8::2") {
		t.Errorf("key = {%d, %s}, want {100, 2001:db8::2}", got.Color, got.Endpoint)
	}
	if len(got.Candidates) != 1 {
		t.Fatalf("candidates = %d, want 1", len(got.Candidates))
	}
	cp := got.Candidates[0]
	if cp.Distinguisher != 1 || cp.Preference != 200 {
		t.Errorf("candidate meta = {dist %d, pref %d}, want {1, 200}", cp.Distinguisher, cp.Preference)
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

func TestEncodeSRPolicyPath_Rejects(t *testing.T) {
	cases := map[string]bgp.SRPolicy{
		"ipv4 endpoint": {
			Color: 1, Endpoint: netip.MustParseAddr("10.0.0.1"), AdvertiseNextHop: netip.MustParseAddr("2001:db8::1"),
			Candidates: []bgp.CandidatePath{{Distinguisher: 1, SegmentList: []netip.Addr{netip.MustParseAddr("fd00::1")}}},
		},
		"ipv4 next hop": {
			Color: 1, Endpoint: netip.MustParseAddr("2001:db8::2"), AdvertiseNextHop: netip.MustParseAddr("10.0.0.1"),
			Candidates: []bgp.CandidatePath{{Distinguisher: 1, SegmentList: []netip.Addr{netip.MustParseAddr("fd00::1")}}},
		},
		"no segments": {
			Color: 1, Endpoint: netip.MustParseAddr("2001:db8::2"), AdvertiseNextHop: netip.MustParseAddr("2001:db8::1"),
			Candidates: []bgp.CandidatePath{{Distinguisher: 1}},
		},
		"no candidate": {
			Color: 1, Endpoint: netip.MustParseAddr("2001:db8::2"), AdvertiseNextHop: netip.MustParseAddr("2001:db8::1"),
		},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := encodeSRPolicyPath(p); err == nil {
				t.Errorf("expected encodeSRPolicyPath to reject %q", name)
			}
		})
	}
}

func TestSRPolicyAdvKey_Distinct(t *testing.T) {
	a := srPolicyAdvKey(100, netip.MustParseAddr("2001:db8::2"), 1)
	b := srPolicyAdvKey(100, netip.MustParseAddr("2001:db8::2"), 2)
	c := srPolicyAdvKey(200, netip.MustParseAddr("2001:db8::2"), 1)
	if a == b || a == c || b == c {
		t.Errorf("distinct {color,endpoint,dist} produced colliding keys: %v %v %v", a, b, c)
	}
	if a.Family != bgp.FamilySRPolicyIPv6 {
		t.Errorf("adv key family = %v, want SR Policy IPv6", a.Family)
	}
}
