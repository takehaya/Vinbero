package gobgp

import (
	"context"
	"net/netip"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"go.uber.org/zap"

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

// Advertising a local SR Policy through a started gobgp session must be
// accepted into the RIB (a malformed MP_REACH / NLRI / Tunnel Encap would
// make AddPath fail here), tracked for withdrawal, superseded on
// re-advertise, and removed on withdraw. Exercises the live gobgp path,
// not just the offline encoder. No root or peer required.
func (s *Session) advertisedLen() int {
	s.advMu.Lock()
	defer s.advMu.Unlock()
	return len(s.advertised)
}

func TestSession_AdvertiseSRPolicyLifecycle(t *testing.T) {
	s := NewSession(zap.NewNop())
	ctx := context.Background()
	if err := s.Start(ctx, bgp.GlobalConfig{LocalASN: 65100, RouterID: "10.255.0.9", ListenPort: 10251}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = s.Stop(ctx) })

	p := advSRPolicy(100, 1, 200, "2001:db8::2", "2001:db8::1", "fd00:200:0:1::", "fd00:200:0:2::")
	if err := s.PushPolicy(ctx, p); err != nil {
		t.Fatalf("PushPolicy (gobgp rejected the encoded SR Policy path): %v", err)
	}
	if n := s.advertisedLen(); n != 1 {
		t.Fatalf("advertised entries = %d, want 1", n)
	}

	// Re-advertising the same {color, endpoint, distinguisher} supersedes the
	// prior path rather than leaving an orphan.
	if err := s.PushPolicy(ctx, p); err != nil {
		t.Fatalf("re-advertise PushPolicy: %v", err)
	}
	if n := s.advertisedLen(); n != 1 {
		t.Errorf("after re-advertise advertised entries = %d, want 1", n)
	}

	key := bgp.SRPolicyKey{Color: 100, Endpoint: netip.MustParseAddr("2001:db8::2"), Distinguisher: 1}
	if err := s.WithdrawPolicy(ctx, key); err != nil {
		t.Fatalf("WithdrawPolicy: %v", err)
	}
	if n := s.advertisedLen(); n != 0 {
		t.Errorf("after withdraw advertised entries = %d, want 0", n)
	}
	// Withdrawing again is a no-op.
	if err := s.WithdrawPolicy(ctx, key); err != nil {
		t.Errorf("idempotent WithdrawPolicy: %v", err)
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
