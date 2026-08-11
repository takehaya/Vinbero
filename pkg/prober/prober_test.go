package prober

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
)

type sentProbe struct {
	target Target
	token  uint16
	seq    uint16
	cookie uint64
}

type fakeWire struct {
	sent []sentProbe
}

func (f *fakeWire) send(t Target, token, seq uint16, cookie uint64) error {
	f.sent = append(f.sent, sentProbe{t, token, seq, cookie})
	return nil
}
func (f *fakeWire) recv() (uint16, uint16, uint64, netip.Addr, bool) {
	return 0, 0, 0, netip.Addr{}, false
}
func (f *fakeWire) close() {}

// reply answers one recorded probe as its destination would.
func reply(p *Prober, s sentProbe, now time.Time) {
	p.handleReply(s.token, s.seq, s.cookie, s.target.Dst, now)
}

type fakeLive struct {
	bitmaps map[uint32]uint64
	deleted []uint32
}

func newFakeLive() *fakeLive { return &fakeLive{bitmaps: map[uint32]uint64{}} }

func (f *fakeLive) SetEcmpLive(groupID uint32, bitmap uint64) error {
	f.bitmaps[groupID] = bitmap
	return nil
}
func (f *fakeLive) DeleteEcmpLive(groupID uint32) error {
	delete(f.bitmaps, groupID)
	f.deleted = append(f.deleted, groupID)
	return nil
}

func testProber(t *testing.T) (*Prober, *fakeWire, *fakeLive) {
	t.Helper()
	fw := &fakeWire{}
	fl := newFakeLive()
	p := newWithWire(fl, fw, Config{Interval: 100 * time.Millisecond, Multiplier: 3}, zap.NewNop())
	return p, fw, fl
}

func target(idx uint8, dst string, segs ...string) Target {
	t := Target{PathIndex: idx, Dst: netip.MustParseAddr(dst)}
	for _, s := range segs {
		t.Segments = append(t.Segments, netip.MustParseAddr(s))
	}
	return t
}

// replyAll answers the probes sent since the previous call.
func replyAll(p *Prober, fw *fakeWire, from int, now time.Time) int {
	for _, s := range fw.sent[from:] {
		reply(p, s, now)
	}
	return len(fw.sent)
}

func TestProber_RegisterInstallsAllUp(t *testing.T) {
	p, _, fl := testProber(t)
	p.Register(7, []Target{target(0, "fd00::2"), target(3, "fd00::3")})
	if got := fl.bitmaps[7]; got != 0b1001 {
		t.Fatalf("initial bitmap = %b, want paths 0 and 3 up", got)
	}
}

func TestProber_DownAfterMultiplierMisses(t *testing.T) {
	p, _, fl := testProber(t)
	p.Register(7, []Target{target(0, "fd00::2"), target(1, "fd00::3")})

	now := time.Unix(0, 0)
	// Round 1 sends; rounds 2..4 judge the previous silence. The path must
	// survive the first two judged misses (hysteresis) and fail on the
	// third.
	for i := 0; i < 3; i++ {
		p.tick(now)
		now = now.Add(100 * time.Millisecond)
		if got := fl.bitmaps[7]; got != 0b11 {
			t.Fatalf("round %d: bitmap = %b, want still all-up", i, got)
		}
	}
	p.tick(now)
	if got := fl.bitmaps[7]; got != 0 {
		t.Fatalf("after %d silent rounds: bitmap = %b, want all down", 4, got)
	}
}

func TestProber_AnsweredPathStaysUpAndRecovers(t *testing.T) {
	p, fw, fl := testProber(t)
	p.Register(9, []Target{target(0, "fd00::2"), target(1, "fd00::3")})

	now := time.Unix(0, 0)
	seen := 0
	// Path 0 answers every round, path 1 stays silent.
	for i := 0; i < 5; i++ {
		p.tick(now)
		for _, s := range fw.sent[seen:] {
			if s.target.PathIndex == 0 {
				reply(p, s, now)
			}
		}
		seen = len(fw.sent)
		now = now.Add(100 * time.Millisecond)
	}
	if got := fl.bitmaps[9]; got != 0b01 {
		t.Fatalf("bitmap = %b, want only path 0 up", got)
	}

	// Path 1 starts answering: three consecutive replies bring it back.
	for i := 0; i < 4; i++ {
		p.tick(now)
		seen = replyAll(p, fw, seen, now)
		now = now.Add(100 * time.Millisecond)
	}
	if got := fl.bitmaps[9]; got != 0b11 {
		t.Fatalf("bitmap = %b, want recovered", got)
	}
}

func TestProber_StaleSeqIgnored(t *testing.T) {
	p, fw, _ := testProber(t)
	p.Register(1, []Target{target(0, "fd00::2")})
	now := time.Unix(0, 0)
	p.tick(now)
	first := fw.sent[0]
	p.tick(now.Add(100 * time.Millisecond))
	p.tick(now.Add(200 * time.Millisecond))
	// A straggler from round 1 lands during round 3: two rounds stale, so
	// it must not count (the previous-round window is exactly one).
	reply(p, first, now.Add(250*time.Millisecond))
	p.mu.Lock()
	ps := p.tokens[first.token]
	seen := ps.replySeen
	p.mu.Unlock()
	if seen {
		t.Fatalf("a two-rounds-stale reply marked the current round answered")
	}
}

func TestProber_PreviousRoundReplyCounts(t *testing.T) {
	// A path whose RTT exceeds one interval answers each probe during the
	// NEXT round; that must still count as liveness or the path would be
	// permanently judged down.
	p, fw, fl := testProber(t)
	p.Register(2, []Target{target(0, "fd00::2")})
	now := time.Unix(0, 0)
	for i := 0; i < 8; i++ {
		p.tick(now)
		if n := len(fw.sent); n >= 2 {
			// Answer the PREVIOUS round's probe only.
			reply(p, fw.sent[n-2], now)
		}
		now = now.Add(100 * time.Millisecond)
	}
	if got := fl.bitmaps[2]; got != 0b1 {
		t.Fatalf("bitmap = %b; a slow but answering path was judged down", got)
	}
}

func TestProber_ReplyValidation(t *testing.T) {
	p, fw, _ := testProber(t)
	p.Register(3, []Target{target(0, "fd00::2")})
	p.tick(time.Unix(0, 0))
	s := fw.sent[0]

	check := func(name string) {
		t.Helper()
		p.mu.Lock()
		seen := p.tokens[s.token].replySeen
		p.mu.Unlock()
		if seen {
			t.Fatalf("%s was accepted", name)
		}
	}
	// Wrong source: another node echoing our id/seq/cookie.
	p.handleReply(s.token, s.seq, s.cookie, netip.MustParseAddr("fd00::99"), time.Unix(1, 0))
	check("a reply from the wrong source")
	// Wrong cookie: an unrelated process's ping sharing the identifier.
	p.handleReply(s.token, s.seq, s.cookie^1, s.target.Dst, time.Unix(1, 0))
	check("a reply with the wrong cookie")
}

func TestProber_ReRegisterKeepsDownState(t *testing.T) {
	// A reconcile that rewrites the group (same members) must not
	// resurrect a path the probes declared dead.
	p, _, fl := testProber(t)
	p.Register(6, []Target{target(0, "fd00::2"), target(1, "fd00::3")})
	now := time.Unix(0, 0)
	for i := 0; i < 4; i++ {
		p.tick(now)
		now = now.Add(100 * time.Millisecond)
	}
	if got := fl.bitmaps[6]; got != 0 {
		t.Fatalf("setup: bitmap = %b, want all down", got)
	}
	p.Register(6, []Target{target(0, "fd00::2"), target(1, "fd00::3")})
	if got := fl.bitmaps[6]; got != 0 {
		t.Fatalf("re-registration resurrected dead paths: bitmap = %b", got)
	}
}

func TestProber_LinkLocalUnprobeable(t *testing.T) {
	p, fw, fl := testProber(t)
	p.Register(8, []Target{target(0, "fe80::1"), target(1, "fd00::3")})
	now := time.Unix(0, 0)
	for i := 0; i < 5; i++ {
		p.tick(now)
		now = now.Add(100 * time.Millisecond)
	}
	if got := fl.bitmaps[8]; got != 0b01 {
		t.Fatalf("bitmap = %b, want the link-local path pinned up", got)
	}
	for _, s := range fw.sent {
		if s.target.PathIndex == 0 {
			t.Fatalf("a probe was sent to a link-local destination")
		}
	}
}

func TestProber_UnprobeablePathStaysUp(t *testing.T) {
	p, fw, fl := testProber(t)
	p.Register(4, []Target{{PathIndex: 0}, target(1, "fd00::3")})
	now := time.Unix(0, 0)
	for i := 0; i < 5; i++ {
		p.tick(now)
		now = now.Add(100 * time.Millisecond)
	}
	if got := fl.bitmaps[4]; got != 0b01 {
		t.Fatalf("bitmap = %b, want the unprobeable path pinned up", got)
	}
	for _, s := range fw.sent {
		if s.target.PathIndex == 0 {
			t.Fatalf("a probe was sent for the unprobeable path")
		}
	}
}

func TestProber_ReRegisterReplacesAndUnregisterDeletes(t *testing.T) {
	p, _, fl := testProber(t)
	p.Register(5, []Target{target(0, "fd00::2"), target(1, "fd00::3")})
	p.Register(5, []Target{target(0, "fd00::2")})
	if got := fl.bitmaps[5]; got != 0b1 {
		t.Fatalf("bitmap after shrink = %b, want single path", got)
	}
	p.Unregister(5)
	if _, ok := fl.bitmaps[5]; ok {
		t.Fatalf("bitmap survived Unregister")
	}
	// Tokens released: registering many groups again must not exhaust.
	p.mu.Lock()
	n := len(p.tokens)
	p.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d tokens leaked", n)
	}
}

func TestBuildEchoRequest_SRHLayout(t *testing.T) {
	src := netip.MustParseAddr("fd00::1")
	tgt := target(0, "fd00::d", "fd00::a", "fd00::b")
	pkt, firstHop := buildEchoRequest(src, tgt, 0x1234, 7, 0xdeadbeefcafe0123)

	if firstHop != netip.MustParseAddr("fd00::a") {
		t.Fatalf("first hop = %v", firstHop)
	}
	if got := netip.AddrFrom16([16]byte(pkt[24:40])); got != firstHop {
		t.Fatalf("IPv6 DA = %v, want the first segment", got)
	}
	if pkt[6] != protoRouting {
		t.Fatalf("next header = %d, want routing", pkt[6])
	}
	srh := pkt[ipv6HeaderLen:]
	if srh[0] != protoICMPv6 || srh[2] != srhTypeSegment {
		t.Fatalf("SRH header = % x", srh[:8])
	}
	if srh[3] != 2 || srh[4] != 2 {
		t.Fatalf("segments left / last entry = %d/%d, want 2/2", srh[3], srh[4])
	}
	// RFC 8754 order: list[0] = final destination, list[last] = first hop.
	list := func(i int) netip.Addr {
		return netip.AddrFrom16([16]byte(srh[srhFixedLen+16*i : srhFixedLen+16*i+16]))
	}
	if list(0) != tgt.Dst || list(1) != netip.MustParseAddr("fd00::b") || list(2) != firstHop {
		t.Fatalf("segment list order wrong: %v %v %v", list(0), list(1), list(2))
	}
	echo := srh[srhFixedLen+16*3:]
	if echo[0] != icmpv6EchoReq {
		t.Fatalf("icmp type = %d", echo[0])
	}
	if id := binary.BigEndian.Uint16(echo[4:6]); id != 0x1234 {
		t.Fatalf("echo id = %#x", id)
	}
	if ck := binary.BigEndian.Uint64(echo[8:16]); ck != 0xdeadbeefcafe0123 {
		t.Fatalf("cookie = %#x", ck)
	}
	// Verify the checksum over the pseudo-header with the FINAL destination.
	want := binary.BigEndian.Uint16(echo[2:4])
	echo[2], echo[3] = 0, 0
	if got := icmpv6Checksum(src, tgt.Dst, echo[:icmpv6EchoLen]); got != want {
		t.Fatalf("checksum mismatch: %#x vs %#x", got, want)
	}
}

func TestBuildEchoRequest_NoSegments(t *testing.T) {
	src := netip.MustParseAddr("fd00::1")
	pkt, firstHop := buildEchoRequest(src, target(0, "fd00::d"), 1, 1, 42)
	if firstHop != netip.MustParseAddr("fd00::d") {
		t.Fatalf("first hop = %v", firstHop)
	}
	if pkt[6] != protoICMPv6 {
		t.Fatalf("next header = %d, want ICMPv6 (no SRH)", pkt[6])
	}
	if len(pkt) != ipv6HeaderLen+icmpv6EchoLen {
		t.Fatalf("packet length = %d", len(pkt))
	}
}

// TestProber_LoopbackE2E exercises the real sockets: a plain probe to ::1
// must be answered by the local kernel. Needs CAP_NET_RAW.
func TestProber_LoopbackE2E(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for raw sockets")
	}
	fl := newFakeLive()
	p, err := New(fl, netip.MustParseAddr("::1"), Config{Interval: 50 * time.Millisecond, Multiplier: 3}, zap.NewNop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p.Register(1, []Target{target(0, "::1")})
	p.Start()
	defer p.Stop()

	deadline := time.After(3 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("no probe reply from ::1; status=%+v", p.Status())
		default:
		}
		st := p.Status()
		if len(st) == 1 && !st[0].LastReply.IsZero() {
			if !st[0].Up {
				t.Fatalf("path down despite replies: %+v", st[0])
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}
