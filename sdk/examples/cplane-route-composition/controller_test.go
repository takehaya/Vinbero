package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/takehaya/vinbero/sdk/go/cplane"
)

type recorder struct {
	sets []cplane.Composition
	fail bool
}

func (r *recorder) ApplyComposition(set cplane.Composition) error {
	r.sets = append(r.sets, set)
	if r.fail {
		return errors.New("injected commit failure")
	}
	return nil
}

func inputConfig(extra string) cplane.InputConfig {
	return cplane.InputConfig{Version: 1, Codec: cplane.BGPPathCodec,
		Payload:  []byte(`{"context":"mobile","source":"fd00:feed::1","args_offset":7` + extra + `}`),
		Contexts: []cplane.InputContext{{Name: "mobile", Families: []string{"mup_ipv4", "mup_ipv6"}}}}
}

func marker(kind cplane.EventKind) cplane.Event {
	return cplane.Event{Kind: kind, ReplaySource: cplane.BGPSource}
}

func route(t *testing.T, n *bgp.MUPNLRI, attrs ...bgp.PathAttributeInterface) cplane.Event {
	t.Helper()
	raw, err := n.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	p := &cplane.BGPPath{Codec: cplane.BGPPathCodec, AFI: n.Afi, SAFI: 85, NLRI: raw, RouteKey: []byte(n.String())}
	for _, attr := range attrs {
		b, err := attr.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		p.Attributes = append(p.Attributes, b)
	}
	return cplane.Event{Kind: cplane.EventRoute, Route: cplane.Route{Family: "mup_ipv4", Peer: "192.0.2.254", Contexts: []string{"mobile"}, BGPPath: p}}
}

func fixtures(t *testing.T, teid uint32) []cplane.Event {
	t.Helper()
	a := netip.MustParseAddr
	p := netip.MustParsePrefix
	rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, 7)
	var rawTEID [4]byte
	binary.BigEndian.PutUint32(rawTEID[:], teid)
	sid := func(behavior bgp.SRBehavior) bgp.PathAttributeInterface {
		return bgp.NewPathAttributePrefixSID(bgp.NewSRv6ServiceTLV(bgp.TLVTypeSRv6L3Service,
			bgp.NewSRv6InformationSubTLV(a("fd00:a:0:100::"), behavior,
				bgp.NewSRv6SIDStructureSubSubTLV(32, 16, 8, 72, 0, 0))))
	}
	direct := bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{bgp.NewMUPExtended(0, 0)})
	return []cplane.Event{
		route(t, bgp.NewMUPType1SessionTransformedRoute(rd, p("10.0.0.1/32"), netip.AddrFrom4(rawTEID), 9, a("172.16.0.1"), nil)),
		route(t, bgp.NewMUPInterworkSegmentDiscoveryRoute(rd, p("172.16.0.0/24")), sid(bgp.ENDM_GTP4E)),
		route(t, bgp.NewMUPType2SessionTransformedRoute(rd, 64, a("192.0.2.1"), netip.AddrFrom4(rawTEID)), direct),
		route(t, bgp.NewMUPDirectSegmentDiscoveryRoute(rd, a("192.0.2.2")), direct, sid(bgp.END_DT4)),
	}
}

func replay(events []cplane.Event) []cplane.Event {
	return append(append([]cplane.Event{marker(cplane.EventStartOfReplay)}, events...), marker(cplane.EventEndOfReplay))
}

func TestObserveOnlyDefault(t *testing.T) {
	r := &recorder{}
	var logs []string
	c, err := newController(inputConfig(""), r, func(_ cplane.LogLevel, s string) { logs = append(logs, s) })
	if err != nil {
		t.Fatal(err)
	}
	c.update(replay(fixtures(t, 256)))
	c.reconcile()
	if len(r.sets) != 0 || len(logs) != 1 || !strings.Contains(logs[0], "observe_only=true headends=1 uplinks=1") {
		t.Fatalf("writes=%d logs=%v", len(r.sets), logs)
	}
}

func TestWriteWithdrawAndEmptyReplay(t *testing.T) {
	r := &recorder{}
	c, err := newController(inputConfig(`,"observe_only":false`), r, nil)
	if err != nil {
		t.Fatal(err)
	}
	events := fixtures(t, 256)
	c.update(replay(events))
	if len(r.sets) != 1 || len(r.sets[0].Headends) != 1 || len(r.sets[0].Uplinks) != 1 {
		t.Fatalf("initial desired set: %+v", r.sets)
	}
	set := r.sets[0]
	if set.Headends[0].Entry.Segments[0] != "fd00:a:0:1ac:1000:124:0:100" || set.Uplinks[0].TEID != 256 || set.Uplinks[0].TEIDBits != 32 {
		t.Fatalf("builders not connected: %+v", set)
	}
	c.reconcile()
	if len(r.sets) != 1 {
		t.Fatal("successful revision was retried")
	}
	events[1].Route.Withdraw = true
	c.update(events[1:2])
	if len(r.sets) != 2 || len(r.sets[1].Headends) != 0 || len(r.sets[1].Uplinks) != 1 {
		t.Fatalf("ISD withdraw: %+v", r.sets)
	}
	c.update(replay(nil))
	last := r.sets[len(r.sets)-1]
	if len(r.sets) != 3 || len(last.Headends)+len(last.Uplinks) != 0 || last.Revision <= set.Revision {
		t.Fatalf("empty replay failed to retract: %+v", r.sets)
	}
}

func TestRetryUsesLatestReadyRevision(t *testing.T) {
	r := &recorder{fail: true}
	c, err := newController(inputConfig(`,"observe_only":false`), r, nil)
	if err != nil {
		t.Fatal(err)
	}
	initial := fixtures(t, 256)
	c.update(replay(initial))
	first := r.sets[0]
	c.reconcile()
	if len(r.sets) != 2 || r.sets[1].Revision != first.Revision {
		t.Fatal("tick did not retry failed apply")
	}
	// ST1 TEID is payload, not destination identity: replace the same key.
	changed := fixtures(t, 512)[0]
	changed.Route.BGPPath.RouteKey = append([]byte(nil), initial[0].Route.BGPPath.RouteKey...)
	c.update([]cplane.Event{changed})
	r.fail = false
	c.reconcile()
	last := r.sets[len(r.sets)-1]
	if len(r.sets) != 4 || last.Revision <= first.Revision || last.Headends[0].Entry.Segments[0] == first.Headends[0].Entry.Segments[0] || c.handledRevision != last.Revision {
		t.Fatalf("latest revision not retried: %+v", r.sets)
	}
	c.reconcile()
	if len(r.sets) != 4 {
		t.Fatal("successful retry repeated")
	}
}

func TestReplayAndIncompleteSuppressRetry(t *testing.T) {
	for _, reason := range []string{"replay", "incomplete"} {
		t.Run(reason, func(t *testing.T) {
			r := &recorder{fail: true}
			c, err := newController(inputConfig(`,"observe_only":false`), r, nil)
			if err != nil {
				t.Fatal(err)
			}
			c.update(replay(fixtures(t, 256)))
			if reason == "replay" {
				c.update([]cplane.Event{marker(cplane.EventStartOfReplay)})
			} else {
				results := c.update([]cplane.Event{{Kind: cplane.EventRoute, Sequence: 42}})
				if len(results) != 1 || results[0].Disposition != cplane.InputIncomplete {
					t.Fatalf("missing incomplete result: %v", results)
				}
			}
			r.fail = false
			c.reconcile()
			if len(r.sets) != 1 || c.engine.Status().Ready {
				t.Fatal("stale desired set retried")
			}
			c.update(replay(nil))
			if len(r.sets) != 2 || len(r.sets[1].Headends)+len(r.sets[1].Uplinks) != 0 {
				t.Fatalf("recovery reused stale desired set: %+v", r.sets)
			}
		})
	}
}

func TestConfigFailsClosed(t *testing.T) {
	if _, err := newController(inputConfig(`,"observe_only":false`), nil, nil); err == nil {
		t.Fatal("observation artifact accepted writing configuration")
	}
	for name, payload := range map[string]string{
		"empty": "{}", "null": "null", "unknown": string(inputConfig(`,"typo":true`).Payload),
		"trailing":       string(inputConfig("").Payload) + "{}",
		"bad-offset":     `{"context":"mobile","source":"fd00::1","args_offset":8}`,
		"missing-offset": `{"context":"mobile","source":"fd00::1"}`,
		"bad-source":     `{"context":"mobile","source":"192.0.2.1","args_offset":7}`,
	} {
		t.Run(name, func(t *testing.T) {
			input := inputConfig("")
			input.Payload = []byte(payload)
			if _, err := newController(input, nil, nil); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	input := inputConfig("")
	input.Contexts[0].Families = []string{"mup_ipv4"}
	if _, err := newController(input, nil, nil); err == nil {
		t.Fatal("missing family grant accepted")
	}
}

type wireHost struct {
	kind          cplane.Kind
	puts, commits int
	status        cplane.Status
}

func (h *wireHost) Begin(k cplane.Kind) uint64 { h.kind = k; return 1 }
func (h *wireHost) Put(_ uint64, b []byte) cplane.Status {
	if len(b) == 0 {
		panic("empty chunk")
	}
	h.puts++
	return cplane.StatusOK
}
func (h *wireHost) Commit(uint64) cplane.Status { h.commits++; return h.status }
func (*wireHost) Abort(uint64)                  { panic("unexpected abort") }

func TestClientTransportCommitFailure(t *testing.T) {
	h := &wireHost{status: cplane.StatusInternal}
	c, err := newController(inputConfig(`,"observe_only":false`), &cplane.Client{Host: h}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.update(replay(fixtures(t, 256)))
	if h.kind != cplane.CompositionSet || h.commits != 1 || h.puts == 0 || c.handledRevision != 0 {
		t.Fatal(fmt.Sprintf("transport=%+v handled=%d", h, c.handledRevision))
	}
	h.status = cplane.StatusOK
	c.reconcile()
	if h.commits != 2 || c.handledRevision == 0 {
		t.Fatal("client failure not retried")
	}
}
