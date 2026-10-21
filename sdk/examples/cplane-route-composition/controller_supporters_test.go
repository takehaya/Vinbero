package main

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/takehaya/vinbero/sdk/go/cplane"
)

func TestControllerHeadendSupporters(t *testing.T) {
	for _, tt := range []struct {
		name string
		rd   uint32
		teid uint32
		want int
	}{
		{"identical reflected", 7, 256, 1},
		{"conflicting reflected", 7, 512, 0},
		{"identical different RD", 8, 256, 1},
		{"conflicting different RD", 8, 512, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := &recorder{}
			var logs []string
			c, err := newController(inputConfig(`,"observe_only":false`), r, func(_ cplane.LogLevel, s string) { logs = append(logs, s) })
			if err != nil {
				t.Fatal(err)
			}
			initial := fixtures(t, 256)
			c.update(replay(initial))
			var teid [4]byte
			binary.BigEndian.PutUint32(teid[:], tt.teid)
			other := route(t, bgp.NewMUPType1SessionTransformedRoute(bgp.NewRouteDistinguisherTwoOctetAS(65000, tt.rd), netip.MustParsePrefix("10.0.0.1/32"), netip.AddrFrom4(teid), 9, netip.MustParseAddr("172.16.0.1"), nil))
			other.Route.Peer = "192.0.2.253"
			withdraw := initial[2]
			withdraw.Route.Withdraw = true
			c.update([]cplane.Event{other, withdraw})
			set := r.sets[len(r.sets)-1]
			if len(set.Headends) != tt.want || len(set.Uplinks) != 0 || c.handledRevision != set.Revision {
				t.Fatalf("supporter blocked complete-set convergence: %+v", set)
			}
			if tt.want == 0 && !strings.Contains(strings.Join(logs, "\n"), "ambiguous forwarding key") {
				t.Fatal("conflict not diagnosed")
			}
			other.Route.Withdraw = true
			c.update([]cplane.Event{other})
			set = r.sets[len(r.sets)-1]
			if len(set.Headends) != 1 || set.Headends[0].Entry.Segments[0] != r.sets[0].Headends[0].Entry.Segments[0] {
				t.Fatal("surviving supporter did not restore the original output")
			}
		})
	}
}

func TestControllerUplinkOutputKeys(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(map[bool]string{false: "equivalent", true: "conflicting"}[conflict], func(t *testing.T) {
			r := &recorder{}
			c, err := newController(inputConfig(`,"observe_only":false`), r, nil)
			if err != nil {
				t.Fatal(err)
			}
			initial := fixtures(t, 256)
			c.update(replay(initial))
			rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, 8)
			direct := bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{bgp.NewMUPExtended(0, 1)})
			st2 := route(t, bgp.NewMUPType2SessionTransformedRoute(rd, 64, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("0.0.1.0")), direct)
			address := netip.MustParseAddr("fd00:a:0:100::")
			if conflict {
				address = netip.MustParseAddr("fd00:b:0:100::")
			}
			sid := bgp.NewPathAttributePrefixSID(bgp.NewSRv6ServiceTLV(bgp.TLVTypeSRv6L3Service, bgp.NewSRv6InformationSubTLV(address, bgp.END_DT4)))
			dsd := route(t, bgp.NewMUPDirectSegmentDiscoveryRoute(rd, netip.MustParseAddr("192.0.2.3")), direct, sid)
			withdraw := initial[0]
			withdraw.Route.Withdraw = true
			c.update([]cplane.Event{st2, dsd, withdraw})
			set := r.sets[len(r.sets)-1]
			want := 1
			if conflict {
				want = 0
			}
			if len(set.Uplinks) != want || len(set.Headends) != 0 {
				t.Fatalf("uplink collision blocked unrelated withdrawal: %+v", set)
			}
		})
	}
}

func TestControllerSharedGateClaims(t *testing.T) {
	for _, name := range []string{"single", "conflicting headends", "conflicting uplinks", "containing prefix"} {
		for _, reverse := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "/forward", true: "/reverse"}[reverse], func(t *testing.T) {
				r := &recorder{}
				c, err := newController(inputConfig(`,"observe_only":false`), r, nil)
				if err != nil {
					t.Fatal(err)
				}
				prefix := "192.0.2.1/32"
				if name == "containing prefix" {
					prefix = "192.0.2.0/24"
				}
				extra := []cplane.Event{route(t, bgp.NewMUPType1SessionTransformedRoute(bgp.NewRouteDistinguisherTwoOctetAS(65000, 8), netip.MustParsePrefix(prefix), netip.MustParseAddr("0.0.1.0"), 9, netip.MustParseAddr("172.16.0.1"), nil))}
				if name == "conflicting headends" {
					extra = append(extra, route(t, bgp.NewMUPType1SessionTransformedRoute(bgp.NewRouteDistinguisherTwoOctetAS(65000, 9), netip.MustParsePrefix(prefix), netip.MustParseAddr("0.0.2.0"), 9, netip.MustParseAddr("172.16.0.1"), nil)))
				}
				if name == "conflicting uplinks" {
					direct := bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{bgp.NewMUPExtended(0, 1)})
					rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, 8)
					sid := bgp.NewPathAttributePrefixSID(bgp.NewSRv6ServiceTLV(bgp.TLVTypeSRv6L3Service, bgp.NewSRv6InformationSubTLV(netip.MustParseAddr("fd00:b:0:100::"), bgp.END_DT4)))
					extra = append(extra, route(t, bgp.NewMUPType2SessionTransformedRoute(rd, 64, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("0.0.1.0")), direct), route(t, bgp.NewMUPDirectSegmentDiscoveryRoute(rd, netip.MustParseAddr("192.0.2.3")), direct, sid))
				}
				initial := fixtures(t, 256)
				events := append(append([]cplane.Event(nil), initial...), extra...)
				if reverse {
					for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
						events[i], events[j] = events[j], events[i]
					}
				}
				c.update(replay(events))
				withdraw := initial[0]
				withdraw.Route.Withdraw = true
				c.update([]cplane.Event{withdraw})
				set := r.sets[len(r.sets)-1]
				wantHeads, wantUplinks := 0, 0
				if name == "containing prefix" {
					wantHeads, wantUplinks = 1, 1
				}
				if len(set.Headends) != wantHeads || len(set.Uplinks) != wantUplinks {
					t.Fatalf("cross-kind ambiguity was lost or nonexact overlap suppressed: %+v", set)
				}
				for i := range extra {
					extra[i].Route.Withdraw = true
				}
				c.update(extra)
				set = r.sets[len(r.sets)-1]
				if len(set.Headends) != 0 || len(set.Uplinks) != 1 {
					t.Fatalf("remaining uplink did not recover: %+v", set)
				}
			})
		}
	}
}
