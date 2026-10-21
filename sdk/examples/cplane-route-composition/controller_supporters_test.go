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
