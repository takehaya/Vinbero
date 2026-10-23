//go:build bench

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	gobgpapi "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	gobgpsrv "github.com/osrg/gobgp/v4/pkg/server"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/gobgp"
	"go.uber.org/zap"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIPv4SessionRange(t *testing.T) {
	routes, err := prefixes("10.0.2.2", 512)
	if err != nil {
		t.Fatal(err)
	}
	if routes[0].Prefix != "10.0.2.2/32" || routes[253].Prefix != "10.0.2.255/32" || routes[254].Prefix != "10.0.3.0/32" || routes[511].Prefix != "10.0.4.1/32" {
		t.Fatalf("wrong range: %s %s %s %s", routes[0].Prefix, routes[253].Prefix, routes[254].Prefix, routes[511].Prefix)
	}
	seen := make(map[string]bool)
	for i, r := range routes {
		if seen[r.Prefix] || r.TEID != uint32(256+i) {
			t.Fatalf("duplicate prefix or wrong initial TEID: %+v", r)
		}
		seen[r.Prefix] = true
	}
	if _, err := prefixes("255.255.255.255", 1); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		base  string
		count int
	}{{"255.255.254.1", 512}, {"255.255.255.255", 2}, {"::ffff:10.0.2.2", 512}, {"::1", 64}, {"invalid", 64}, {"10.0.2.2", 0}} {
		if _, err := prefixes(tc.base, tc.count); err == nil {
			t.Fatalf("accepted invalid range %+v", tc)
		}
	}
}

func TestLateSlotsDoNotCatchUp(t *testing.T) {
	start := time.Unix(100, 0)
	// Waking 350ms late at 10/s discards slots 0,1,2; only the current
	// slot 3 may emit. A later slot remains scheduled for the future.
	now := start.Add(350 * time.Millisecond)
	for i := 0; i < 5; i++ {
		planned, missed := slot(start, i, 10, time.Second, now)
		if planned != start.Add(time.Duration(i)*100*time.Millisecond) || missed != (i < 3) {
			t.Fatalf("slot %d: planned=%s missed=%v", i, planned, missed)
		}
	}
	if _, missed := slot(start, 0, 10, time.Second, start.Add(100*time.Millisecond)); !missed {
		t.Fatal("slot exactly at its deadline must be missed")
	}
	if _, missed := slot(start, 9, 10, 950*time.Millisecond, start.Add(950*time.Millisecond)); !missed {
		t.Fatal("final partial slot continued beyond the load window")
	}
}

func TestSuccessfulPerSessionUpdatesAlwaysChangePayload(t *testing.T) {
	if nextTEID(7, 0) != 1048583 || nextTEID(7, 1) != 2097159 || nextTEID(7, 2) != 1048583 {
		t.Fatal("updates must alternate between the two non-initial TEID ranges")
	}
	for _, count := range []int{64, 512} {
		routes, err := prefixes("10.0.2.2", count)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 5*count; i++ {
			index := i % count
			r := &routes[index]
			next := nextTEID(index, r.Version)
			if next == r.TEID || next == uint32(256+index) {
				t.Fatalf("N=%d slot=%d repeats payload: %+v", count, i, r)
			}
			if i%7 == 0 { // A missed slot or failed call must not advance state.
				if nextTEID(index, r.Version) != next {
					t.Fatal("retry payload changed without a successful update")
				}
				continue
			}
			r.TEID, r.Version = next, r.Version+1
		}
	}
	// Eight full rounds (N64 burst512) must not return the map to its initial
	// contents, which would make a never-delivered burst pass the final oracle.
	for index := 0; index < 64; index++ {
		if nextTEID(index, 7) == uint32(256+index) {
			t.Fatal("burst final output equals initial output")
		}
	}
}

func TestExpectedStateAndStartBarrier(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "expected.json")
	want := expectedState{Complete: true, Sessions: []sessionState{{Prefix: "10.0.2.2/32", TEID: 1048576, Version: 1}}, SentinelSID: "fd00:b::100"}
	if err := saveExpected(path, &want); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got expectedState
	if err := json.Unmarshal(raw, &got); err != nil || !got.Complete || len(got.Sessions) != 1 || got.Sessions[0] != want.Sessions[0] || got.SentinelSID != want.SentinelSID {
		t.Fatalf("saved state: %+v, %v", got, err)
	}
	startPath := filepath.Join(dir, "start")
	if err := os.WriteFile(startPath, []byte("1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := awaitStart(context.Background(), startPath, time.Second); err == nil {
		t.Fatal("stale start file accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitUntil(ctx, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("cancelled wait succeeded")
	}
}

// A real TCP peer checks the instrument's replacement semantics independently
// of the controller: one received path per prefix, new TEID, and intact VPN SID.
func TestLiveRouteReplacements(t *testing.T) {
	ctx := context.Background()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	source := gobgp.NewSession(zap.NewNop())
	if err := source.Start(ctx, bgp.GlobalConfig{LocalASN: 65100, RouterID: "10.255.0.2", ListenPort: int32(port)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Stop(ctx) })
	if err := source.AddPeer(ctx, bgp.PeerConfig{Neighbor: "127.0.0.1", PeerASN: 65100, Passive: true, Families: []bgp.Family{bgp.FamilyMUPIPv4, bgp.FamilyVPNv4}}); err != nil {
		t.Fatal(err)
	}
	sink := gobgpsrv.NewBgpServer()
	go sink.Serve()
	t.Cleanup(sink.Stop)
	if err := sink.StartBgp(ctx, &gobgpapi.StartBgpRequest{Global: &gobgpapi.Global{Asn: 65100, RouterId: "10.255.0.1", ListenPort: -1}}); err != nil {
		t.Fatal(err)
	}
	families := []*gobgpapi.AfiSafi{}
	for _, safi := range []gobgpapi.Family_Safi{gobgpapi.Family_SAFI_MUP, gobgpapi.Family_SAFI_MPLS_VPN} {
		families = append(families, &gobgpapi.AfiSafi{Config: &gobgpapi.AfiSafiConfig{Family: &gobgpapi.Family{Afi: gobgpapi.Family_AFI_IP, Safi: safi}}})
	}
	if err := sink.AddPeer(ctx, &gobgpapi.AddPeerRequest{Peer: &gobgpapi.Peer{Conf: &gobgpapi.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65100}, Transport: &gobgpapi.Transport{RemoteAddress: "127.0.0.1", RemotePort: uint32(port), LocalAddress: "127.0.0.1"}, AfiSafis: families}}); err != nil {
		t.Fatal(err)
	}
	wait := func(what string, fn func() bool) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if fn() {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("timeout: " + what)
	}
	wait("peer established", func() bool {
		peers, err := source.Peers(ctx)
		return err == nil && len(peers) == 1 && peers[0].SessionState == "established"
	})
	paths := func(family gobgppkt.Family) []*apiutil.Path {
		t.Helper()
		var result []*apiutil.Path
		if err := sink.ListPath(apiutil.ListPathRequest{TableType: gobgpapi.TableType_TABLE_TYPE_GLOBAL, Family: family}, func(_ gobgppkt.NLRI, p []*apiutil.Path) { result = append(result, p...) }); err != nil {
			t.Fatal(err)
		}
		return result
	}
	for version := 0; version < 5; version++ {
		teid := uint32(256)
		if version > 0 {
			teid = nextTEID(0, version-1)
		}
		route := st1Route("10.0.2.2/32", teid, version, "127.0.0.1")
		if route.RTs[0] != "65000:7" || version > 0 && (len(route.RTs) != 2 || route.RTs[1] != fmt.Sprintf("65000:%d", 1000+(version-1)%2)) {
			t.Fatalf("wrong RTs: %v", route.RTs)
		}
		if err := source.PushMUPT1ST(ctx, route); err != nil {
			t.Fatal(err)
		}
		wait(fmt.Sprintf("TEID version %d", version), func() bool {
			got := paths(gobgppkt.RF_MUP_IPv4)
			if len(got) != 1 {
				return false
			}
			n, ok := got[0].Nlri.(*gobgppkt.MUPNLRI)
			if !ok {
				return false
			}
			r, ok := n.RouteTypeData.(*gobgppkt.MUPType1SessionTransformedRoute)
			if !ok {
				return false
			}
			bytes := r.TEID.As4()
			return binary.BigEndian.Uint32(bytes[:]) == teid
		})
		sid := "fd00:a::100"
		if version%2 == 1 {
			sid = "fd00:b::100"
		}
		if err := source.Advertise(ctx, sentinelRoute(sid, "127.0.0.1")); err != nil {
			t.Fatal(err)
		}
		wait(fmt.Sprintf("sentinel SID version %d", version), func() bool {
			got := paths(gobgppkt.RF_IPv4_VPN)
			if len(got) != 1 {
				return false
			}
			for _, attr := range got[0].Attrs {
				psid, ok := attr.(*gobgppkt.PathAttributePrefixSID)
				if !ok {
					continue
				}
				for _, tlv := range psid.TLVs {
					service, ok := tlv.(*gobgppkt.SRv6ServiceTLV)
					if !ok {
						continue
					}
					for _, sub := range service.SubTLVs {
						info, ok := sub.(*gobgppkt.SRv6InformationSubTLV)
						if !ok {
							continue
						}
						addr, ok := netip.AddrFromSlice(info.SID)
						return ok && addr.String() == sid && info.EndpointBehavior == 65025
					}
				}
			}
			return false
		})
	}
}
