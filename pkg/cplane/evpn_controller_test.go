package cplane

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	gp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/cplane/native"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"github.com/takehaya/vinbero/sdk/go/cplane/gobgppath"
)

type evpnFixtureMaps interface {
	ForwardingMapOps
	ListFdb() (map[bpf.FdbKey]*bpf.FdbEntry, error)
	ListBdPeers() (map[bpf.BdPeerKey]*bpf.HeadendEntry, error)
}
type evpnValueFake struct {
	*serviceFake
	entries map[bpf.FdbKey]*bpf.FdbEntry
}

func (f *evpnValueFake) CreateFdbOwned(bd uint16, mac net.HardwareAddr, e *bpf.FdbEntry, o bpf.OwnerTag) error {
	if err := f.serviceFake.CreateFdbOwned(bd, mac, e, o); err != nil {
		return err
	}
	copy := *e
	f.entries[fk(bd, mac)] = &copy
	return nil
}
func (f *evpnValueFake) DeleteFdbOwned(bd uint16, mac net.HardwareAddr, o bpf.OwnerTag) error {
	if err := f.serviceFake.DeleteFdbOwned(bd, mac, o); err != nil {
		return err
	}
	delete(f.entries, fk(bd, mac))
	return nil
}
func (f *evpnValueFake) ListFdb() (map[bpf.FdbKey]*bpf.FdbEntry, error) { return f.entries, nil }
func (f *evpnValueFake) ListBdPeers() (map[bpf.BdPeerKey]*bpf.HeadendEntry, error) {
	return f.peerEntries, nil
}

func evpnPolicyFixture(t *testing.T, imet bool, rt string) bgp.RouteEvent {
	t.Helper()
	rdNumber := uint32(7)
	sid := "fd00:2::1"
	if imet {
		rdNumber = 8
		sid = "fd00:3::1"
	}
	return evpnPolicyPath(t, imet, rt, rdNumber, "02:00:00:00:00:01", "2001:db8::1", sid)
}
func evpnPolicyPath(t *testing.T, imet bool, rt string, rdNumber uint32, mac, remote, sid string) bgp.RouteEvent {
	t.Helper()
	behavior, kind := gp.END_DT2U, bgp.EVPNRouteType(2)
	if imet {
		behavior, kind = gp.END_DT2M, 3
	}
	rd := gp.NewRouteDistinguisherTwoOctetAS(65000, rdNumber)
	var n *gp.EVPNNLRI
	var err error
	if imet {
		n, err = gp.NewEVPNMulticastEthernetTagRoute(rd, 0, netip.MustParseAddr("192.0.2.1"))
	} else {
		n, err = gp.NewEVPNMacIPAdvertisementRoute(rd, gp.EthernetSegmentIdentifier{}, 0, mac, netip.Addr{}, []uint32{0})
	}
	if err != nil {
		t.Fatal(err)
	}
	mp, err := gp.NewPathAttributeMpReachNLRI(gp.RF_EVPN, []gp.PathNLRI{{NLRI: n}}, netip.MustParseAddr(remote))
	if err != nil {
		t.Fatal(err)
	}
	sidAttr := gp.NewPathAttributePrefixSID(gp.NewSRv6ServiceTLV(gp.TLVTypeSRv6L2Service, gp.NewSRv6InformationSubTLV(netip.MustParseAddr(sid), behavior)))
	path, err := gobgppath.Encode(gp.RF_EVPN, n, []gp.PathAttributeInterface{mp, sidAttr, rtAttribute(rt)})
	if err != nil {
		t.Fatal(err)
	}
	return bgp.RouteEvent{Family: bgp.FamilyEVPN, Source: bgp.PathSource{Peer: netip.MustParseAddr("192.0.2.254")}, EVPN: &bgp.EVPNRoute{Type: kind, RD: rd.String(), RTs: []string{rt}, MAC: mac, NextHop: remote, SRv6SID: sid}, BGPPath: &bgp.EncodedBGPPath{Codec: path.Codec, AFI: path.AFI, SAFI: path.SAFI, NLRI: path.NLRI, RouteKey: []byte(n.String()), Attributes: path.Attributes}}
}
func evpnManagerLifecycle(t *testing.T, backend string, maps evpnFixtureMaps) {
	t.Helper()
	source := &compositionSource{newFakeSource()}
	source.rib = []bgp.RouteEvent{evpnPolicyFixture(t, false, "65000:7"), evpnPolicyFixture(t, true, "65000:7")}
	manager, err := NewManager(ManagerConfig{AllowNative: true, Source: source, Headend: newFakeHeadendOps(), ForwardingMaps: maps, ResolveInputTarget: func(bgp.RouteEvent) (string, uint16, bool) { return "", 100, true }})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close(context.Background())
	policy := &v1.CplaneInputPolicy{Version: 1, Contexts: []*v1.CplaneInputContext{{Name: "l2", Grants: []*v1.CplaneInputGrant{{Families: []string{"evpn"}, RouteTargets: []string{"65000:7"}}}, DelegateEvpn: true, BridgeDomain: 100}}}
	reg := Registration{Name: "imet", Backend: backend, Config: []byte(`{"context":"l2","source":"fd00:feed::1","observe_only":false}`), Capabilities: wasm.Capabilities{wasm.CapEVPN: {}}, Input: policy}
	if backend == BackendNative {
		reg.NativeID = native.EVPNIMET
		reg.NativeVersion = native.ImplementationVersion
	} else {
		reg.Module, err = os.ReadFile("../../out/cplane-evpn-imet.wasm")
		if err != nil {
			if os.Getenv("VINBERO_CPLANE_PARITY") == "1" {
				t.Fatal(err)
			}
			t.Skip("make cplane-evpn-imet", err)
		}
	}
	if err = manager.Register(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	check := func(want int) {
		t.Helper()
		if !manager.WaitIdle("imet", 5*time.Second) {
			t.Fatal("worker did not drain")
		}
		st, _ := manager.StatsFor("imet")
		if !st.InputReady || st.InputFault != "" || st.OutputFailure != "" || st.DesiredRevision == 0 || st.DesiredRevision != st.AppliedRevision {
			t.Fatalf("unhealthy: %+v", st)
		}
		fdb, e := maps.ListFdb()
		if e != nil {
			t.Fatal(e)
		}
		peers, e := maps.ListBdPeers()
		if e != nil {
			t.Fatal(e)
		}
		owners, e := maps.ListFdbOwners()
		if e != nil {
			t.Fatal(e)
		}
		peerOwners, e := maps.ListBdPeerOwners()
		if e != nil {
			t.Fatal(e)
		}
		if len(fdb) != want || len(peers) != want || len(owners) != want || len(peerOwners) != want {
			t.Fatalf("entries fdb=%v peers=%v owners=%v/%v", fdb, peers, owners, peerOwners)
		}
		for key, value := range fdb {
			if key.BdId != 100 || key.Mac != [6]byte{2, 0, 0, 0, 0, 1} || value.IsStatic != 1 || value.IsRemote != 1 || value.BdId != 100 || owners[key] != bpf.OwnerPluginBundle("imet") {
				t.Fatalf("wrong FDB key=%+v value=%+v owner=%s", key, value, owners[key])
			}
			pk := bpf.BdPeerKey{BdId: 100, Index: value.PeerIndex}
			p := peers[pk]
			if p == nil || p.NumSegments != 1 || p.Segments[0] != netip.MustParseAddr("fd00:2::1").As16() || p.SrcAddr != netip.MustParseAddr("fd00:feed::1").As16() || p.FloodExclude != 1 || p.Mode != uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2) || peerOwners[pk] != bpf.OwnerPluginBundle("imet") {
				t.Fatalf("wrong peer %+v owner=%s", p, peerOwners[pk])
			}
		}
	}
	check(1)
	denied := evpnPolicyFixture(t, true, "65000:8")
	source.emit("imet", denied)
	check(0)
	source.emit("imet", source.rib[1])
	check(1)
	withdraw := source.rib[1]
	withdraw.IsWithdraw = true
	source.emit("imet", withdraw)
	check(0)
	source.emit("imet", source.rib[1])
	check(1)
	if err = manager.Unregister(context.Background(), "imet"); err != nil {
		t.Fatal(err)
	}
	fdb, err := maps.ListFdb()
	if err != nil || len(fdb) != 0 {
		t.Fatalf("FDB cleanup: %v %v", fdb, err)
	}
	peers, err := maps.ListBdPeers()
	if err != nil || len(peers) != 0 {
		t.Fatalf("peer cleanup: %v %v", peers, err)
	}
	owners, err := maps.ListFdbOwners()
	if err != nil || len(owners) != 0 {
		t.Fatalf("FDB owner cleanup: %v %v", owners, err)
	}
	peerOwners, err := maps.ListBdPeerOwners()
	if err != nil || len(peerOwners) != 0 {
		t.Fatalf("peer owner cleanup: %v %v", peerOwners, err)
	}
}
func TestEVPNControllerManager(t *testing.T) {
	for _, backend := range []string{BackendNative, BackendWASM} {
		t.Run(backend, func(t *testing.T) {
			evpnManagerLifecycle(t, backend, &evpnValueFake{serviceFake: newServiceFake(), entries: map[bpf.FdbKey]*bpf.FdbEntry{}})
		})
	}
}

// This opt-in fixture loads anonymous maps only; it does not claim packet or
// SRv6 interoperability coverage and never touches pinned deployment maps.
func TestEVPNControllerOwnedBPFMaps(t *testing.T) {
	if os.Getenv("VINBERO_CPLANE_EVPN_BPF") != "1" {
		t.Skip("set VINBERO_CPLANE_EVPN_BPF=1 with BPF map privileges")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{BackendNative, BackendWASM} {
		t.Run(backend, func(t *testing.T) {
			makeMap := func(key, value any) *ebpf.Map {
				m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: uint32(binary.Size(key)), ValueSize: uint32(binary.Size(value)), MaxEntries: 32})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = m.Close() })
				return m
			}
			objects := &bpf.BpfObjects{}
			objects.SidAuxMap = makeMap(uint32(0), uint32(0))
			objects.FdbMap = makeMap(bpf.FdbKey{}, bpf.FdbEntry{})
			objects.FdbOwnerMap = makeMap(bpf.FdbKey{}, [64]byte{})
			objects.BdPeerMap = makeMap(bpf.BdPeerKey{}, bpf.HeadendEntry{})
			objects.BdPeerOwnerMap = makeMap(bpf.BdPeerKey{}, [64]byte{})
			objects.BdPeerReverseMap = makeMap(bpf.BdPeerReverseKey{}, bpf.BdPeerReverseVal{})
			objects.BdPeerL2ExtMap = makeMap(bpf.BpfBdPeerL2ExtKey{}, bpf.BpfBdPeerL2ExtVal{})
			evpnManagerLifecycle(t, backend, bpf.NewMapOperations(objects))
		})
	}
}

func TestEVPNControllerHostDenials(t *testing.T) {
	for _, backend := range []string{BackendNative, BackendWASM} {
		for _, denial := range []string{"capability", "delegation"} {
			t.Run(backend+"/"+denial, func(t *testing.T) {
				maps := &evpnValueFake{serviceFake: newServiceFake(), entries: map[bpf.FdbKey]*bpf.FdbEntry{}}
				source := &compositionSource{newFakeSource()}
				source.rib = []bgp.RouteEvent{evpnPolicyFixture(t, false, "65000:7"), evpnPolicyFixture(t, true, "65000:7")}
				manager, err := NewManager(ManagerConfig{AllowNative: true, Source: source, Headend: newFakeHeadendOps(), ForwardingMaps: maps, ResolveInputTarget: func(bgp.RouteEvent) (string, uint16, bool) { return "", 100, true }})
				if err != nil {
					t.Fatal(err)
				}
				defer manager.Close(context.Background())
				policy := &v1.CplaneInputPolicy{Version: 1, Contexts: []*v1.CplaneInputContext{{Name: "l2", Grants: []*v1.CplaneInputGrant{{Families: []string{"evpn"}, RouteTargets: []string{"65000:7"}}}, DelegateEvpn: true, BridgeDomain: 100}}}
				reg := Registration{Name: "imet", Backend: backend, Config: []byte(`{"context":"l2","source":"fd00:feed::1","observe_only":false}`), Input: policy, Capabilities: wasm.Capabilities{wasm.CapEVPN: {}}}
				if denial == "capability" {
					reg.Capabilities = wasm.Capabilities{wasm.CapHeadend: {}}
				} else {
					policy.Contexts[0].DelegateEvpn = false
					policy.Contexts[0].BridgeDomain = 0
				}
				if backend == BackendNative {
					reg.NativeID = native.EVPNIMET
					reg.NativeVersion = native.ImplementationVersion
				} else {
					reg.Module, err = os.ReadFile("../../out/cplane-evpn-imet.wasm")
					if err != nil {
						if os.Getenv("VINBERO_CPLANE_PARITY") == "1" {
							t.Fatal(err)
						}
						t.Skip(err)
					}
				}
				err = manager.Register(context.Background(), reg)
				if denial == "capability" && (err == nil || !strings.Contains(err.Error(), "evpn capability")) {
					t.Fatalf("expected EVPN capability admission denial: %v", err)
				}
				if denial == "delegation" && err != nil {
					t.Fatalf("undelegated observer input should configure before output denial: %v", err)
				}
				if err == nil {
					if !manager.WaitIdle("imet", 5*time.Second) {
						t.Fatal("worker did not drain")
					}
					st, _ := manager.StatsFor("imet")
					if st.OutputFailure == "" {
						t.Fatalf("missing output denial: %+v", st)
					}
				}
				if len(maps.entries) != 0 || len(maps.peers) != 0 || len(maps.fdb) != 0 {
					t.Fatal("denied output changed maps")
				}
			})
		}
	}
}

func TestEVPNControllerDelegationTarget(t *testing.T) {
	policy, err := parseInputPolicy(compositionPolicy(), nil)
	if err != nil {
		t.Fatal(err)
	}
	event := evpnPolicyFixture(t, false, "65000:7")
	for _, tc := range []struct {
		bd             uint16
		resolved, want bool
	}{{100, true, true}, {101, true, false}, {100, false, false}} {
		got := policy.delegates(event, func(bgp.RouteEvent) (string, uint16, bool) { return "", tc.bd, tc.resolved })
		if got != tc.want {
			t.Fatalf("BD %d resolved %v: got %v", tc.bd, tc.resolved, got)
		}
	}
	forbidden := evpnPolicyFixture(t, false, "65000:8")
	if policy.delegates(forbidden, func(bgp.RouteEvent) (string, uint16, bool) { return "", 100, true }) {
		t.Fatal("unauthorized RT delegated")
	}
	event.IsWithdraw = true
	if policy.delegates(event, func(bgp.RouteEvent) (string, uint16, bool) { return "", 100, true }) {
		t.Fatal("withdrawal withheld from built-in cleanup")
	}
}

func TestEVPNControllerRemoteConflictWithdrawal(t *testing.T) {
	for _, backend := range []string{BackendNative, BackendWASM} {
		t.Run(backend, func(t *testing.T) {
			path := func(imet bool, rd uint32, mac, remote, sid string) bgp.RouteEvent {
				return evpnPolicyPath(t, imet, "65000:7", rd, mac, remote, sid)
			}
			a := path(false, 7, "02:00:00:00:00:01", "2001:db8::1", "fd00:2::1")
			b := path(false, 9, "02:00:00:00:00:02", "2001:db8::1", "fd00:2::2")
			unrelated := path(false, 10, "02:00:00:00:00:03", "2001:db8::2", "fd00:2::3")
			source := &compositionSource{newFakeSource()}
			source.rib = []bgp.RouteEvent{a, unrelated, path(true, 8, "", "2001:db8::1", "fd00:3::1"), path(true, 11, "", "2001:db8::2", "fd00:3::2")}
			maps := &evpnValueFake{serviceFake: newServiceFake(), entries: map[bpf.FdbKey]*bpf.FdbEntry{}}
			manager, err := NewManager(ManagerConfig{AllowNative: true, Source: source, Headend: newFakeHeadendOps(), ForwardingMaps: maps, ResolveInputTarget: func(bgp.RouteEvent) (string, uint16, bool) { return "", 100, true }})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close(context.Background())
			policy := &v1.CplaneInputPolicy{Version: 1, Contexts: []*v1.CplaneInputContext{{Name: "l2", Grants: []*v1.CplaneInputGrant{{Families: []string{"evpn"}, RouteTargets: []string{"65000:7"}}}, DelegateEvpn: true, BridgeDomain: 100}}}
			reg := Registration{Name: "imet", Backend: backend, Config: []byte(`{"context":"l2","source":"fd00:feed::1","observe_only":false}`), Capabilities: wasm.Capabilities{wasm.CapEVPN: {}}, Input: policy}
			if backend == BackendNative {
				reg.NativeID = native.EVPNIMET
				reg.NativeVersion = native.ImplementationVersion
			} else {
				reg.Module, err = os.ReadFile("../../out/cplane-evpn-imet.wasm")
				if err != nil {
					if os.Getenv("VINBERO_CPLANE_PARITY") == "1" {
						t.Fatal(err)
					}
					t.Skip(err)
				}
			}
			if err = manager.Register(context.Background(), reg); err != nil {
				t.Fatal(err)
			}
			check := func(want map[string]string, peerCount int) {
				t.Helper()
				if !manager.WaitIdle("imet", 5*time.Second) {
					t.Fatal("worker did not drain")
				}
				st, _ := manager.StatsFor("imet")
				if !st.InputReady || st.InputFault != "" || st.OutputFailure != "" || st.DesiredRevision == 0 || st.DesiredRevision != st.AppliedRevision {
					t.Fatalf("unhealthy: %+v", st)
				}
				if len(maps.entries) != len(want) || len(maps.peerEntries) != peerCount {
					t.Fatalf("wrong output sizes: MACs=%v peers=%v", maps.entries, maps.peerEntries)
				}
				for key, entry := range maps.entries {
					mac := net.HardwareAddr(key.Mac[:]).String()
					sid, ok := want[mac]
					peer := maps.peerEntries[bpf.BdPeerKey{BdId: 100, Index: entry.PeerIndex}]
					if !ok || key.BdId != 100 || entry.IsStatic != 1 || peer == nil || peer.NumSegments != 1 || peer.Segments[0] != netip.MustParseAddr(sid).As16() {
						t.Fatalf("unexpected MAC %s entry %+v peer %+v", mac, entry, peer)
					}
				}
			}
			check(map[string]string{a.EVPN.MAC: "fd00:2::1", unrelated.EVPN.MAC: "fd00:2::3"}, 2)
			source.emit("imet", b)
			if !manager.WaitIdle("imet", 5*time.Second) {
				t.Fatal("conflicting input did not drain")
			}
			// A rejected whole set used to leave this unrelated MAC installed.
			unrelated.IsWithdraw = true
			source.emit("imet", unrelated)
			check(nil, 0)
			b.IsWithdraw = true
			source.emit("imet", b)
			check(map[string]string{a.EVPN.MAC: "fd00:2::1"}, 1)
			b = path(false, 9, "02:00:00:00:00:02", "2001:db8::1", "fd00:2::1")
			source.emit("imet", b)
			check(map[string]string{a.EVPN.MAC: "fd00:2::1", b.EVPN.MAC: "fd00:2::1"}, 1)
		})
	}
}
