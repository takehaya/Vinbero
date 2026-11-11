package gobgp_test

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	gobgpapi "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	gobgpsrv "github.com/osrg/gobgp/v4/pkg/server"
	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/gobgp"
	"github.com/takehaya/vinbero/pkg/evpn"
)

// Loopback ports of the ESI tests. Unprivileged: no BPF, no namespaces.
const (
	esiTxPort = 10181 // the Vinbero speaker (gobgp.Session)
	esiRxPort = 10182 // the receiving plain GoBGP
)

var evpnFamily = &gobgpapi.Family{Afi: gobgpapi.Family_AFI_L2VPN, Safi: gobgpapi.Family_SAFI_EVPN}

// startEVPNReceiver starts a plain GoBGP that peers with 127.0.0.1:txPort and
// negotiates EVPN. It stands for any remote node running GoBGP.
func startEVPNReceiver(t *testing.T, listen, txPort int32) *gobgpsrv.BgpServer {
	t.Helper()
	ctx := context.Background()
	rx := gobgpsrv.NewBgpServer()
	go rx.Serve()
	t.Cleanup(func() { rx.Stop() })
	if err := rx.StartBgp(ctx, &gobgpapi.StartBgpRequest{
		Global: &gobgpapi.Global{Asn: 65001, RouterId: "10.0.0.1", ListenPort: listen},
	}); err != nil {
		t.Fatalf("receiver StartBgp: %v", err)
	}
	if err := rx.AddPeer(ctx, &gobgpapi.AddPeerRequest{Peer: &gobgpapi.Peer{
		Conf: &gobgpapi.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65002},
		Transport: &gobgpapi.Transport{
			RemoteAddress: "127.0.0.1", RemotePort: uint32(txPort), LocalAddress: "127.0.0.1",
		},
		AfiSafis: []*gobgpapi.AfiSafi{{Config: &gobgpapi.AfiSafiConfig{Family: evpnFamily}}},
	}}); err != nil {
		t.Fatalf("receiver AddPeer: %v", err)
	}
	return rx
}

func evpnPathCount(rx *gobgpsrv.BgpServer) int {
	n := 0
	_ = rx.ListPath(apiutil.ListPathRequest{
		TableType: gobgpapi.TableType_TABLE_TYPE_GLOBAL, Family: gobgppkt.RF_EVPN,
	}, func(_ gobgppkt.NLRI, paths []*apiutil.Path) { n += len(paths) })
	return n
}

func peerState(rx *gobgpsrv.BgpServer) gobgpapi.PeerState_SessionState {
	st := gobgpapi.PeerState_SESSION_STATE_UNSPECIFIED
	_ = rx.ListPeer(context.Background(), &gobgpapi.ListPeerRequest{}, func(p *gobgpapi.Peer) {
		st = p.GetState().GetSessionState()
	})
	return st
}

// Every ESI type that evpn.ValidateESI accepts is accepted by a receiving
// GoBGP in all three route types that carry an ESI, and the session stays up.
// This is what keeps the validation from being stricter than needed.
func TestE2E_ValidESIsAreAcceptedByReceiver(t *testing.T) {
	ctx := context.Background()
	tx := gobgp.NewSession(zap.NewNop())
	if err := tx.Start(ctx, bgp.GlobalConfig{LocalASN: 65002, RouterID: "10.0.0.2", ListenPort: esiTxPort}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = tx.Stop(ctx) })
	if err := tx.AddPeer(ctx, bgp.PeerConfig{
		Neighbor: "127.0.0.1", PeerASN: 65001, HoldTimeSec: 90, KeepaliveSec: 30,
		Families: []bgp.Family{bgp.FamilyEVPN},
	}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	rx := startEVPNReceiver(t, esiRxPort, esiTxPort)
	waitSessionEstablished(t, tx, rx)

	esis := map[string][evpn.ESILen]byte{
		"arbitrary":  {0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		"lacp":       {1, 0xaa, 0xbb, 0xcc, 0, 0, 1, 0, 5, 0},
		"mstp":       {2, 0xaa, 0xbb, 0xcc, 0, 0, 1, 0x80, 0, 0},
		"mac":        {3, 0xaa, 0xbb, 0xcc, 0, 0, 1, 0, 0, 7},
		"routerid":   {4, 10, 0, 0, 1, 0, 0, 0, 9, 0},
		"as":         {5, 0, 0, 0xfd, 0xe8, 0, 0, 0, 3, 0},
		"mac-lastff": {3, 0xaa, 0xbb, 0xcc, 0, 0, 1, 0xff, 0xff, 0xff},
	}
	want := 0
	i := 0
	for name, esi := range esis {
		if err := evpn.ValidateESI(esi); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		i++
		rd := fmt.Sprintf("65000:%d", i)
		if err := tx.PushEVPNMac(ctx, bgp.EVPNRoute{
			Type: bgp.EVPNRouteTypeMACIP, RD: rd, RTs: []string{"65000:100"}, ESI: esi,
			MAC: fmt.Sprintf("aa:bb:cc:00:00:%02x", i), SRv6SID: "fd00:2:2:d2::", NextHop: "2001:db8::1",
		}); err != nil {
			t.Fatalf("%s RT2: %v", name, err)
		}
		if err := tx.PushEVPNEthernetSegment(ctx, bgp.EVPNRoute{
			Type: bgp.EVPNRouteTypeEthernetSegment, RD: rd, ESI: esi,
			ESImportRT: "aa:bb:cc:dd:ee:ff", NextHop: "2001:db8::1",
		}); err != nil {
			t.Fatalf("%s RT4: %v", name, err)
		}
		if err := tx.PushEVPNEthernetAD(ctx, bgp.EVPNRoute{
			Type: bgp.EVPNRouteTypeEthernetAD, RD: rd, RTs: []string{"65000:100"}, ESI: esi,
			EthernetTag: bgp.EVPNMaxEthernetTag, NextHop: "2001:db8::1",
		}); err != nil {
			t.Fatalf("%s RT1: %v", name, err)
		}
		want += 3
	}
	waitFor(t, "every route received", 20*time.Second, func() bool { return evpnPathCount(rx) >= want })
	if st := peerState(rx); st != gobgpapi.PeerState_SESSION_STATE_ESTABLISHED {
		t.Errorf("session state after the routes = %v, want established", st)
	}
}

// Vinbero's encoders refuse an ESI that a receiver would reject, so the bad
// route never leaves the process.
func TestE2E_InvalidESIIsNotSent(t *testing.T) {
	ctx := context.Background()
	tx := gobgp.NewSession(zap.NewNop())
	if err := tx.Start(ctx, bgp.GlobalConfig{LocalASN: 65002, RouterID: "10.0.0.2", ListenPort: esiTxPort + 10}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = tx.Stop(ctx) })
	bad := [evpn.ESILen]byte{1, 0xaa, 0xbb, 0xcc, 0, 0, 1, 0, 5, 1}
	for name, err := range map[string]error{
		"RT2": tx.PushEVPNMac(ctx, bgp.EVPNRoute{Type: bgp.EVPNRouteTypeMACIP, RD: "65000:1", RTs: []string{"65000:100"},
			ESI: bad, MAC: "aa:bb:cc:00:00:01", SRv6SID: "fd00:2:2:d2::", NextHop: "2001:db8::1"}),
		"RT4": tx.PushEVPNEthernetSegment(ctx, bgp.EVPNRoute{Type: bgp.EVPNRouteTypeEthernetSegment, RD: "65000:1",
			ESI: bad, ESImportRT: "aa:bb:cc:dd:ee:ff", NextHop: "2001:db8::1"}),
		"RT1": tx.PushEVPNEthernetAD(ctx, bgp.EVPNRoute{Type: bgp.EVPNRouteTypeEthernetAD, RD: "65000:1", RTs: []string{"65000:100"},
			ESI: bad, EthernetTag: bgp.EVPNMaxEthernetTag, NextHop: "2001:db8::1"}),
	} {
		if err == nil {
			t.Errorf("%s with an invalid ESI was pushed", name)
		}
	}
}

// The report this validation answers: a plain GoBGP that sends a type 1 ESI
// whose last octet is not zero makes the receiving GoBGP drop the session
// (EthernetSegmentIdentifier.DecodeFromBytes). The route is never accepted.
func TestE2E_ReceiverRejectsNonzeroReservedOctet(t *testing.T) {
	ctx := context.Background()
	txSrv := gobgpsrv.NewBgpServer()
	go txSrv.Serve()
	t.Cleanup(func() { txSrv.Stop() })
	if err := txSrv.StartBgp(ctx, &gobgpapi.StartBgpRequest{
		Global: &gobgpapi.Global{Asn: 65002, RouterId: "10.0.0.2", ListenPort: esiTxPort + 20},
	}); err != nil {
		t.Fatalf("StartBgp: %v", err)
	}
	if err := txSrv.AddPeer(ctx, &gobgpapi.AddPeerRequest{Peer: &gobgpapi.Peer{
		Conf:     &gobgpapi.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65001},
		AfiSafis: []*gobgpapi.AfiSafi{{Config: &gobgpapi.AfiSafiConfig{Family: evpnFamily}}},
		Transport: &gobgpapi.Transport{
			PassiveMode: true, LocalAddress: "127.0.0.1",
		},
	}}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	rx := startEVPNReceiver(t, esiRxPort+20, esiTxPort+20)
	waitFor(t, "session established", 30*time.Second, func() bool {
		return peerState(rx) == gobgpapi.PeerState_SESSION_STATE_ESTABLISHED
	})

	rd, _ := gobgppkt.ParseRouteDistinguisher("65000:1")
	esi := gobgppkt.EthernetSegmentIdentifier{Type: gobgppkt.ESI_LACP, Value: []byte{0xaa, 0xbb, 0xcc, 0, 0, 1, 0, 5, 1}}
	nlri := gobgppkt.NewEVPNNLRI(gobgppkt.EVPN_ETHERNET_SEGMENT_ROUTE, &gobgppkt.EVPNEthernetSegmentRoute{
		RD: rd, ESI: esi, IPAddressLength: 128, IPAddress: netip.MustParseAddr("2001:db8::1"),
	})
	mp, err := gobgppkt.NewPathAttributeMpReachNLRI(gobgppkt.RF_EVPN, []gobgppkt.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr("2001:db8::1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := txSrv.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{{
		Family: gobgppkt.RF_EVPN, Nlri: nlri,
		Attrs: []gobgppkt.PathAttributeInterface{gobgppkt.NewPathAttributeOrigin(0), mp},
	}}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "receiver leaves established", 20*time.Second, func() bool {
		return peerState(rx) != gobgpapi.PeerState_SESSION_STATE_ESTABLISHED
	})
	if n := evpnPathCount(rx); n != 0 {
		t.Errorf("receiver holds %d EVPN paths, want 0", n)
	}
}
