package server

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/netresource"
	"github.com/takehaya/vinbero/pkg/vinbero"
)

// A type 1 ESI whose last octet is not zero: a receiving GoBGP resets the
// session on it, so no entry point may take it.
const badESI = "01:aa:bb:cc:00:00:01:00:05:01"

func wantESIError(t *testing.T, what, reason string) {
	t.Helper()
	if !strings.Contains(reason, "octet 10 is 0x01 but must be 0x00") || !strings.Contains(reason, "layout:") {
		t.Errorf("%s: reason %q does not name the octet and the layout", what, reason)
	}
}

func TestEsiValidation_AdvertiseEvpnMac(t *testing.T) {
	fe := &fakeEvpnAdv{}
	s := NewBgpRouteServer(nil, nil, fe, nil, nil, nil)
	resp, err := s.BgpAdvertiseEvpnMac(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseEvpnMacRequest{Macs: []*v1.BgpEvpnMac{{
			Rd: "65000:100", Mac: "aa:bb:cc:00:00:01", Sid: "fd00:2:2:d2::", NextHop: "2001:db8::1", Esi: badESI,
		}}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.Errors) != 1 || len(resp.Msg.Advertised) != 0 || len(fe.pushed) != 0 {
		t.Fatalf("errors=%d advertised=%d pushed=%d", len(resp.Msg.Errors), len(resp.Msg.Advertised), len(fe.pushed))
	}
	wantESIError(t, "RT2", resp.Msg.Errors[0].Reason)
}

func TestEsiValidation_AdvertiseEvpnEs(t *testing.T) {
	fe := &fakeEvpnAdv{}
	s := NewBgpRouteServer(nil, nil, fe, nil, nil, nil)
	resp, err := s.BgpAdvertiseEvpnEs(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseEvpnEsRequest{Segments: []*v1.BgpEvpnEs{{
			Rd: "65000:100", Esi: badESI, EsImportRt: "aa:bb:cc:00:00:01", NextHop: "2001:db8::1",
		}}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.Errors) != 1 || len(fe.esPushed) != 0 {
		t.Fatalf("errors=%d pushed=%d", len(resp.Msg.Errors), len(fe.esPushed))
	}
	wantESIError(t, "RT4", resp.Msg.Errors[0].Reason)
}

func TestEsiValidation_AdvertiseEvpnAd(t *testing.T) {
	fe := &fakeEvpnAdv{}
	s := NewBgpRouteServer(nil, nil, fe, nil, nil, nil)
	resp, err := s.BgpAdvertiseEvpnAd(context.Background(),
		connect.NewRequest(&v1.BgpAdvertiseEvpnAdRequest{Routes: []*v1.BgpEvpnAd{{
			Rd: "65000:100", Esi: badESI, EthernetTag: 0xFFFFFFFF, NextHop: "2001:db8::1",
		}}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.Errors) != 1 || len(fe.adPushed) != 0 {
		t.Fatalf("errors=%d pushed=%d", len(resp.Msg.Errors), len(fe.adPushed))
	}
	wantESIError(t, "RT1", resp.Msg.Errors[0].Reason)
}

// A valid ESI of each defined type still goes through.
func TestEsiValidation_ValidTypesAreAdvertised(t *testing.T) {
	fe := &fakeEvpnAdv{}
	s := NewBgpRouteServer(nil, nil, fe, nil, nil, nil)
	for i, esi := range []string{
		"00:01:02:03:04:05:06:07:08:09", "01:aa:bb:cc:00:00:01:00:05:00", "02:aa:bb:cc:00:00:01:80:00:00",
		"03:aa:bb:cc:00:00:01:00:00:ff", "04:0a:00:00:01:00:00:00:09:00", "05:00:00:fd:e8:00:00:00:03:00",
	} {
		resp, err := s.BgpAdvertiseEvpnEs(context.Background(),
			connect.NewRequest(&v1.BgpAdvertiseEvpnEsRequest{Segments: []*v1.BgpEvpnEs{{
				Rd: "65000:100", Esi: esi, EsImportRt: "aa:bb:cc:00:00:01", NextHop: "2001:db8::1",
			}}}))
		if err != nil || len(resp.Msg.Errors) != 0 || len(fe.esPushed) != i+1 {
			t.Errorf("%s: err=%v errors=%v pushed=%d", esi, err, resp.Msg.GetErrors(), len(fe.esPushed))
		}
	}
}

// Withdrawing and deleting still take the value, so a stored one can be removed.
func TestEsiValidation_WithdrawAcceptsStoredValue(t *testing.T) {
	fe := &fakeEvpnAdv{}
	s := NewBgpRouteServer(nil, nil, fe, nil, nil, nil)
	resp, err := s.BgpWithdrawEvpnEs(context.Background(),
		connect.NewRequest(&v1.BgpWithdrawEvpnEsRequest{Keys: []*v1.BgpEvpnEsKey{{Rd: "65000:100", Esi: badESI}}}))
	if err != nil || len(resp.Msg.Errors) != 0 || len(fe.esWithdrawn) != 1 {
		t.Errorf("withdraw: err=%v %+v", err, resp.Msg)
	}
}

func TestEsiValidation_EsCreate(t *testing.T) {
	m := memEsiMap{}
	hook := &recordingES{}
	elected := 0
	s := NewEthernetSegmentServer(nil, func([bpf.ESILen]byte) { elected++ }, hook, zap.NewNop())
	res, err := netresource.NewResourceManager(filepath.Join(t.TempDir(), "state.json"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	s.SetSegments(vinbero.NewEthernetSegments(m, res, zap.NewNop()))
	resp, err := s.EsCreate(context.Background(), connect.NewRequest(&v1.EsCreateRequest{Entries: []*v1.EthernetSegment{{
		Esi: badESI, LocalAttached: true, LocalPeSrcAddr: "fc00:1::1",
		RedundancyMode: v1.EsiRedundancyMode_ESI_REDUNDANCY_MODE_ALL_ACTIVE, Rd: "65000:1",
	}}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.Errors) != 1 || len(resp.Msg.Created) != 0 || len(m) != 0 || hook.enabled != 0 || elected != 0 {
		t.Fatalf("errors=%d created=%d map=%d enabled=%d elected=%d", len(resp.Msg.Errors), len(resp.Msg.Created), len(m), hook.enabled, elected)
	}
	wantESIError(t, "es create", resp.Msg.Errors[0].Reason)
}

// A bd-peer create with such an ESI fails before it reaches the map (the
// server has none here, so reaching it would panic).
func TestEsiValidation_BdPeerCreate(t *testing.T) {
	s := NewBdPeerServer(nil)
	resp, err := s.BdPeerCreate(context.Background(), connect.NewRequest(&v1.BdPeerCreateRequest{Peers: []*v1.BdPeer{{
		BdId: 100, SrcAddr: "fc00::1", Segments: []string{"fc00::2"}, Esi: badESI,
	}}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.Errors) != 1 || len(resp.Msg.Created) != 0 {
		t.Fatalf("got %+v", resp.Msg)
	}
	wantESIError(t, "bd-peer create", resp.Msg.Errors[0].Reason)
}

// An L2 circuit with such an ESI is refused before the circuit book is asked.
func TestEsiValidation_HeadendL2Create(t *testing.T) {
	s := NewHeadendL2Server(nil)
	s.SetCircuits(&fakeBook{create: func(c vinbero.L2Circuit) error {
		t.Error("the circuit book was asked to create a circuit with an invalid ESI")
		return nil
	}})
	resp, err := s.HeadendL2Create(context.Background(), connect.NewRequest(&v1.HeadendL2CreateRequest{
		HeadendL2S: []*v1.HeadendL2{{InterfaceName: "lo", SrcAddr: "fc00::1", Segments: []string{"fc00::2"}, BdId: 100, Esi: badESI}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.Errors) != 1 || len(resp.Msg.Created) != 0 {
		t.Fatalf("got %+v", resp.Msg)
	}
	wantESIError(t, "headend l2 create", resp.Msg.Errors[0].Reason)
}
