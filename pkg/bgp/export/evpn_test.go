package export

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// fakeEVPNAdv records RT2 advertise / withdraw calls.
type fakeEVPNAdv struct {
	pushed    []bgp.EVPNRoute
	withdrawn []bgp.EVPNMACKey
	pushErr   error
}

func (f *fakeEVPNAdv) PushEVPNMac(_ context.Context, r bgp.EVPNRoute) error {
	if f.pushErr != nil {
		return f.pushErr
	}
	f.pushed = append(f.pushed, r)
	return nil
}

func (f *fakeEVPNAdv) WithdrawEVPNMac(_ context.Context, key bgp.EVPNMACKey) error {
	f.withdrawn = append(f.withdrawn, key)
	return nil
}

func newTestEVPNExporter(t *testing.T) (*EVPNExporter, *fakeEVPNAdv, *fakeSidOps) {
	t.Helper()
	locs := locator.NewManager()
	if err := locs.Add(&locator.Locator{
		Name:              "LOC1",
		Prefix:            netip.MustParsePrefix("fd00:1:1::/48"),
		BlockLen:          32,
		NodeLen:           16,
		FunctionLen:       16,
		ArgumentLen:       64,
		Behavior:          locator.BehaviorClassic,
		FunctionAutoStart: 0x10,
		FunctionAutoEnd:   0xfffe,
	}); err != nil {
		t.Fatalf("add locator: %v", err)
	}
	adv := &fakeEVPNAdv{}
	sid := &fakeSidOps{}
	e := NewEVPNExporter(adv, sid, locs, vrfbgp.NewManager(), "2001:db8:ff::1", zap.NewNop())
	return e, adv, sid
}

func evpnTestBinding() vrfbgp.Binding {
	return vrfbgp.Binding{
		VRFName:        "evi100",
		RD:             "65000:100",
		ExportRTs:      []string{"65000:100"},
		DefaultLocator: "LOC1",
		BDID:           100,
	}
}

func TestEnableBDInstallsDT2U(t *testing.T) {
	e, _, sid := newTestEVPNExporter(t)
	if err := e.EnableBD(evpnTestBinding(), 10); err != nil {
		t.Fatalf("EnableBD: %v", err)
	}
	if len(sid.created) != 1 {
		t.Fatalf("want 1 End.DT2U SID installed, got %d: %+v", len(sid.created), sid.created)
	}
	if sid.created[0].action != endpointActionDT2U {
		t.Errorf("installed SID action = %d, want End.DT2U %d", sid.created[0].action, endpointActionDT2U)
	}
}

func TestEnableBDRejectsMissingFields(t *testing.T) {
	e, _, _ := newTestEVPNExporter(t)
	noBD := evpnTestBinding()
	noBD.BDID = 0
	if err := e.EnableBD(noBD, 10); err == nil {
		t.Error("EnableBD without bd_id should fail")
	}
	noRD := evpnTestBinding()
	noRD.RD = ""
	if err := e.EnableBD(noRD, 10); err == nil {
		t.Error("EnableBD without RD should fail")
	}
	badLoc := evpnTestBinding()
	badLoc.DefaultLocator = "NOPE"
	if err := e.EnableBD(badLoc, 10); err == nil {
		t.Error("EnableBD with an unknown locator should fail")
	}
}

func TestOnLocalMACAdvertisesRT2(t *testing.T) {
	e, adv, sid := newTestEVPNExporter(t)
	if err := e.EnableBD(evpnTestBinding(), 10); err != nil {
		t.Fatalf("EnableBD: %v", err)
	}
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	e.OnLocalMAC(100, mac, true)

	if len(adv.pushed) != 1 {
		t.Fatalf("want 1 RT2 advertised, got %d", len(adv.pushed))
	}
	r := adv.pushed[0]
	if r.Type != bgp.EVPNRouteTypeMACIP {
		t.Errorf("type = %d, want RT2", r.Type)
	}
	if r.RD != "65000:100" {
		t.Errorf("rd = %q", r.RD)
	}
	if len(r.RTs) != 1 || r.RTs[0] != "65000:100" {
		t.Errorf("rts = %v", r.RTs)
	}
	if r.MAC != mac.String() {
		t.Errorf("mac = %q, want %q", r.MAC, mac.String())
	}
	if r.NextHop != "2001:db8:ff::1" {
		t.Errorf("nexthop = %q, want the configured loopback", r.NextHop)
	}
	if r.RemoteSrc != "fd00:1:1::" {
		t.Errorf("remote_src = %q, want the locator base fd00:1:1::", r.RemoteSrc)
	}
	if r.SRv6SID+"/128" != sid.created[0].prefix {
		t.Errorf("SID = %q, want the installed End.DT2U %q", r.SRv6SID, sid.created[0].prefix)
	}
}

func TestOnLocalMACWithdrawMirrorsAdvertise(t *testing.T) {
	e, adv, _ := newTestEVPNExporter(t)
	if err := e.EnableBD(evpnTestBinding(), 10); err != nil {
		t.Fatalf("EnableBD: %v", err)
	}
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	e.OnLocalMAC(100, mac, true)
	e.OnLocalMAC(100, mac, false)
	if len(adv.withdrawn) != 1 {
		t.Fatalf("want 1 withdraw, got %d", len(adv.withdrawn))
	}
	k := adv.withdrawn[0]
	if k.RD != "65000:100" || k.MAC != mac.String() || k.EthernetTag != 0 {
		t.Errorf("withdraw key = %+v", k)
	}
}

func TestOnLocalMACAddIsIdempotent(t *testing.T) {
	e, adv, _ := newTestEVPNExporter(t)
	if err := e.EnableBD(evpnTestBinding(), 10); err != nil {
		t.Fatalf("EnableBD: %v", err)
	}
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	e.OnLocalMAC(100, mac, true)
	e.OnLocalMAC(100, mac, true) // duplicate learn
	if len(adv.pushed) != 1 {
		t.Errorf("a duplicate MAC learn should advertise once, got %d", len(adv.pushed))
	}
}

func TestOnLocalMACIgnoresUnboundBD(t *testing.T) {
	e, adv, _ := newTestEVPNExporter(t)
	e.OnLocalMAC(999, net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}, true)
	if len(adv.pushed) != 0 {
		t.Errorf("a MAC in an unbound BD must not be advertised, got %d", len(adv.pushed))
	}
}

func TestOnLocalMACWithdrawUnadvertisedIsNoop(t *testing.T) {
	e, adv, _ := newTestEVPNExporter(t)
	if err := e.EnableBD(evpnTestBinding(), 10); err != nil {
		t.Fatalf("EnableBD: %v", err)
	}
	// Delete a MAC we never advertised: must not issue a withdraw.
	e.OnLocalMAC(100, net.HardwareAddr{0xaa, 0, 0, 0, 0, 9}, false)
	if len(adv.withdrawn) != 0 {
		t.Errorf("withdraw of an unadvertised MAC must be a no-op, got %d", len(adv.withdrawn))
	}
}

func TestDisableBDWithdrawsAllAndReleases(t *testing.T) {
	e, adv, sid := newTestEVPNExporter(t)
	if err := e.EnableBD(evpnTestBinding(), 10); err != nil {
		t.Fatalf("EnableBD: %v", err)
	}
	e.OnLocalMAC(100, net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}, true)
	e.OnLocalMAC(100, net.HardwareAddr{0xaa, 0, 0, 0, 0, 2}, true)

	e.DisableBD(100)

	if len(adv.withdrawn) != 2 {
		t.Errorf("want 2 RT2 withdrawn on disable, got %d", len(adv.withdrawn))
	}
	if len(sid.deleted) != 1 {
		t.Errorf("want the End.DT2U SID released on disable, got %d", len(sid.deleted))
	}
	// The BD is gone, so re-enabling must succeed.
	if err := e.EnableBD(evpnTestBinding(), 10); err != nil {
		t.Fatalf("re-enable after disable: %v", err)
	}
}

func TestOnLocalMACPushFailureNotRecorded(t *testing.T) {
	e, adv, _ := newTestEVPNExporter(t)
	if err := e.EnableBD(evpnTestBinding(), 10); err != nil {
		t.Fatalf("EnableBD: %v", err)
	}
	adv.pushErr = errors.New("push failed")
	e.OnLocalMAC(100, net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}, true)
	// The push failed, so the MAC must not be recorded -- a later disable must
	// not withdraw a route that was never advertised.
	adv.pushErr = nil
	e.DisableBD(100)
	if len(adv.withdrawn) != 0 {
		t.Errorf("a failed push must not be recorded, but disable withdrew %d", len(adv.withdrawn))
	}
}
