package cplane

import (
	"context"
	"net/netip"
	"testing"

	gp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

func compositionVPNFixture(t *testing.T, prefixes ...string) (*PluginOps, *fakeAdvertiser, *v1.PluginApplyChunk, netip.Addr) {
	t.Helper()
	p, _ := compositionOps(t)
	p.guard = testGuard()
	p.caps[wasm.CapAdvertise] = struct{}{}
	p.caps[wasm.CapLocalSID] = struct{}{}
	p.policy.contexts[0].families = append(p.policy.contexts[0].families, "vpnv4")
	p.localSIDs = NewLocalSIDSet(&fakeAllocator{}, newFakeSIDOps(), nil, nil)
	alloc, _, err := p.localSIDs.Apply(p.owner, []LocalSID{{Name: "self", Locator: "main", Slot: 33}}, unlimited)
	if err != nil {
		t.Fatal(err)
	}
	adv := &fakeAdvertiser{}
	p.advertise = NewAdvertiseSet(adv, p.leases)
	sid := gp.NewPathAttributePrefixSID(gp.NewSRv6ServiceTLV(gp.TLVTypeSRv6L3Service, gp.NewSRv6InformationSubTLV(alloc[0].SID, gp.END_DT4)))
	m := &v1.PluginApplyChunk{DesiredRevision: 1}
	for _, prefix := range prefixes {
		n, err := gp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix(prefix), *gp.NewMPLSLabelStack(0), gp.NewRouteDistinguisherTwoOctetAS(0, 0))
		if err != nil {
			t.Fatal(err)
		}
		mp, err := gp.NewPathAttributeMpReachNLRI(gp.RF_IPv4_VPN, []gp.PathNLRI{{NLRI: n}}, netip.MustParseAddr("2001:db8::1"))
		if err != nil {
			t.Fatal(err)
		}
		a := rawAdvertisement(t, gp.RF_IPv4_VPN, n, gp.NewPathAttributeOrigin(0), mp, sid)
		a.Vrf = testVRF
		m.BgpAdvertisements = append(m.BgpAdvertisements, a)
	}
	if err := putComposition(p, m); err != nil {
		t.Fatal(err)
	}
	return p, adv, m, alloc[0].SID
}

func TestCompositionSIDUpdateRestoresAdvertisement(t *testing.T) {
	p, _, m, sid := compositionVPNFixture(t, "10.7.0.0/24")
	g, err := p.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_LOCAL_SID))
	if err != nil {
		t.Fatal(err)
	}
	chunk, err := proto.Marshal(&v1.PluginApplyChunk{LocalSids: []*v1.PluginLocalSid{{Name: "self", Locator: "main", Slot: 33, AuxRaw: []byte{1}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = p.ApplyPut(g, chunk); err != nil {
		t.Fatal(err)
	}
	if err = p.ApplyCommit(g); err != nil {
		t.Fatal(err)
	}
	if p.advertise.LiveCount(p.owner) != 0 || !p.localSIDs.OwnsSID(p.owner, sid) {
		t.Fatal("dependency withdrawal changed allocated SID")
	}
	m.DesiredRevision = 2
	if err = putComposition(p, m); err != nil {
		t.Fatal(err)
	}
	if p.advertise.LiveCount(p.owner) != 1 {
		t.Fatal("identical desired composition did not restore advertisement")
	}
}

func TestCompositionPartialWithdrawalRestoresOriginalDesired(t *testing.T) {
	p, adv, m, _ := compositionVPNFixture(t, "10.7.0.0/24", "10.8.0.0/24")
	adv.failWithdraw = "10.8.0.0/24"
	if err := putComposition(p, &v1.PluginApplyChunk{DesiredRevision: 2}); err == nil {
		t.Fatal("partial withdrawal failure hidden")
	}
	if p.advertise.LiveCount(p.owner) != 1 {
		t.Fatal("expected one successful withdrawal")
	}
	adv.failWithdraw = ""
	m.DesiredRevision = 3
	if err := putComposition(p, m); err != nil {
		t.Fatal(err)
	}
	if p.advertise.LiveCount(p.owner) != 2 || p.appliedRevision != 3 {
		t.Fatal("return to original desired set did not restore every advertisement")
	}
}

func TestCompositionTeardownFencesCapturedWork(t *testing.T) {
	p, f := compositionOps(t)
	if err := putComposition(p, desiredComposition(1)); err != nil {
		t.Fatal(err)
	}
	// The relevant unregister teardown operations: stop guest calls, discard
	// open declarations and flush the owner before releasing registration.
	inst, err := wasm.Instantiate(t.Context(), wasm.Config{Name: "compose", Module: fixtureModule(t, "echo"), Ops: p})
	if err != nil {
		t.Fatal(err)
	}
	captured := p.latestComposition
	manager := &Manager{logger: zap.NewNop()}
	manager.teardown(t.Context(), &plugin{ops: p, inst: inst})
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(f.uplinks) != 0 || len(f.v4) != 0 {
		t.Fatal("flush incomplete")
	}
	// Manager.ReconcileAdvertised can retain p in its pre-unregister snapshot.
	if _, err := p.ReconcileAdvertised(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.applyTransaction(captured); err != nil {
		t.Fatal(err)
	}
	p.BeginInstance()
	p.RetryPending()
	if len(f.uplinks) != 0 || len(f.v4) != 0 {
		t.Fatalf("unregistered owner's output resurrected: uplinks=%d headends=%d", len(f.uplinks), len(f.v4))
	}
}
