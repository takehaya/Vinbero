package server

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
	"go.uber.org/zap"
)

// fakeEvpnBridge records the EVPN coordinator's exporter calls so the
// binding-axis tests can assert which bridge domains were enabled / disabled.
type fakeEvpnBridge struct {
	enabled    map[uint16]bool // bd_ids currently enabled
	disabled   []uint16        // each DisableBD's bd_id, in order
	enableCnt  int             // total EnableBD calls (for replay-storm tests)
	disableCnt int             // total DisableBD calls
}

func (f *fakeEvpnBridge) EnableBD(b vrfbgp.Binding, _ uint32) error {
	if f.enabled == nil {
		f.enabled = make(map[uint16]bool)
	}
	f.enabled[b.BDID] = true
	f.enableCnt++
	return nil
}

func (f *fakeEvpnBridge) DisableBD(bdID uint16) {
	delete(f.enabled, bdID)
	f.disabled = append(f.disabled, bdID)
	f.disableCnt++
}

func (f *fakeEvpnBridge) SIDsForBD(uint16) []string { return nil }

// newEvpnCoordForTest builds a coordinator over hook, treating the bd_id ->
// ifindex entries in bridges as the bridges that already exist; replayFDB is a
// no-op.
func newEvpnCoordForTest(hook EvpnBridgeHook, bridges map[uint16]uint32) *EvpnCoordinator {
	return NewEvpnCoordinator(
		hook,
		func(bdID uint16) (uint32, bool) { ifindex, ok := bridges[bdID]; return ifindex, ok },
		func(int) error { return nil },
		zap.NewNop(),
	)
}

// An out-of-range bd_id (> uint16) is rejected as a per-item error rather than
// silently truncated into a different bridge domain.
func TestVrfBgpBind_BdIdOutOfRange(t *testing.T) {
	s := NewVrfBgpServer(vrfbgp.NewManager(), nil, nil, nil)
	resp, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{
			{VrfName: "evi-ok", ImportRts: []string{"65000:100"}, BdId: 100},
			{VrfName: "evi-bad", ImportRts: []string{"65000:101"}, BdId: 70000},
		},
	}))
	if err != nil {
		t.Fatalf("VrfBgpBind: %v", err)
	}
	if len(resp.Msg.Bound) != 1 || resp.Msg.Bound[0].GetVrfName() != "evi-ok" {
		t.Errorf("only the in-range binding should be bound; bound=%v", resp.Msg.Bound)
	}
	if len(resp.Msg.Errors) != 1 {
		t.Fatalf("out-of-range bd_id must be a per-item error; errors=%v", resp.Msg.Errors)
	}
	if got := s.mgr.List(); len(got) != 1 || got[0].BDID != 100 {
		t.Errorf("only the in-range BD must be stored; got %+v", got)
	}
}

type fakeVrfExporter struct {
	added    []string
	removed  []string
	addErr   error
	failOnRD string                    // AddVRF fails for a binding whose RD equals this
	enabled  map[string]vrfbgp.Binding // current enabled state, modelling the real exporter
}

// AddVRF models the real Exporter: it removes any prior enablement before
// (attempting and possibly) failing, so a failed AddVRF leaves the VRF disabled.
func (f *fakeVrfExporter) AddVRF(b vrfbgp.Binding) error {
	if f.enabled == nil {
		f.enabled = make(map[string]vrfbgp.Binding)
	}
	if f.addErr != nil {
		delete(f.enabled, b.VRFName)
		return f.addErr
	}
	if f.failOnRD != "" && b.RD == f.failOnRD {
		delete(f.enabled, b.VRFName)
		return errors.New("boom")
	}
	f.enabled[b.VRFName] = b
	f.added = append(f.added, b.VRFName)
	return nil
}

func (f *fakeVrfExporter) RemoveVRF(name string) {
	delete(f.enabled, name)
	f.removed = append(f.removed, name)
}

// A successful bind drives the exporter's AddVRF, and an unbind its RemoveVRF.
func TestVrfBgpBind_DrivesExporter(t *testing.T) {
	exp := &fakeVrfExporter{}
	s := NewVrfBgpServer(vrfbgp.NewManager(), exp, nil, nil)
	resp, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{
			{VrfName: "vrf1", Rd: "65100:200", ExportRts: []string{"65000:200"}, DefaultLocator: "LOC1", Redistribute: []string{"static"}},
		},
	}))
	if err != nil {
		t.Fatalf("VrfBgpBind: %v", err)
	}
	if len(resp.Msg.Bound) != 1 {
		t.Fatalf("bound=%v errors=%v", resp.Msg.Bound, resp.Msg.Errors)
	}
	if len(exp.added) != 1 || exp.added[0] != "vrf1" {
		t.Errorf("AddVRF should be called for vrf1, got %v", exp.added)
	}
	if _, err := s.VrfBgpUnbind(context.Background(), connect.NewRequest(&v1.VrfBgpUnbindRequest{VrfNames: []string{"vrf1"}})); err != nil {
		t.Fatalf("VrfBgpUnbind: %v", err)
	}
	if len(exp.removed) != 1 || exp.removed[0] != "vrf1" {
		t.Errorf("RemoveVRF should be called for vrf1, got %v", exp.removed)
	}
}

// A failing AddVRF is a per-item error and rolls the manager bind back so the
// registry and the exporter stay consistent.
func TestVrfBgpBind_AddVRFFailureRollsBack(t *testing.T) {
	mgr := vrfbgp.NewManager()
	s := NewVrfBgpServer(mgr, &fakeVrfExporter{addErr: errors.New("boom")}, nil, nil)
	resp, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{
			{VrfName: "vrf1", Rd: "65100:200", DefaultLocator: "LOC1", Redistribute: []string{"static"}},
		},
	}))
	if err != nil {
		t.Fatalf("VrfBgpBind: %v", err)
	}
	if len(resp.Msg.Errors) != 1 {
		t.Errorf("AddVRF failure should be a per-item error; errors=%v", resp.Msg.Errors)
	}
	if got := mgr.List(); len(got) != 0 {
		t.Errorf("failed AddVRF must roll back the manager bind; got %+v", got)
	}
}

// Re-binding an already-bound VRF with a change the exporter rejects must
// restore the prior binding rather than dropping it from both registries.
func TestVrfBgpBind_RebindFailureRestoresPrior(t *testing.T) {
	mgr := vrfbgp.NewManager()
	exp := &fakeVrfExporter{failOnRD: "65100:999"}
	s := NewVrfBgpServer(mgr, exp, nil, nil)

	// Initial bind succeeds.
	if _, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{
			{VrfName: "vrf1", Rd: "65100:200", DefaultLocator: "LOC1", Redistribute: []string{"static"}},
		},
	})); err != nil {
		t.Fatalf("initial VrfBgpBind: %v", err)
	}

	// Re-bind with a changed RD the exporter rejects.
	resp, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{
			{VrfName: "vrf1", Rd: "65100:999", DefaultLocator: "LOC1", Redistribute: []string{"static"}},
		},
	}))
	if err != nil {
		t.Fatalf("re-bind VrfBgpBind: %v", err)
	}
	if len(resp.Msg.Errors) != 1 {
		t.Errorf("re-bind failure should be a per-item error; errors=%v", resp.Msg.Errors)
	}
	got := mgr.List()
	if len(got) != 1 || got[0].RD != "65100:200" {
		t.Errorf("re-bind failure must restore the prior binding (RD 65100:200); got %+v", got)
	}
	// The exporter must be re-enabled with the prior binding too, not just the
	// manager: without the restore AddVRF(prev), the failed re-bind would leave
	// the VRF disabled in the exporter.
	if eb, ok := exp.enabled["vrf1"]; !ok || eb.RD != "65100:200" {
		t.Errorf("re-bind failure must re-apply the prior binding to the exporter (RD 65100:200); got enabled=%+v", exp.enabled)
	}
}

// Two concurrent same-VRF binds — one the exporter accepts, one it rejects — must
// leave the manager and the exporter agreeing on the VRF, never the desync where
// the manager loses the binding while the exporter keeps advertising (or vice
// versa). Run under -race.
func TestVrfBgpBind_ConcurrentSameVRFStaysConsistent(t *testing.T) {
	for i := range 300 {
		mgr := vrfbgp.NewManager()
		exp := &fakeVrfExporter{failOnRD: "fail"}
		s := NewVrfBgpServer(mgr, exp, nil, nil)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = s.bindOne(&v1.VrfBgpBinding{VrfName: "vrf1", Rd: "ok", DefaultLocator: "LOC1", Redistribute: []string{"static"}})
		}()
		go func() {
			defer wg.Done()
			_, _ = s.bindOne(&v1.VrfBgpBinding{VrfName: "vrf1", Rd: "fail", DefaultLocator: "LOC1", Redistribute: []string{"static"}})
		}()
		wg.Wait()

		mb, mok := mgr.Get("vrf1")
		eb, eok := exp.enabled["vrf1"]
		if mok != eok {
			t.Fatalf("iter %d: manager has vrf1=%v but exporter has vrf1=%v (desync)", i, mok, eok)
		}
		if mok && mb.RD != eb.RD {
			t.Fatalf("iter %d: manager RD=%q != exporter RD=%q (desync)", i, mb.RD, eb.RD)
		}
	}
}

// The new rd / redistribute / max_prefixes fields survive a bind -> list round
// trip through protoToBinding and back, and import/export RTs are not swapped.
func TestVrfBgpList_RoundTripsNewFields(t *testing.T) {
	s := NewVrfBgpServer(vrfbgp.NewManager(), nil, nil, nil)
	if _, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{
			{
				VrfName:             "vrf1",
				Rd:                  "65100:200",
				ImportRts:           []string{"65000:200"},
				ExportRts:           []string{"65000:201"},
				Redistribute:        []string{"connected", "static"},
				MaxPrefixes:         42,
				DefaultLocator:      "LOC1",
				BdId:                100,
				MupGtp4SourcePrefix: "fd00:d::/64",
			},
		},
	})); err != nil {
		t.Fatalf("VrfBgpBind: %v", err)
	}
	resp, err := s.VrfBgpList(context.Background(), connect.NewRequest(&v1.VrfBgpListRequest{}))
	if err != nil {
		t.Fatalf("VrfBgpList: %v", err)
	}
	if len(resp.Msg.Bindings) != 1 {
		t.Fatalf("want 1 binding, got %d", len(resp.Msg.Bindings))
	}
	b := resp.Msg.Bindings[0]
	if b.GetRd() != "65100:200" {
		t.Errorf("rd = %q, want 65100:200", b.GetRd())
	}
	if got := b.GetRedistribute(); len(got) != 2 || got[0] != "connected" || got[1] != "static" {
		t.Errorf("redistribute = %v, want [connected static]", got)
	}
	if b.GetMaxPrefixes() != 42 {
		t.Errorf("max_prefixes = %d, want 42", b.GetMaxPrefixes())
	}
	if b.GetBdId() != 100 {
		t.Errorf("bd_id = %d, want 100", b.GetBdId())
	}
	if got := b.GetImportRts(); len(got) != 1 || got[0] != "65000:200" {
		t.Errorf("import_rts = %v, want [65000:200] (import/export must not be swapped)", got)
	}
	if got := b.GetExportRts(); len(got) != 1 || got[0] != "65000:201" {
		t.Errorf("export_rts = %v, want [65000:201] (import/export must not be swapped)", got)
	}
	if got := b.GetMupGtp4SourcePrefix(); got != "fd00:d::/64" {
		t.Errorf("mup_gtp4_source_prefix = %q, want fd00:d::/64", got)
	}
}

// fakeMupSrc records the RDs the binding mutations re-reconciled so the
// MUP GTP4 source-embed hook tests can pin when (and for which RD) it fires.
type fakeMupSrc struct{ rds []string }

func (f *fakeMupSrc) ReconcileMUPGTP4SrcForRD(rd string) { f.rds = append(f.rds, rd) }

// The MUP source-embed hook fires on a bind that carries a prefix, on a
// prefix change, and on an RD move (both RDs); it stays silent on an
// unrelated mutation of the same binding.
func TestVrfBgpBind_DrivesMupSrcReconcile(t *testing.T) {
	hook := &fakeMupSrc{}
	s := NewVrfBgpServer(vrfbgp.NewManager(), nil, nil, hook)

	bind := func(b *v1.VrfBgpBinding) {
		t.Helper()
		resp, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
			Bindings: []*v1.VrfBgpBinding{b},
		}))
		if err != nil {
			t.Fatalf("VrfBgpBind: %v", err)
		}
		if len(resp.Msg.Errors) != 0 {
			t.Fatalf("VrfBgpBind errors: %v", resp.Msg.Errors)
		}
	}

	// First bind with a prefix: one reconcile for the RD.
	bind(&v1.VrfBgpBinding{VrfName: "mup1", Rd: "65001:1", MupGtp4SourcePrefix: "fd00:d::/64"})
	if want := []string{"65001:1"}; !slices.Equal(hook.rds, want) {
		t.Fatalf("after first bind rds = %v, want %v", hook.rds, want)
	}

	// Unrelated re-bind (same prefix, new max_prefixes): no reconcile.
	bind(&v1.VrfBgpBinding{VrfName: "mup1", Rd: "65001:1", MupGtp4SourcePrefix: "fd00:d::/64", MaxPrefixes: 7})
	if len(hook.rds) != 1 {
		t.Fatalf("unrelated mutation must not reconcile; rds = %v", hook.rds)
	}

	// Prefix change: one reconcile.
	bind(&v1.VrfBgpBinding{VrfName: "mup1", Rd: "65001:1", MupGtp4SourcePrefix: "fd00:e::/64"})
	if want := []string{"65001:1", "65001:1"}; !slices.Equal(hook.rds, want) {
		t.Fatalf("after prefix change rds = %v, want %v", hook.rds, want)
	}

	// RD move with the prefix kept: both the new and the old RD reconcile
	// (the old one reverts to the plain encap source).
	bind(&v1.VrfBgpBinding{VrfName: "mup1", Rd: "65001:2", MupGtp4SourcePrefix: "fd00:e::/64"})
	if want := []string{"65001:1", "65001:1", "65001:2", "65001:1"}; !slices.Equal(hook.rds, want) {
		t.Fatalf("after RD move rds = %v, want %v", hook.rds, want)
	}

	// Prefix removed: one reconcile so the installs revert.
	bind(&v1.VrfBgpBinding{VrfName: "mup1", Rd: "65001:2"})
	if want := []string{"65001:1", "65001:1", "65001:2", "65001:1", "65001:2"}; !slices.Equal(hook.rds, want) {
		t.Fatalf("after prefix removal rds = %v, want %v", hook.rds, want)
	}
}

// Unbinding a VRF whose binding carried a source prefix reconciles its RD so
// the installed downlinks revert to the plain encap source.
func TestVrfBgpUnbind_DrivesMupSrcReconcile(t *testing.T) {
	hook := &fakeMupSrc{}
	s := NewVrfBgpServer(vrfbgp.NewManager(), nil, nil, hook)
	if _, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{
			{VrfName: "mup1", Rd: "65001:1", MupGtp4SourcePrefix: "fd00:d::/64"},
			{VrfName: "plain", Rd: "65001:9"},
		},
	})); err != nil {
		t.Fatalf("VrfBgpBind: %v", err)
	}
	hook.rds = nil
	if _, err := s.VrfBgpUnbind(context.Background(), connect.NewRequest(&v1.VrfBgpUnbindRequest{
		VrfNames: []string{"plain", "mup1"},
	})); err != nil {
		t.Fatalf("VrfBgpUnbind: %v", err)
	}
	// Only the prefix-carrying binding's RD reconciles.
	if want := []string{"65001:1"}; !slices.Equal(hook.rds, want) {
		t.Errorf("unbind rds = %v, want %v", hook.rds, want)
	}
}

// An invalid mup_gtp4_source_prefix — bad syntax, IPv4, longer than /96, or
// set without an rd — is a per-item bind error, and UpdateBinding surfaces
// it as InvalidArgument.
func TestVrfBgpBind_MupGtp4SourcePrefixValidation(t *testing.T) {
	s := NewVrfBgpServer(vrfbgp.NewManager(), nil, nil, nil)
	bad := []*v1.VrfBgpBinding{
		{VrfName: "v1", Rd: "65001:1", MupGtp4SourcePrefix: "not-a-prefix"},
		{VrfName: "v2", Rd: "65001:2", MupGtp4SourcePrefix: "10.0.0.0/24"},
		{VrfName: "v3", Rd: "65001:3", MupGtp4SourcePrefix: "fd00:d::/97"},
		{VrfName: "v4", MupGtp4SourcePrefix: "fd00:d::/64"}, // no rd
	}
	resp, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{Bindings: bad}))
	if err != nil {
		t.Fatalf("VrfBgpBind: %v", err)
	}
	if len(resp.Msg.Errors) != len(bad) || len(resp.Msg.Bound) != 0 {
		t.Errorf("every invalid prefix must be a per-item error; bound=%v errors=%v",
			resp.Msg.Bound, resp.Msg.Errors)
	}
	if got := s.mgr.List(); len(got) != 0 {
		t.Errorf("no invalid binding may be stored; got %+v", got)
	}
}

// Binding a VRF whose bridge domain already has a bridge enables EVPN
// auto-advertise on the binding axis; binding one whose bridge has not been
// created yet is a no-op (BridgeCreate enables it when the bridge arrives).
func TestVrfBgpBind_EnablesEvpnOnlyWhenBridgeUp(t *testing.T) {
	hook := &fakeEvpnBridge{}
	// bd_id 100's bridge exists; bd_id 200's does not.
	coord := newEvpnCoordForTest(hook, map[uint16]uint32{100: 5})
	s := NewVrfBgpServer(vrfbgp.NewManager(), nil, coord, nil)

	if _, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{
			// Legacy ImportRts/ExportRts auto-expand into FamilyEVPN, which
			// is required so commitBinding fires EnableForBinding (a binding
			// with no FamilyEVPN would only push RT3 with empty RTs).
			{VrfName: "evi-up", Rd: "65100:100", BdId: 100, ImportRts: []string{"65000:100"}, ExportRts: []string{"65000:100"}},
			{VrfName: "evi-down", Rd: "65100:200", BdId: 200, ImportRts: []string{"65000:200"}, ExportRts: []string{"65000:200"}},
			{VrfName: "l3-only", Rd: "65100:300"}, // BDID 0: never EVPN
		},
	})); err != nil {
		t.Fatalf("VrfBgpBind: %v", err)
	}
	if !hook.enabled[100] {
		t.Errorf("bd_id 100 (bridge up) must be EVPN-enabled on bind; enabled=%v", hook.enabled)
	}
	if hook.enabled[200] {
		t.Errorf("bd_id 200 (no bridge yet) must NOT be enabled on bind; enabled=%v", hook.enabled)
	}
	if hook.enabled[0] {
		t.Errorf("an L3VPN-only binding (bd_id 0) must never touch EVPN; enabled=%v", hook.enabled)
	}
}

// Unbinding a VRF disables its bridge domain's EVPN auto-advertise even though
// the bridge device is still up — closing the gap where the exporter kept
// originating RT2/RT3 under a removed RD/RT.
func TestVrfBgpUnbind_DisablesEvpn(t *testing.T) {
	hook := &fakeEvpnBridge{}
	coord := newEvpnCoordForTest(hook, map[uint16]uint32{100: 5})
	s := NewVrfBgpServer(vrfbgp.NewManager(), nil, coord, nil)

	if _, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{{VrfName: "evi", Rd: "65100:100", BdId: 100, ImportRts: []string{"65000:100"}, ExportRts: []string{"65000:100"}}},
	})); err != nil {
		t.Fatalf("VrfBgpBind: %v", err)
	}
	if !hook.enabled[100] {
		t.Fatalf("precondition: bd_id 100 should be enabled after bind; enabled=%v", hook.enabled)
	}
	if _, err := s.VrfBgpUnbind(context.Background(), connect.NewRequest(&v1.VrfBgpUnbindRequest{VrfNames: []string{"evi"}})); err != nil {
		t.Fatalf("VrfBgpUnbind: %v", err)
	}
	if len(hook.disabled) != 1 || hook.disabled[0] != 100 {
		t.Errorf("VrfBgpUnbind must DisableBD(100); disabled=%v", hook.disabled)
	}
	if hook.enabled[100] {
		t.Errorf("bd_id 100 must be disabled after unbind; enabled=%v", hook.enabled)
	}
}

// Re-binding a VRF onto a different bridge domain disables the old BD before
// enabling the new one, so the vacated BD stops advertising.
func TestVrfBgpBind_RebindMovingBridgeDomainDisablesOld(t *testing.T) {
	hook := &fakeEvpnBridge{}
	coord := newEvpnCoordForTest(hook, map[uint16]uint32{100: 5, 200: 6})
	s := NewVrfBgpServer(vrfbgp.NewManager(), nil, coord, nil)

	bind := func(bdID uint32) {
		if _, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
			Bindings: []*v1.VrfBgpBinding{{VrfName: "evi", Rd: "65100:100", BdId: bdID, ImportRts: []string{"65000:100"}, ExportRts: []string{"65000:100"}}},
		})); err != nil {
			t.Fatalf("VrfBgpBind bd_id %d: %v", bdID, err)
		}
	}
	bind(100)
	bind(200) // move the VRF to a different bridge domain
	if !slices.Contains(hook.disabled, uint16(100)) {
		t.Errorf("re-bind moving bd_id 100 -> 200 must DisableBD(100); disabled=%v", hook.disabled)
	}
	if !hook.enabled[200] {
		t.Errorf("bd_id 200 must be enabled after the move; enabled=%v", hook.enabled)
	}
	if hook.enabled[100] {
		t.Errorf("bd_id 100 must be disabled after the move; enabled=%v", hook.enabled)
	}
}

// A binding that declares FamilyEVPN but has no export-direction RT (e.g.
// `family add --family evpn` with no --rt, or import-only EVPN) must NOT
// fire EnableForBinding: pushing RT3/RT2 with an empty extended-community
// RT list is unimportable on every peer.
func TestVrfBgpBind_NoExportRTsKeepsEvpnGated(t *testing.T) {
	hook := &fakeEvpnBridge{}
	coord := newEvpnCoordForTest(hook, map[uint16]uint32{100: 5, 101: 6, 102: 7})
	s := NewVrfBgpServer(vrfbgp.NewManager(), nil, coord, nil)

	if _, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{
			{VrfName: "evi-empty", Rd: "65100:100", BdId: 100, Families: map[string]*v1.VrfBgpFamily{"evpn": {}}},
			{VrfName: "evi-imp-only", Rd: "65100:101", BdId: 101, Families: map[string]*v1.VrfBgpFamily{
				"evpn": {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:101", Direction: "import"}}},
			}},
			{VrfName: "evi-ok", Rd: "65100:102", BdId: 102, Families: map[string]*v1.VrfBgpFamily{
				"evpn": {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:102", Direction: "export"}}},
			}},
		},
	})); err != nil {
		t.Fatalf("VrfBgpBind: %v", err)
	}
	if hook.enabled[100] {
		t.Errorf("evpn family with zero RTs must not enable; enabled=%v", hook.enabled)
	}
	if hook.enabled[101] {
		t.Errorf("evpn family with import-only RT must not enable; enabled=%v", hook.enabled)
	}
	if !hook.enabled[102] {
		t.Errorf("evpn family with an export RT must enable; enabled=%v", hook.enabled)
	}
}

// bindForRPC sets up a one-binding fixture for the new RPC tests so each test
// does not re-do the VrfBgpBind boilerplate. Returns the server and the
// initial families on the binding so the test can assert "post-RPC state vs.
// initial state".
func bindForRPC(t *testing.T, vrfName string, families map[string]*v1.VrfBgpFamily) *VrfBgpServer {
	t.Helper()
	s := NewVrfBgpServer(vrfbgp.NewManager(), nil, nil, nil)
	if _, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{{VrfName: vrfName, Rd: "65100:1", Families: families}},
	})); err != nil {
		t.Fatalf("setup VrfBgpBind: %v", err)
	}
	return s
}

// connectCode unwraps a connect.Error so tests can assert the gRPC code.
func connectCode(t *testing.T, err error) connect.Code {
	t.Helper()
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("expected *connect.Error, got %T: %v", err, err)
	}
	return ce.Code()
}

// AddRouteTarget is idempotent: re-adding the same {family, rt, direction}
// returns success and the families map is unchanged (single entry, same
// direction bits, no duplicate).
func TestAddRouteTarget_Idempotent(t *testing.T) {
	s := bindForRPC(t, "vrf1", map[string]*v1.VrfBgpFamily{"vpnv4": {}})
	add := func() {
		_, err := s.AddRouteTarget(context.Background(), connect.NewRequest(&v1.AddRouteTargetRequest{
			VrfName:     "vrf1",
			Family:      "vpnv4",
			RouteTarget: &v1.VrfBgpRouteTarget{Rt: "65000:200", Direction: "import"},
		}))
		if err != nil {
			t.Fatalf("AddRouteTarget: %v", err)
		}
	}
	add()
	add()
	stored, _ := s.mgr.Get("vrf1")
	fp := stored.Families["vpnv4"]
	if len(fp.RouteTargets) != 1 || fp.RouteTargets[0].RT != "65000:200" || fp.RouteTargets[0].Direction != vrfbgp.DirectionImport {
		t.Errorf("re-adding the same {rt,direction} must be idempotent; families=%+v", stored.Families)
	}
}

// AddRouteTarget on the same RT with a different direction OR's the direction
// bits (import + export = both), keeping a single RT entry.
func TestAddRouteTarget_DirectionOR(t *testing.T) {
	s := bindForRPC(t, "vrf1", map[string]*v1.VrfBgpFamily{"vpnv4": {}})
	for _, dir := range []string{"import", "export"} {
		if _, err := s.AddRouteTarget(context.Background(), connect.NewRequest(&v1.AddRouteTargetRequest{
			VrfName:     "vrf1",
			Family:      "vpnv4",
			RouteTarget: &v1.VrfBgpRouteTarget{Rt: "65000:200", Direction: dir},
		})); err != nil {
			t.Fatalf("AddRouteTarget %s: %v", dir, err)
		}
	}
	stored, _ := s.mgr.Get("vrf1")
	fp := stored.Families["vpnv4"]
	if len(fp.RouteTargets) != 1 || fp.RouteTargets[0].Direction != vrfbgp.DirectionBoth {
		t.Errorf("import+export must OR to both on the same RT; families=%+v", stored.Families)
	}
}

// AddRouteTarget on an undeclared family returns NotFound rather than silently
// promoting an RT-level call into a family-level one.
func TestAddRouteTarget_UndeclaredFamilyIsNotFound(t *testing.T) {
	s := bindForRPC(t, "vrf1", map[string]*v1.VrfBgpFamily{"vpnv4": {}})
	_, err := s.AddRouteTarget(context.Background(), connect.NewRequest(&v1.AddRouteTargetRequest{
		VrfName:     "vrf1",
		Family:      "evpn",
		RouteTarget: &v1.VrfBgpRouteTarget{Rt: "65000:200", Direction: "import"},
	}))
	if err == nil {
		t.Fatalf("AddRouteTarget on undeclared family should fail")
	}
	if got := connectCode(t, err); got != connect.CodeNotFound {
		t.Errorf("undeclared family must be NotFound, got %v", got)
	}
}

// AddRouteTarget on an unknown vrf_name returns NotFound per the error code
// table (the design's "vrf_name 無し" column).
func TestAddRouteTarget_UnknownVRFIsNotFound(t *testing.T) {
	s := NewVrfBgpServer(vrfbgp.NewManager(), nil, nil, nil)
	_, err := s.AddRouteTarget(context.Background(), connect.NewRequest(&v1.AddRouteTargetRequest{
		VrfName:     "missing",
		Family:      "vpnv4",
		RouteTarget: &v1.VrfBgpRouteTarget{Rt: "65000:200", Direction: "import"},
	}))
	if err == nil || connectCode(t, err) != connect.CodeNotFound {
		t.Errorf("unknown vrf_name must be NotFound, got %v", err)
	}
}

// AddRouteTarget rejects malformed family / direction strings as
// InvalidArgument (the design table's "family 名不正 / direction 不正").
func TestAddRouteTarget_InvalidArgs(t *testing.T) {
	s := bindForRPC(t, "vrf1", map[string]*v1.VrfBgpFamily{"vpnv4": {}})
	tests := []struct {
		name string
		req  *v1.AddRouteTargetRequest
	}{
		{"bad family", &v1.AddRouteTargetRequest{VrfName: "vrf1", Family: "bogus", RouteTarget: &v1.VrfBgpRouteTarget{Rt: "65000:1", Direction: "import"}}},
		{"bad direction", &v1.AddRouteTargetRequest{VrfName: "vrf1", Family: "vpnv4", RouteTarget: &v1.VrfBgpRouteTarget{Rt: "65000:1", Direction: "bogus"}}},
		{"empty rt", &v1.AddRouteTargetRequest{VrfName: "vrf1", Family: "vpnv4", RouteTarget: &v1.VrfBgpRouteTarget{Rt: "", Direction: "import"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.AddRouteTarget(context.Background(), connect.NewRequest(tc.req))
			if err == nil || connectCode(t, err) != connect.CodeInvalidArgument {
				t.Errorf("want InvalidArgument, got %v", err)
			}
		})
	}
}

// RemoveRouteTarget with a specific direction clears only that direction bit,
// leaving the other bit in place; the RT is not removed while any bit remains.
func TestRemoveRouteTarget_DirectionLevel(t *testing.T) {
	s := bindForRPC(t, "vrf1", map[string]*v1.VrfBgpFamily{
		"vpnv4": {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:200", Direction: "both"}}},
	})
	if _, err := s.RemoveRouteTarget(context.Background(), connect.NewRequest(&v1.RemoveRouteTargetRequest{
		VrfName: "vrf1", Family: "vpnv4", Rt: "65000:200", Direction: "export",
	})); err != nil {
		t.Fatalf("RemoveRouteTarget: %v", err)
	}
	stored, _ := s.mgr.Get("vrf1")
	fp := stored.Families["vpnv4"]
	if len(fp.RouteTargets) != 1 || fp.RouteTargets[0].Direction != vrfbgp.DirectionImport {
		t.Errorf("removing export from both should leave import; families=%+v", stored.Families)
	}
}

// RemoveRouteTarget with an empty direction strips the entire RT regardless of
// which bits were set (the design's "direction 省略 (= 空文字) なら direction
// に関わらず削除").
func TestRemoveRouteTarget_EmptyDirectionRemovesAll(t *testing.T) {
	s := bindForRPC(t, "vrf1", map[string]*v1.VrfBgpFamily{
		"vpnv4": {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:200", Direction: "both"}}},
	})
	if _, err := s.RemoveRouteTarget(context.Background(), connect.NewRequest(&v1.RemoveRouteTargetRequest{
		VrfName: "vrf1", Family: "vpnv4", Rt: "65000:200",
	})); err != nil {
		t.Fatalf("RemoveRouteTarget: %v", err)
	}
	stored, _ := s.mgr.Get("vrf1")
	if got := stored.Families["vpnv4"].RouteTargets; len(got) != 0 {
		t.Errorf("empty direction must remove the RT entirely; got %+v", got)
	}
}

// RemoveRouteTarget on a missing entry is idempotent success (per the error
// code table's "該当 RT が無くても idempotent success").
func TestRemoveRouteTarget_MissingIsIdempotent(t *testing.T) {
	s := bindForRPC(t, "vrf1", map[string]*v1.VrfBgpFamily{"vpnv4": {}})
	if _, err := s.RemoveRouteTarget(context.Background(), connect.NewRequest(&v1.RemoveRouteTargetRequest{
		VrfName: "vrf1", Family: "vpnv4", Rt: "65000:999",
	})); err != nil {
		t.Errorf("removing a missing RT must succeed (idempotent); got %v", err)
	}
}

// AddFamily on an already-declared family returns AlreadyExists so the
// operator picks UpdateBinding for a deliberate replace.
func TestAddFamily_AlreadyExists(t *testing.T) {
	s := bindForRPC(t, "vrf1", map[string]*v1.VrfBgpFamily{"vpnv4": {}})
	_, err := s.AddFamily(context.Background(), connect.NewRequest(&v1.AddFamilyRequest{
		VrfName: "vrf1", Family: "vpnv4", Config: &v1.VrfBgpFamily{},
	}))
	if err == nil || connectCode(t, err) != connect.CodeAlreadyExists {
		t.Errorf("re-AddFamily must be AlreadyExists, got %v", err)
	}
}

// RemoveFamily on a missing family returns NotFound (the design's
// "RemoveFamily は family が無い場合は NotFound" rule, distinguishing a true
// miss from a silent no-op).
func TestRemoveFamily_MissingIsNotFound(t *testing.T) {
	s := bindForRPC(t, "vrf1", map[string]*v1.VrfBgpFamily{"vpnv4": {}})
	_, err := s.RemoveFamily(context.Background(), connect.NewRequest(&v1.RemoveFamilyRequest{
		VrfName: "vrf1", Family: "evpn",
	}))
	if err == nil || connectCode(t, err) != connect.CodeNotFound {
		t.Errorf("RemoveFamily on missing family must be NotFound, got %v", err)
	}
}

// ListRouteTargets with no filter returns every family; a family filter
// restricts to that one family; a direction filter drops RTs whose direction
// bitmask does not cover the filter direction.
func TestListRouteTargets_Filters(t *testing.T) {
	s := bindForRPC(t, "vrf1", map[string]*v1.VrfBgpFamily{
		"vpnv4": {RouteTargets: []*v1.VrfBgpRouteTarget{
			{Rt: "65000:200", Direction: "import"},
			{Rt: "65000:201", Direction: "export"},
		}},
		"vpnv6": {RouteTargets: []*v1.VrfBgpRouteTarget{
			{Rt: "65000:300", Direction: "both"},
		}},
	})
	all, err := s.ListRouteTargets(context.Background(), connect.NewRequest(&v1.ListRouteTargetsRequest{VrfName: "vrf1"}))
	if err != nil {
		t.Fatalf("ListRouteTargets: %v", err)
	}
	if len(all.Msg.Families) != 2 {
		t.Errorf("unfiltered list must return every family; got %+v", all.Msg.Families)
	}
	byFam, err := s.ListRouteTargets(context.Background(), connect.NewRequest(&v1.ListRouteTargetsRequest{VrfName: "vrf1", Family: "vpnv6"}))
	if err != nil {
		t.Fatalf("ListRouteTargets family filter: %v", err)
	}
	if len(byFam.Msg.Families) != 1 || byFam.Msg.Families[0].GetFamily() != "vpnv6" {
		t.Errorf("family filter must keep only vpnv6; got %+v", byFam.Msg.Families)
	}
	byDir, err := s.ListRouteTargets(context.Background(), connect.NewRequest(&v1.ListRouteTargetsRequest{VrfName: "vrf1", Direction: "import"}))
	if err != nil {
		t.Fatalf("ListRouteTargets direction filter: %v", err)
	}
	// import filter keeps the import RT under vpnv4 and the both RT under vpnv6
	// (both covers import); the export-only RT under vpnv4 is filtered out.
	gotRTs := map[string]string{}
	for _, fam := range byDir.Msg.Families {
		for _, rt := range fam.GetRouteTargets() {
			gotRTs[rt.GetRt()] = fam.GetFamily()
		}
	}
	if gotRTs["65000:201"] != "" {
		t.Errorf("direction=import must drop export-only RT 65000:201; got %v", gotRTs)
	}
	if gotRTs["65000:200"] == "" || gotRTs["65000:300"] == "" {
		t.Errorf("direction=import must keep import and both RTs; got %v", gotRTs)
	}
}

// UpdateBinding is a full replace: a new families map drops out the entries
// that were on the prior binding but not on the new one.
func TestUpdateBinding_FullReplaceDropsOldFamilies(t *testing.T) {
	s := bindForRPC(t, "vrf1", map[string]*v1.VrfBgpFamily{
		"vpnv4": {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:200", Direction: "import"}}},
		"vpnv6": {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:300", Direction: "import"}}},
	})
	if _, err := s.UpdateBinding(context.Background(), connect.NewRequest(&v1.UpdateBindingRequest{
		Binding: &v1.VrfBgpBinding{
			VrfName: "vrf1",
			Rd:      "65100:1",
			Families: map[string]*v1.VrfBgpFamily{
				"vpnv4": {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:999", Direction: "import"}}},
			},
		},
	})); err != nil {
		t.Fatalf("UpdateBinding: %v", err)
	}
	stored, _ := s.mgr.Get("vrf1")
	if _, has := stored.Families["vpnv6"]; has {
		t.Errorf("UpdateBinding full replace must drop vpnv6 that is absent from the new binding; families=%+v", stored.Families)
	}
	rts := stored.Families["vpnv4"].RouteTargets
	if len(rts) != 1 || rts[0].RT != "65000:999" {
		t.Errorf("UpdateBinding must replace vpnv4 RTs with the new list; got %+v", rts)
	}
}

// UpdateBinding with a non-empty expected_version is rejected so a future
// optimistic-concurrency client does not silently no-op on this build.
func TestUpdateBinding_ExpectedVersionReserved(t *testing.T) {
	s := bindForRPC(t, "vrf1", map[string]*v1.VrfBgpFamily{"vpnv4": {}})
	_, err := s.UpdateBinding(context.Background(), connect.NewRequest(&v1.UpdateBindingRequest{
		Binding:         &v1.VrfBgpBinding{VrfName: "vrf1", Rd: "65100:1"},
		ExpectedVersion: "v0",
	}))
	if err == nil || connectCode(t, err) != connect.CodeUnimplemented {
		t.Errorf("expected_version must return Unimplemented in P0, got %v", err)
	}
}

// BatchModifyRouteTargets runs ops in order and the result reflects all of
// them; a clean batch leaves the binding in the documented final state.
func TestBatchModifyRouteTargets_Sequential(t *testing.T) {
	s := bindForRPC(t, "vrf1", map[string]*v1.VrfBgpFamily{"vpnv4": {}})
	_, err := s.BatchModifyRouteTargets(context.Background(), connect.NewRequest(&v1.BatchModifyRouteTargetsRequest{
		VrfName: "vrf1",
		Ops: []*v1.RouteTargetOp{
			{Kind: v1.RouteTargetOp_KIND_ADD, Family: "vpnv4", RouteTarget: &v1.VrfBgpRouteTarget{Rt: "65000:1", Direction: "import"}},
			{Kind: v1.RouteTargetOp_KIND_ADD, Family: "vpnv4", RouteTarget: &v1.VrfBgpRouteTarget{Rt: "65000:2", Direction: "both"}},
			{Kind: v1.RouteTargetOp_KIND_REMOVE, Family: "vpnv4", RouteTarget: &v1.VrfBgpRouteTarget{Rt: "65000:1"}},
		},
	}))
	if err != nil {
		t.Fatalf("BatchModifyRouteTargets: %v", err)
	}
	stored, _ := s.mgr.Get("vrf1")
	rts := stored.Families["vpnv4"].RouteTargets
	if len(rts) != 1 || rts[0].RT != "65000:2" || rts[0].Direction != vrfbgp.DirectionBoth {
		t.Errorf("batch result mismatch; rts=%+v", rts)
	}
}

// BatchModifyRouteTargets rolls back every op when any one fails: a partial
// commit would leave the binding in an inconsistent state the client cannot
// undo.
func TestBatchModifyRouteTargets_RollbackOnMidFailure(t *testing.T) {
	s := bindForRPC(t, "vrf1", map[string]*v1.VrfBgpFamily{
		"vpnv4": {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:200", Direction: "import"}}},
	})
	_, err := s.BatchModifyRouteTargets(context.Background(), connect.NewRequest(&v1.BatchModifyRouteTargetsRequest{
		VrfName: "vrf1",
		Ops: []*v1.RouteTargetOp{
			{Kind: v1.RouteTargetOp_KIND_ADD, Family: "vpnv4", RouteTarget: &v1.VrfBgpRouteTarget{Rt: "65000:201", Direction: "import"}},
			{Kind: v1.RouteTargetOp_KIND_ADD, Family: "evpn", RouteTarget: &v1.VrfBgpRouteTarget{Rt: "65000:300", Direction: "import"}}, // family not declared
		},
	}))
	if err == nil {
		t.Fatalf("BatchModifyRouteTargets must fail when an op references an undeclared family")
	}
	stored, _ := s.mgr.Get("vrf1")
	rts := stored.Families["vpnv4"].RouteTargets
	if len(rts) != 1 || rts[0].RT != "65000:200" {
		t.Errorf("failed batch must roll back: vpnv4 must be unchanged; rts=%+v", rts)
	}
	if _, has := stored.Families["evpn"]; has {
		t.Errorf("failed batch must not leave evpn behind; families=%+v", stored.Families)
	}
}

// BatchModifyRouteTargets on an unknown vrf_name is NotFound per the error
// code table.
func TestBatchModifyRouteTargets_UnknownVRFIsNotFound(t *testing.T) {
	s := NewVrfBgpServer(vrfbgp.NewManager(), nil, nil, nil)
	_, err := s.BatchModifyRouteTargets(context.Background(), connect.NewRequest(&v1.BatchModifyRouteTargetsRequest{
		VrfName: "missing",
		Ops:     []*v1.RouteTargetOp{{Kind: v1.RouteTargetOp_KIND_ADD, Family: "vpnv4", RouteTarget: &v1.VrfBgpRouteTarget{Rt: "65000:1"}}},
	}))
	if err == nil || connectCode(t, err) != connect.CodeNotFound {
		t.Errorf("unknown vrf_name must be NotFound, got %v", err)
	}
}

// The RPC boundary must not panic on nil entries the JSON / proto wire can
// produce (a `{"families":{"vpnv4":null}}` payload, a nil element inside a
// repeated RT list, a nil op in BatchModifyRouteTargets, a nil cfg on
// AddFamily). protobuf-go's generated Get methods are nil-safe on the
// receiver and return zero values, so each path either treats the nil as
// an empty-but-valid entry or rejects it as InvalidArgument -- never
// dereferences and panics. Pin that contract here.
func TestVrfBgp_RPCNilEntriesDoNotPanic(t *testing.T) {
	// (1) families with a nil VrfBgpFamily value.
	s := NewVrfBgpServer(vrfbgp.NewManager(), nil, nil, nil)
	if _, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{{
			VrfName:  "vrf-nil-fam",
			Rd:       "65100:1",
			Families: map[string]*v1.VrfBgpFamily{"vpnv4": nil},
		}},
	})); err != nil {
		t.Fatalf("nil family value must not panic; VrfBgpBind err=%v", err)
	}
	// (2) nil element in a repeated RT list -- ValidateRouteTarget catches the
	//     empty rt the nil entry decodes to and surfaces InvalidArgument.
	s2 := bindForRPC(t, "vrf1", map[string]*v1.VrfBgpFamily{"vpnv4": {}})
	if _, err := s2.AddFamily(context.Background(), connect.NewRequest(&v1.AddFamilyRequest{
		VrfName: "vrf1",
		Family:  "vpnv6",
		Config:  &v1.VrfBgpFamily{RouteTargets: []*v1.VrfBgpRouteTarget{nil}},
	})); err == nil || connectCode(t, err) != connect.CodeInvalidArgument {
		t.Errorf("nil RT element must be InvalidArgument, got %v", err)
	}
	// (3) nil op in BatchModifyRouteTargets -- GetKind returns KIND_UNSPECIFIED
	//     so the switch's default branch fires with "op.kind is required".
	if _, err := s2.BatchModifyRouteTargets(context.Background(), connect.NewRequest(&v1.BatchModifyRouteTargetsRequest{
		VrfName: "vrf1",
		Ops:     []*v1.RouteTargetOp{nil},
	})); err == nil {
		t.Error("nil op must surface an error, not panic and not no-op")
	}
	// (4) AddFamily with nil Config -- GetRouteTargets returns nil so the
	//     family is registered with an empty RT list (the existing API contract
	//     for "register a family without RTs").
	if _, err := s2.AddFamily(context.Background(), connect.NewRequest(&v1.AddFamilyRequest{
		VrfName: "vrf1",
		Family:  "evpn",
		Config:  nil,
	})); err != nil {
		t.Errorf("nil cfg must register an empty family without panic, got %v", err)
	}
}

// UpdateBinding on an unknown vrf_name must be NotFound, not a silent create.
// VrfBgpBind is the only verb that may register a new binding; an Update verb
// against a typo must surface as NotFound so the operator notices.
func TestUpdateBinding_UnknownVRFIsNotFound(t *testing.T) {
	s := NewVrfBgpServer(vrfbgp.NewManager(), nil, nil, nil)
	_, err := s.UpdateBinding(context.Background(), connect.NewRequest(&v1.UpdateBindingRequest{
		Binding: &v1.VrfBgpBinding{VrfName: "missing", Rd: "65100:1"},
	}))
	if err == nil || connectCode(t, err) != connect.CodeNotFound {
		t.Errorf("unknown vrf_name on UpdateBinding must be NotFound, got %v", err)
	}
}

// BatchModifyRouteTargets must preserve the per-op connect.Error code so a
// batch call returns the same code the single-call mutator would (NotFound
// when the family is undeclared rather than wrapping as InvalidArgument).
func TestBatchModifyRouteTargets_PreservesPerOpErrorCode(t *testing.T) {
	s := bindForRPC(t, "vrf1", map[string]*v1.VrfBgpFamily{"vpnv4": {}})
	_, err := s.BatchModifyRouteTargets(context.Background(), connect.NewRequest(&v1.BatchModifyRouteTargetsRequest{
		VrfName: "vrf1",
		Ops: []*v1.RouteTargetOp{
			{Kind: v1.RouteTargetOp_KIND_ADD, Family: "evpn", RouteTarget: &v1.VrfBgpRouteTarget{Rt: "65000:1", Direction: "import"}},
		},
	}))
	if err == nil || connectCode(t, err) != connect.CodeNotFound {
		t.Errorf("undeclared family op must preserve NotFound from addRouteTarget, got %v", err)
	}
	// The outer NewError prepends the code once; the wrapper must not also
	// embed the inner *connect.Error's "code: " prefix or the operator sees
	// the code twice in the wire string.
	if msg := err.Error(); strings.Count(msg, "not_found:") != 1 {
		t.Errorf("error message must contain the code prefix exactly once, got %q", msg)
	}
}

// EmptyForFamily must treat a family declared with zero RTs as undeclared so
// `vbctl vrf-bgp family add --family mup_ipv4` (no --rt) cannot flip the
// global MUP default-allow off and drop every received MUP route.
func TestAddFamily_EmptyDoesNotFlipDefaultAllow(t *testing.T) {
	s := bindForRPC(t, "vrf1", map[string]*v1.VrfBgpFamily{"vpnv4": {}})
	if _, err := s.AddFamily(context.Background(), connect.NewRequest(&v1.AddFamilyRequest{
		VrfName: "vrf1", Family: "mup_ipv4", Config: &v1.VrfBgpFamily{},
	})); err != nil {
		t.Fatalf("AddFamily: %v", err)
	}
	if !s.mgr.EmptyForFamily("mup_ipv4") {
		t.Errorf("a 0-RT family must not flip EmptyForFamily off; that would drop MUP across the box")
	}
}

// ListRouteTargets with direction=both is the operator's natural "show
// everything" filter and must include import-only and export-only RTs.
// Direction.Has(DirectionBoth) requires both bits set, so the handler
// translates a "both" filter into "no narrowing".
// direction=both selects only RTs whose direction has BOTH bits set, i.e.
// the strict bidirectional RTs. Empty direction is the "no filter" (show
// every RT) path; the import/export filters via bitmask containment include
// "both" RTs naturally.
func TestListRouteTargets_BothFilterIsStrict(t *testing.T) {
	s := bindForRPC(t, "vrf1", map[string]*v1.VrfBgpFamily{
		"vpnv4": {RouteTargets: []*v1.VrfBgpRouteTarget{
			{Rt: "65000:1", Direction: "import"},
			{Rt: "65000:2", Direction: "export"},
			{Rt: "65000:3", Direction: "both"},
		}},
	})
	resp, err := s.ListRouteTargets(context.Background(), connect.NewRequest(&v1.ListRouteTargetsRequest{VrfName: "vrf1", Direction: "both"}))
	if err != nil {
		t.Fatalf("ListRouteTargets: %v", err)
	}
	if len(resp.Msg.Families) != 1 || len(resp.Msg.Families[0].GetRouteTargets()) != 1 {
		t.Fatalf("direction=both must return only RTs with both bits set; got %+v", resp.Msg.Families)
	}
	if got := resp.Msg.Families[0].GetRouteTargets()[0].GetRt(); got != "65000:3" {
		t.Errorf("direction=both must return only the bidirectional RT 65000:3; got %q", got)
	}
	// "everything" is the empty-direction filter.
	all, err := s.ListRouteTargets(context.Background(), connect.NewRequest(&v1.ListRouteTargetsRequest{VrfName: "vrf1"}))
	if err != nil {
		t.Fatalf("ListRouteTargets no filter: %v", err)
	}
	if len(all.Msg.Families) != 1 || len(all.Msg.Families[0].GetRouteTargets()) != 3 {
		t.Errorf("empty direction must return every RT; got %+v", all.Msg.Families)
	}
}

// AddRouteTarget rejects an RT whose format is neither ASN:value nor
// IPv4:value, so a CLI typo that slipped through the client-side parser is
// caught at the server boundary rather than stored as garbage.
func TestAddRouteTarget_RejectsMalformedRT(t *testing.T) {
	s := bindForRPC(t, "vrf1", map[string]*v1.VrfBgpFamily{"vpnv4": {}})
	_, err := s.AddRouteTarget(context.Background(), connect.NewRequest(&v1.AddRouteTargetRequest{
		VrfName:     "vrf1",
		Family:      "vpnv4",
		RouteTarget: &v1.VrfBgpRouteTarget{Rt: "65000:200:imprt", Direction: "import"},
	}))
	if err == nil || connectCode(t, err) != connect.CodeInvalidArgument {
		t.Errorf("malformed RT must be InvalidArgument, got %v", err)
	}
}

// RemoveFamily("evpn") on a binding whose bd_id stays unchanged must Disable
// the prior EVPN bridge domain. Without this, EvpnCoordinator keeps the BD
// active and re-advertises RT2/RT3 even though the operator declared "no
// EVPN here anymore".
func TestRemoveFamily_EVPNDisablesBridgeDomain(t *testing.T) {
	hook := &fakeEvpnBridge{}
	coord := newEvpnCoordForTest(hook, map[uint16]uint32{100: 5})
	s := NewVrfBgpServer(vrfbgp.NewManager(), nil, coord, nil)
	if _, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{{
			VrfName: "evi", Rd: "65100:100", BdId: 100,
			Families: map[string]*v1.VrfBgpFamily{
				"evpn": {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:100", Direction: "both"}}},
			},
		}},
	})); err != nil {
		t.Fatalf("VrfBgpBind: %v", err)
	}
	if !hook.enabled[100] {
		t.Fatalf("precondition: bd_id 100 must be EVPN-enabled after bind; enabled=%v", hook.enabled)
	}
	if _, err := s.RemoveFamily(context.Background(), connect.NewRequest(&v1.RemoveFamilyRequest{
		VrfName: "evi", Family: "evpn",
	})); err != nil {
		t.Fatalf("RemoveFamily: %v", err)
	}
	if hook.enabled[100] {
		t.Errorf("RemoveFamily(evpn) must Disable bd_id 100 even when BDID is unchanged; enabled=%v", hook.enabled)
	}
}

// A per-RT mutation on a non-EVPN family (vpnv4 RT add) on a BDID-bound
// binding must NOT re-fire EnableBD. Without the EVPN-fields change check
// the coordinator would re-run replayFDB on every unrelated edit and emit
// an O(N-MACs) RT2 storm.
func TestAddRouteTarget_OnVPNv4FamilyDoesNotReFireEVPN(t *testing.T) {
	hook := &fakeEvpnBridge{}
	coord := newEvpnCoordForTest(hook, map[uint16]uint32{100: 5})
	s := NewVrfBgpServer(vrfbgp.NewManager(), nil, coord, nil)
	if _, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{{
			VrfName: "evi-mixed", Rd: "65100:100", BdId: 100,
			Families: map[string]*v1.VrfBgpFamily{
				"evpn":  {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:100", Direction: "both"}}},
				"vpnv4": {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:200", Direction: "both"}}},
			},
		}},
	})); err != nil {
		t.Fatalf("VrfBgpBind: %v", err)
	}
	priorEnable := hook.enableCnt
	if _, err := s.AddRouteTarget(context.Background(), connect.NewRequest(&v1.AddRouteTargetRequest{
		VrfName: "evi-mixed", Family: "vpnv4",
		RouteTarget: &v1.VrfBgpRouteTarget{Rt: "65000:999", Direction: "export"},
	})); err != nil {
		t.Fatalf("AddRouteTarget: %v", err)
	}
	if hook.enableCnt != priorEnable {
		t.Errorf("vpnv4 RT add must NOT re-drive EnableBD on a BDID-bound binding (would replay FDB); enableCnt %d -> %d", priorEnable, hook.enableCnt)
	}
}

// An RT add on the EVPN family itself MUST re-drive EnableBD so the
// re-export reflects the new RT2/RT3 RT set.
func TestAddRouteTarget_OnEVPNFamilyReFiresEVPN(t *testing.T) {
	hook := &fakeEvpnBridge{}
	coord := newEvpnCoordForTest(hook, map[uint16]uint32{100: 5})
	s := NewVrfBgpServer(vrfbgp.NewManager(), nil, coord, nil)
	if _, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{{
			VrfName: "evi", Rd: "65100:100", BdId: 100,
			Families: map[string]*v1.VrfBgpFamily{
				"evpn": {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:100", Direction: "both"}}},
			},
		}},
	})); err != nil {
		t.Fatalf("VrfBgpBind: %v", err)
	}
	priorEnable := hook.enableCnt
	if _, err := s.AddRouteTarget(context.Background(), connect.NewRequest(&v1.AddRouteTargetRequest{
		VrfName: "evi", Family: "evpn",
		RouteTarget: &v1.VrfBgpRouteTarget{Rt: "65000:101", Direction: "export"},
	})); err != nil {
		t.Fatalf("AddRouteTarget: %v", err)
	}
	if hook.enableCnt <= priorEnable {
		t.Errorf("evpn RT add must re-drive EnableBD so the export set updates; enableCnt %d -> %d", priorEnable, hook.enableCnt)
	}
}

// V6 regression: a binding with bd_id set but no FamilyEVPN (e.g. operator
// forgot --rt evpn:...) would otherwise advertise RT3 with empty
// extended-community RTs, which no peer can import. commitBinding must skip
// EnableForBinding when FamilyEVPN is absent.
func TestVrfBgpBind_BDIDWithoutEvpnFamilySkipsEnable(t *testing.T) {
	hook := &fakeEvpnBridge{}
	coord := newEvpnCoordForTest(hook, map[uint16]uint32{100: 5})
	s := NewVrfBgpServer(vrfbgp.NewManager(), nil, coord, nil)
	if _, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{{
			VrfName: "evi-no-evpn-rt", Rd: "65100:100", BdId: 100,
			// Only vpnv4 declared; FamilyEVPN never populated after Normalize.
			Families: map[string]*v1.VrfBgpFamily{
				"vpnv4": {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:200", Direction: "both"}}},
			},
		}},
	})); err != nil {
		t.Fatalf("VrfBgpBind: %v", err)
	}
	if hook.enableCnt != 0 || hook.enabled[100] {
		t.Errorf("bind with BDID set but no FamilyEVPN must NOT call EnableBD (would push empty-RT RT3); enableCnt=%d enabled=%v", hook.enableCnt, hook.enabled)
	}
}

// V7 regression: MaxPrefixes is an L3VPN-axis cap; an update that only
// changes --max-prefixes on an EVPN binding must NOT re-drive EnableBD (and
// therefore replayFDB), so a benign cap tweak does not trigger an O(N MACs)
// RT2 origination storm.
func TestUpdateBinding_MaxPrefixesAloneSkipsEVPNReFire(t *testing.T) {
	hook := &fakeEvpnBridge{}
	coord := newEvpnCoordForTest(hook, map[uint16]uint32{100: 5})
	s := NewVrfBgpServer(vrfbgp.NewManager(), nil, coord, nil)
	if _, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{{
			VrfName: "evi", Rd: "65100:100", BdId: 100,
			Families: map[string]*v1.VrfBgpFamily{
				"evpn": {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:100", Direction: "both"}}},
			},
		}},
	})); err != nil {
		t.Fatalf("VrfBgpBind: %v", err)
	}
	priorEnable := hook.enableCnt
	if _, err := s.UpdateBinding(context.Background(), connect.NewRequest(&v1.UpdateBindingRequest{
		Binding: &v1.VrfBgpBinding{
			VrfName: "evi", Rd: "65100:100", BdId: 100, MaxPrefixes: 5000,
			Families: map[string]*v1.VrfBgpFamily{
				"evpn": {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:100", Direction: "both"}}},
			},
		},
	})); err != nil {
		t.Fatalf("UpdateBinding: %v", err)
	}
	if hook.enableCnt != priorEnable {
		t.Errorf("update changing only MaxPrefixes must NOT re-fire EnableBD; enableCnt %d -> %d", priorEnable, hook.enableCnt)
	}
}

// V8 regression: sameRouteTargets compares RouteTargets as a set so a
// reorder (proto map iteration is unspecified across reconcile cycles) does
// not trip evpnFieldsChanged and trigger replayFDB on every reconcile.
func TestSameRouteTargets_OrderInsensitive(t *testing.T) {
	a := []vrfbgp.RouteTarget{
		{RT: "65000:100", Direction: vrfbgp.DirectionImport},
		{RT: "65000:200", Direction: vrfbgp.DirectionExport},
	}
	b := []vrfbgp.RouteTarget{
		{RT: "65000:200", Direction: vrfbgp.DirectionExport},
		{RT: "65000:100", Direction: vrfbgp.DirectionImport},
	}
	if !sameRouteTargets(a, b) {
		t.Error("sameRouteTargets must treat a reorder of the same RT set as equal")
	}
	c := []vrfbgp.RouteTarget{
		{RT: "65000:100", Direction: vrfbgp.DirectionImport},
		{RT: "65000:201", Direction: vrfbgp.DirectionExport}, // different RT
	}
	if sameRouteTargets(a, c) {
		t.Error("sameRouteTargets must distinguish different RT sets")
	}
	d := []vrfbgp.RouteTarget{
		{RT: "65000:100", Direction: vrfbgp.DirectionImport},
		{RT: "65000:200", Direction: vrfbgp.DirectionImport}, // different direction
	}
	if sameRouteTargets(a, d) {
		t.Error("sameRouteTargets must distinguish RTs with different directions")
	}
}

// V9 regression: when exporter.AddVRF(updated) fails AND the rollback
// exporter.AddVRF(prev) also fails, commitBinding must NOT call
// mgr.Unbind(updated.VRFName) -- the manager was never touched, so prev is
// still authoritative. Unbinding it would silently delete the operator's
// prior binding from the only place it still lives.
func TestVrfBgpBind_DoubleAddVRFFailureKeepsManagerPrev(t *testing.T) {
	mgr := vrfbgp.NewManager()
	exp := &fakeVrfExporter{}
	s := NewVrfBgpServer(mgr, exp, nil, nil)
	// Initial bind: prev lands in both manager and exporter.
	if _, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{{VrfName: "vrf1", Rd: "65100:200", DefaultLocator: "LOC1"}},
	})); err != nil {
		t.Fatalf("initial VrfBgpBind: %v", err)
	}
	// Re-bind: flip the exporter to fail every AddVRF (both updated and the
	// AddVRF(prev) rollback). commitBinding must keep prev in the manager.
	exp.addErr = errors.New("boom")
	resp, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{{VrfName: "vrf1", Rd: "65100:999", DefaultLocator: "LOC1"}},
	}))
	if err != nil {
		t.Fatalf("re-bind VrfBgpBind: %v", err)
	}
	if len(resp.Msg.Errors) != 1 {
		t.Fatalf("double AddVRF failure must surface as a per-item error; errors=%v", resp.Msg.Errors)
	}
	got := mgr.List()
	if len(got) != 1 || got[0].RD != "65100:200" {
		t.Errorf("double AddVRF failure must NOT Unbind prev; manager should still hold RD 65100:200; got %+v", got)
	}
}
