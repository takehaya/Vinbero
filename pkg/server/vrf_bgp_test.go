package server

import (
	"context"
	"errors"
	"sync"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// An out-of-range bd_id (> uint16) is rejected as a per-item error rather than
// silently truncated into a different bridge domain.
func TestVrfBgpBind_BdIdOutOfRange(t *testing.T) {
	s := NewVrfBgpServer(vrfbgp.NewManager(), nil)
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
	s := NewVrfBgpServer(vrfbgp.NewManager(), exp)
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
	s := NewVrfBgpServer(mgr, &fakeVrfExporter{addErr: errors.New("boom")})
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
	s := NewVrfBgpServer(mgr, exp)

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
		s := NewVrfBgpServer(mgr, exp)
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
	s := NewVrfBgpServer(vrfbgp.NewManager(), nil)
	if _, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{
			{
				VrfName:        "vrf1",
				Rd:             "65100:200",
				ImportRts:      []string{"65000:200"},
				ExportRts:      []string{"65000:201"},
				Redistribute:   []string{"connected", "static"},
				MaxPrefixes:    42,
				DefaultLocator: "LOC1",
				BdId:           100,
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
}
