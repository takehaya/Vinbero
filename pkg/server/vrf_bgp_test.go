package server

import (
	"context"
	"errors"
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
	failOnRD string // AddVRF fails for a binding whose RD equals this (re-bind tests)
}

func (f *fakeVrfExporter) AddVRF(b vrfbgp.Binding) error {
	if f.addErr != nil {
		return f.addErr
	}
	if f.failOnRD != "" && b.RD == f.failOnRD {
		return errors.New("boom")
	}
	f.added = append(f.added, b.VRFName)
	return nil
}

func (f *fakeVrfExporter) RemoveVRF(name string) { f.removed = append(f.removed, name) }

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
}
