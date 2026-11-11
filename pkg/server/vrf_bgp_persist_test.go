package server

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// fakeBindingStore keeps the last saved bindings, like the state file. A set
// err fails every save and keeps the previous record. onSave, when set, runs
// inside each save.
type fakeBindingStore struct {
	mu     sync.Mutex
	saved  []vrfbgp.Binding
	writes int
	err    error
	onSave func([]vrfbgp.Binding)
}

func (f *fakeBindingStore) SaveBindings(b []vrfbgp.Binding) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.onSave != nil {
		f.onSave(b)
	}
	if f.err != nil {
		return f.err
	}
	f.saved = append([]vrfbgp.Binding(nil), b...)
	f.writes++
	return nil
}

func (f *fakeBindingStore) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeBindingStore) last() []vrfbgp.Binding {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]vrfbgp.Binding(nil), f.saved...)
}

// runtimeBindings is what the state file should hold: every binding of the
// manager the config does not declare, by name.
func runtimeBindings(mgr *vrfbgp.Manager) []vrfbgp.Binding {
	var out []vrfbgp.Binding
	for _, b := range mgr.List() {
		if !mgr.ConfigDeclared(b.VRFName) {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VRFName < out[j].VRFName })
	return out
}

func requireSavedMatches(t *testing.T, store *fakeBindingStore, mgr *vrfbgp.Manager, step string) {
	t.Helper()
	got, want := store.last(), runtimeBindings(mgr)
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: saved %+v, manager holds %+v", step, got, want)
	}
}

func newPersistServer(t *testing.T) (*VrfBgpServer, *vrfbgp.Manager, *fakeBindingStore, *fakeVrfExporter) {
	t.Helper()
	mgr := vrfbgp.NewManager()
	store := &fakeBindingStore{}
	mgr.SetStore(store)
	exp := &fakeVrfExporter{}
	return NewVrfBgpServer(mgr, exp, nil, nil, nil, nil), mgr, store, exp
}

func bindReq(b ...*v1.VrfBgpBinding) *connect.Request[v1.VrfBgpBindRequest] {
	return connect.NewRequest(&v1.VrfBgpBindRequest{Bindings: b})
}

func vpnv4(rts ...string) map[string]*v1.VrfBgpFamily {
	f := &v1.VrfBgpFamily{}
	for _, rt := range rts {
		f.RouteTargets = append(f.RouteTargets, &v1.VrfBgpRouteTarget{Rt: rt, Direction: "both"})
	}
	return map[string]*v1.VrfBgpFamily{"vpnv4": f}
}

// Every mutation RPC leaves the state file holding what the manager holds,
// unbind included.
func TestVrfBgpPersist_EveryChangeIsSaved(t *testing.T) {
	ctx := context.Background()
	s, mgr, store, _ := newPersistServer(t)
	steps := []struct {
		name string
		run  func() error
	}{
		{"bind legacy", func() error {
			resp, err := s.VrfBgpBind(ctx, bindReq(&v1.VrfBgpBinding{
				VrfName: "legacy", Rd: "65000:1", ImportRts: []string{"65000:1"}, ExportRts: []string{"65000:2", "65000:1"},
			}))
			if err == nil && len(resp.Msg.Errors) > 0 {
				err = errors.New(resp.Msg.Errors[0].Reason)
			}
			return err
		}},
		{"bind families", func() error {
			_, err := s.VrfBgpBind(ctx, bindReq(&v1.VrfBgpBinding{
				VrfName: "t1", Rd: "65000:10", DefaultLocator: "LOC1", Redistribute: []string{"static"},
				MaxPrefixes: 10, Families: vpnv4("65000:10"),
			}))
			return err
		}},
		{"family add", func() error {
			_, err := s.AddFamily(ctx, connect.NewRequest(&v1.AddFamilyRequest{VrfName: "t1", Family: "evpn"}))
			return err
		}},
		{"rt add", func() error {
			_, err := s.AddRouteTarget(ctx, connect.NewRequest(&v1.AddRouteTargetRequest{
				VrfName: "t1", Family: "evpn", RouteTarget: &v1.VrfBgpRouteTarget{Rt: "65000:20", Direction: "import"},
			}))
			return err
		}},
		{"batch", func() error {
			_, err := s.BatchModifyRouteTargets(ctx, connect.NewRequest(&v1.BatchModifyRouteTargetsRequest{
				VrfName: "t1", Ops: []*v1.RouteTargetOp{{
					Kind: v1.RouteTargetOp_KIND_ADD, Family: "vpnv4",
					RouteTarget: &v1.VrfBgpRouteTarget{Rt: "65000:11", Direction: "export"},
				}},
			}))
			return err
		}},
		{"rt remove", func() error {
			_, err := s.RemoveRouteTarget(ctx, connect.NewRequest(&v1.RemoveRouteTargetRequest{
				VrfName: "t1", Family: "vpnv4", Rt: "65000:10",
			}))
			return err
		}},
		{"family remove", func() error {
			_, err := s.RemoveFamily(ctx, connect.NewRequest(&v1.RemoveFamilyRequest{VrfName: "t1", Family: "evpn"}))
			return err
		}},
		{"update", func() error {
			_, err := s.UpdateBinding(ctx, connect.NewRequest(&v1.UpdateBindingRequest{Binding: &v1.VrfBgpBinding{
				VrfName: "t1", Rd: "65000:99", DefaultLocator: "LOC1", Redistribute: []string{"static"}, Families: vpnv4("65000:99"),
			}}))
			return err
		}},
		{"unbind", func() error {
			resp, err := s.VrfBgpUnbind(ctx, connect.NewRequest(&v1.VrfBgpUnbindRequest{VrfNames: []string{"legacy"}}))
			if err == nil && len(resp.Msg.Errors) > 0 {
				err = errors.New(resp.Msg.Errors[0].Reason)
			}
			return err
		}},
	}
	for _, st := range steps {
		if err := st.run(); err != nil {
			t.Fatalf("%s: %v", st.name, err)
		}
		requireSavedMatches(t, store, mgr, st.name)
	}
	if got := store.last(); len(got) != 1 || got[0].VRFName != "t1" || got[0].RD != "65000:99" {
		t.Fatalf("final saved = %+v, want only t1 with rd 65000:99", got)
	}
}

// The state file holds a binding before anything can use it: during the
// save of a new binding, the manager does not have it yet.
func TestVrfBgpPersist_SavedBeforePublished(t *testing.T) {
	s, mgr, store, _ := newPersistServer(t)
	var visible []bool
	store.onSave = func([]vrfbgp.Binding) {
		_, ok := mgr.Get("t1")
		visible = append(visible, ok)
	}
	if _, opErr := s.bindOne(&v1.VrfBgpBinding{VrfName: "t1", Rd: "65000:1", Families: vpnv4("65000:1")}); opErr != nil {
		t.Fatal(opErr.Reason)
	}
	if !reflect.DeepEqual(visible, []bool{false}) {
		t.Fatalf("binding visible during its save: %v", visible)
	}
}

// A save that fails changes nothing, for every mutation RPC: the manager,
// the exporter and the state file keep the previous binding, the error says
// so, and repeating the RPC once the file can be written succeeds.
func TestVrfBgpPersist_SaveFailureChangesNothingAndRetrySucceeds(t *testing.T) {
	ctx := context.Background()
	diskFull := errors.New("disk full")
	opErr := func(errs []*v1.OperationError) error {
		if len(errs) == 0 {
			return nil
		}
		return errors.New(errs[0].Reason)
	}
	cases := []struct {
		name string
		// connectErr: the RPC returns a connect error (CodeInternal) rather
		// than an OperationError in its response.
		connectErr bool
		run        func(s *VrfBgpServer) error
	}{
		{"bind new", false, func(s *VrfBgpServer) error {
			resp, err := s.VrfBgpBind(ctx, bindReq(&v1.VrfBgpBinding{
				VrfName: "new", Rd: "65000:5", DefaultLocator: "LOC1", Redistribute: []string{"static"}, Families: vpnv4("65000:5"),
			}))
			if err != nil {
				return err
			}
			return opErr(resp.Msg.Errors)
		}},
		{"rebind", false, func(s *VrfBgpServer) error {
			resp, err := s.VrfBgpBind(ctx, bindReq(&v1.VrfBgpBinding{
				VrfName: "t1", Rd: "65000:2", DefaultLocator: "LOC1", Redistribute: []string{"static"}, Families: vpnv4("65000:1"),
			}))
			if err != nil {
				return err
			}
			return opErr(resp.Msg.Errors)
		}},
		{"update", true, func(s *VrfBgpServer) error {
			_, err := s.UpdateBinding(ctx, connect.NewRequest(&v1.UpdateBindingRequest{Binding: &v1.VrfBgpBinding{
				VrfName: "t1", Rd: "65000:3", DefaultLocator: "LOC1", Redistribute: []string{"static"}, Families: vpnv4("65000:1"),
			}}))
			return err
		}},
		{"rt add", true, func(s *VrfBgpServer) error {
			_, err := s.AddRouteTarget(ctx, connect.NewRequest(&v1.AddRouteTargetRequest{
				VrfName: "t1", Family: "vpnv4", RouteTarget: &v1.VrfBgpRouteTarget{Rt: "65000:7", Direction: "both"},
			}))
			return err
		}},
		{"family add", true, func(s *VrfBgpServer) error {
			_, err := s.AddFamily(ctx, connect.NewRequest(&v1.AddFamilyRequest{VrfName: "t1", Family: "vpnv6"}))
			return err
		}},
		{"family remove", true, func(s *VrfBgpServer) error {
			_, err := s.RemoveFamily(ctx, connect.NewRequest(&v1.RemoveFamilyRequest{VrfName: "t1", Family: "vpnv4"}))
			return err
		}},
		{"batch", true, func(s *VrfBgpServer) error {
			_, err := s.BatchModifyRouteTargets(ctx, connect.NewRequest(&v1.BatchModifyRouteTargetsRequest{
				VrfName: "t1", Ops: []*v1.RouteTargetOp{{
					Kind: v1.RouteTargetOp_KIND_REMOVE, Family: "vpnv4",
					RouteTarget: &v1.VrfBgpRouteTarget{Rt: "65000:1"},
				}},
			}))
			return err
		}},
		{"unbind", false, func(s *VrfBgpServer) error {
			resp, err := s.VrfBgpUnbind(ctx, connect.NewRequest(&v1.VrfBgpUnbindRequest{VrfNames: []string{"t1"}}))
			if err != nil {
				return err
			}
			return opErr(resp.Msg.Errors)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, mgr, store, exp := newPersistServer(t)
			if _, opErr := s.bindOne(&v1.VrfBgpBinding{
				VrfName: "t1", Rd: "65000:1", DefaultLocator: "LOC1", Redistribute: []string{"static"}, Families: vpnv4("65000:1"),
			}); opErr != nil {
				t.Fatal(opErr.Reason)
			}
			before := runtimeBindings(mgr)
			exported := maps(exp.enabled)
			savedBefore := store.last()

			store.setErr(diskFull)
			err := tc.run(s)
			if err == nil {
				t.Fatal("RPC succeeded with an unwritable state file")
			}
			if tc.connectErr {
				if code := connectCode(t, err); code != connect.CodeInternal {
					t.Errorf("code = %v, want Internal", code)
				}
			}
			if !strings.Contains(err.Error(), errBindingNotSaved.Error()) {
				t.Errorf("error does not say the state file was not written: %v", err)
			}
			if got := runtimeBindings(mgr); !reflect.DeepEqual(got, before) {
				t.Errorf("manager changed: %+v, want %+v", got, before)
			}
			if got := maps(exp.enabled); !reflect.DeepEqual(got, exported) {
				t.Errorf("exporter changed: %+v, want %+v", got, exported)
			}
			if got := store.last(); !reflect.DeepEqual(got, savedBefore) {
				t.Errorf("state file changed: %+v, want %+v", got, savedBefore)
			}

			store.setErr(nil)
			if err := tc.run(s); err != nil {
				t.Fatalf("retry: %v", err)
			}
			requireSavedMatches(t, store, mgr, "retry")
			if reflect.DeepEqual(runtimeBindings(mgr), before) {
				t.Error("retry did not apply the change")
			}
		})
	}
}

func maps(m map[string]vrfbgp.Binding) map[string]vrfbgp.Binding {
	out := make(map[string]vrfbgp.Binding, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// A binding the config file declares is applied but never saved, so the
// next start binds it from the config again; the others are saved as usual.
func TestVrfBgpPersist_ConfigDeclaredIsNotSaved(t *testing.T) {
	ctx := context.Background()
	s, mgr, store, _ := newPersistServer(t)
	mgr.SetConfigDeclared([]string{"cfg"})
	if _, opErr := s.bindOne(&v1.VrfBgpBinding{VrfName: "cfg", Rd: "65000:1", Families: vpnv4("65000:1")}); opErr != nil {
		t.Fatal(opErr.Reason)
	}
	if store.writes != 0 {
		t.Fatalf("a config binding was saved: %+v", store.last())
	}
	if _, opErr := s.bindOne(&v1.VrfBgpBinding{VrfName: "api", Rd: "65000:2", Families: vpnv4("65000:2")}); opErr != nil {
		t.Fatal(opErr.Reason)
	}
	if _, err := s.AddRouteTarget(ctx, connect.NewRequest(&v1.AddRouteTargetRequest{
		VrfName: "cfg", Family: "vpnv4", RouteTarget: &v1.VrfBgpRouteTarget{Rt: "65000:9", Direction: "both"},
	})); err != nil {
		t.Fatal(err)
	}
	resp, err := s.VrfBgpUnbind(ctx, connect.NewRequest(&v1.VrfBgpUnbindRequest{VrfNames: []string{"cfg"}}))
	if err != nil || len(resp.Msg.Errors) > 0 {
		t.Fatalf("unbind cfg: %v %v", err, resp.Msg.GetErrors())
	}
	got := store.last()
	if len(got) != 1 || got[0].VRFName != "api" {
		t.Fatalf("saved = %+v, want only api", got)
	}
	// A failing file does not stand in the way of a config binding.
	store.setErr(errors.New("disk full"))
	if _, opErr := s.bindOne(&v1.VrfBgpBinding{VrfName: "cfg", Rd: "65000:1", Families: vpnv4("65000:1")}); opErr != nil {
		t.Fatalf("config binding refused by the state file: %s", opErr.Reason)
	}
	if resp := unbindOne(t, s, "cfg"); len(resp.GetErrors()) > 0 {
		t.Fatalf("config unbind refused by the state file: %s", resp.GetErrors()[0].GetReason())
	}
}

func unbindOne(t *testing.T, s *VrfBgpServer, name string) *v1.VrfBgpUnbindResponse {
	t.Helper()
	resp, err := s.VrfBgpUnbind(context.Background(), connect.NewRequest(&v1.VrfBgpUnbindRequest{VrfNames: []string{name}}))
	if err != nil {
		t.Fatal(err)
	}
	return resp.Msg
}

// Concurrent binds, unbinds and edits leave the state file holding exactly
// what the manager holds. Run under -race.
func TestVrfBgpPersist_ConcurrentRPCs(t *testing.T) {
	ctx := context.Background()
	s, mgr, store, _ := newPersistServer(t)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 40 {
				name := fmt.Sprintf("t%d", (g+i)%5)
				switch i % 4 {
				case 0:
					_, _ = s.bindOne(&v1.VrfBgpBinding{VrfName: name, Rd: fmt.Sprintf("65000:%d", g), Families: vpnv4("65000:1")})
				case 1:
					_, _ = s.AddRouteTarget(ctx, connect.NewRequest(&v1.AddRouteTargetRequest{
						VrfName: name, Family: "vpnv4", RouteTarget: &v1.VrfBgpRouteTarget{Rt: fmt.Sprintf("65000:%d", 100+i), Direction: "both"},
					}))
				case 2:
					_, _ = s.VrfBgpUnbind(ctx, connect.NewRequest(&v1.VrfBgpUnbindRequest{VrfNames: []string{name}}))
				case 3:
					_, _ = s.UpdateBinding(ctx, connect.NewRequest(&v1.UpdateBindingRequest{Binding: &v1.VrfBgpBinding{
						VrfName: name, Rd: fmt.Sprintf("65000:%d", 200+g), Families: vpnv4("65000:2"),
					}}))
				}
			}
		}()
	}
	wg.Wait()
	requireSavedMatches(t, store, mgr, "after the concurrent RPCs")
}
