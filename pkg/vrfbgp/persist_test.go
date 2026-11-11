package vrfbgp

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
)

type recordingStore struct {
	saved [][]Binding
	err   error
}

func (r *recordingStore) SaveBindings(b []Binding) error {
	if r.err != nil {
		return r.err
	}
	r.saved = append(r.saved, b)
	return nil
}

func (r *recordingStore) last(t *testing.T) []Binding {
	t.Helper()
	if len(r.saved) == 0 {
		t.Fatal("nothing saved")
	}
	return r.saved[len(r.saved)-1]
}

func names(bs []Binding) []string {
	out := make([]string, 0, len(bs))
	for _, b := range bs {
		out = append(out, b.VRFName)
	}
	return out
}

// Saves write every binding the config does not declare, by name, and
// SaveWith / SaveWithout write the set as it will be after the change
// without making it.
func TestSave_RuntimeBindingsOnly(t *testing.T) {
	m := NewManager()
	store := &recordingStore{}
	m.SetStore(store)
	m.SetConfigDeclared([]string{"cfg"})
	for _, name := range []string{"zeta", "cfg", "alpha"} {
		if err := m.Bind(Binding{VRFName: name, RD: "65000:1"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	if got := names(store.last(t)); !reflect.DeepEqual(got, []string{"alpha", "zeta"}) {
		t.Errorf("Save wrote %v", got)
	}
	if err := m.SaveWith(Binding{VRFName: "mid", RD: "65000:2", ImportRTs: []string{"65000:2"}}); err != nil {
		t.Fatal(err)
	}
	last := store.last(t)
	if got := names(last); !reflect.DeepEqual(got, []string{"alpha", "mid", "zeta"}) {
		t.Errorf("SaveWith wrote %v", got)
	}
	if last[1].Families == nil {
		t.Error("SaveWith did not normalize the binding it saves")
	}
	if _, bound := m.Get("mid"); bound {
		t.Error("SaveWith bound the binding")
	}
	n := len(store.saved)
	if err := m.SaveWith(Binding{VRFName: "cfg", RD: "65000:9"}); err != nil || len(store.saved) != n {
		t.Errorf("SaveWith of a config binding wrote (err %v)", err)
	}
	if err := m.SaveWithout("alpha"); err != nil {
		t.Fatal(err)
	}
	if got := names(store.last(t)); !reflect.DeepEqual(got, []string{"zeta"}) {
		t.Errorf("SaveWithout wrote %v", got)
	}
	if _, bound := m.Get("alpha"); !bound {
		t.Error("SaveWithout unbound the binding")
	}
	store.err = errors.New("disk full")
	if err := m.Save(); err == nil {
		t.Error("a failed store write is not reported")
	}
}

// Without a store nothing is saved and nothing fails.
func TestSave_NoStore(t *testing.T) {
	m := NewManager()
	if err := m.SaveWith(Binding{VRFName: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := m.SaveWithout("a"); err != nil {
		t.Fatal(err)
	}
}

// Restore brings bindings back as they were saved: the legacy lists keep
// their order, families keep empty entries, and nil stays nil. The VRFs are
// Ensured and the bindings marked as restored.
func TestRestore_KeepsBindingsAsSaved(t *testing.T) {
	legacy := Binding{VRFName: "legacy", ImportRTs: []string{"65000:1"}, ExportRTs: []string{"65000:2", "65000:1"}}.Normalize()
	fams := Binding{
		VRFName: "fams", RD: "65000:3", DefaultLocator: "LOC1", Redistribute: []string{"static"}, MaxPrefixes: 5,
		Families: map[bgp.Family]FamilyPolicy{
			bgp.FamilyVPNv4: {RouteTargets: []RouteTarget{{RT: "65000:3", Direction: DirectionImport}, {RT: "65000:4", Direction: DirectionBoth}}},
			bgp.FamilyEVPN:  {RouteTargets: []RouteTarget{}},
		},
		MupGTP4SourcePrefix: netip.MustParsePrefix("2001:db8::/64"),
	}.Normalize()
	empty := Binding{VRFName: "empty", Families: map[bgp.Family]FamilyPolicy{}}.Normalize()
	bare := Binding{VRFName: "bare", RD: "65000:5"}.Normalize()
	if !reflect.DeepEqual(legacy.ExportRTs, []string{"65000:2", "65000:1"}) {
		t.Fatalf("fixture: %v", legacy.ExportRTs)
	}

	m := NewManager()
	if err := m.Restore([]Binding{legacy, fams, empty, bare}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []Binding{legacy, fams, empty, bare} {
		got, ok := m.Get(want.VRFName)
		if !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("%s restored as %+v, want %+v", want.VRFName, got, want)
		}
		if !m.Restored(want.VRFName) {
			t.Errorf("%s not marked restored", want.VRFName)
		}
		if _, ok := m.VRF().Get(want.VRFName); !ok {
			t.Errorf("%s: VRF not ensured", want.VRFName)
		}
	}
	if err := m.Bind(Binding{VRFName: "later"}); err != nil {
		t.Fatal(err)
	}
	if m.Restored("later") {
		t.Error("a bound binding is marked restored")
	}
}

// Restore refuses a record this daemon could not have saved instead of
// guessing.
func TestRestore_RefusesWhatCouldNotHaveBeenSaved(t *testing.T) {
	ok := Binding{VRFName: "a", Families: map[bgp.Family]FamilyPolicy{
		bgp.FamilyVPNv4: {RouteTargets: []RouteTarget{{RT: "65000:1", Direction: DirectionBoth}}},
	}}.Normalize()
	cases := map[string][]Binding{
		"no name":       {{RD: "65000:1"}},
		"twice":         {ok, ok},
		"bad family":    {{VRFName: "a", Families: map[bgp.Family]FamilyPolicy{"ipv6_unicast": {}}}},
		"bad direction": {{VRFName: "a", Families: map[bgp.Family]FamilyPolicy{bgp.FamilyVPNv4: {RouteTargets: []RouteTarget{{RT: "65000:1"}}}}}},
		"legacy disagrees": {func() Binding {
			b := ok
			b.ExportRTs = []string{"65000:9"}
			return b
		}()},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			m := NewManager()
			if err := m.Restore(in); err == nil {
				t.Fatal("Restore accepted it")
			}
			if len(m.List()) != 0 {
				t.Errorf("a refused Restore left bindings: %+v", m.List())
			}
		})
	}
	m := NewManager()
	if err := m.Bind(Binding{VRFName: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore([]Binding{ok}); err == nil || !strings.Contains(err.Error(), "already bound") {
		t.Errorf("Restore over a bound VRF: %v", err)
	}
}

// Route-target strings are restored as saved, even ones the API let through
// without checking, so a restart never refuses what the last run accepted.
func TestRestore_DoesNotRecheckRouteTargets(t *testing.T) {
	b := Binding{VRFName: "a", ImportRTs: []string{"not-an-rt"}}.Normalize()
	m := NewManager()
	if err := m.Restore([]Binding{b}); err != nil {
		t.Fatalf("Restore: %v", err)
	}
}
