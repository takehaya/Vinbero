package locator

import (
	"errors"
	"net/netip"
	"testing"
)

func TestManager_AddListGet(t *testing.T) {
	m := NewManager()
	loc := makeClassic48(t)
	if err := m.Add(&loc); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, ok := m.Get("LOC1")
	if !ok {
		t.Fatalf("Get missing")
	}
	if got.Name != "LOC1" || got.Prefix.String() != "fd00:1:1::/48" {
		t.Errorf("Get returned %+v", got)
	}
	if all := m.List(); len(all) != 1 {
		t.Errorf("List returned %d, want 1", len(all))
	}
}

func TestManager_AddDuplicateRejected(t *testing.T) {
	m := NewManager()
	loc := makeClassic48(t)
	if err := m.Add(&loc); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if err := m.Add(&loc); !errors.Is(err, ErrLocatorExists) {
		t.Errorf("duplicate Add: got %v, want ErrLocatorExists", err)
	}
}

func TestManager_DeleteUnknown(t *testing.T) {
	m := NewManager()
	if err := m.Delete("nope", false); !errors.Is(err, ErrLocatorNotFound) {
		t.Errorf("delete unknown: got %v, want ErrLocatorNotFound", err)
	}
}

func TestManager_AllocReleaseRoundTrip(t *testing.T) {
	m := NewManager()
	loc := makeClassic48(t)
	if err := m.Add(&loc); err != nil {
		t.Fatalf("Add: %v", err)
	}
	sid, binding, err := m.AllocateSID("LOC1", nil)
	if err != nil {
		t.Fatalf("AllocateSID: %v", err)
	}
	if !sid.IsValid() || !sid.Is6() {
		t.Errorf("AllocateSID returned invalid sid %s", sid)
	}
	if binding.LocatorName != "LOC1" {
		t.Errorf("binding name = %q, want LOC1", binding.LocatorName)
	}
	if got, ok := m.BindingOf(sid); !ok || got != binding {
		t.Errorf("BindingOf: ok=%v got=%+v want %+v", ok, got, binding)
	}

	m.ReleaseSID(sid)
	if _, ok := m.BindingOf(sid); ok {
		t.Errorf("BindingOf after Release: still present")
	}
}

func TestManager_DeleteRejectsInUseUnlessForce(t *testing.T) {
	m := NewManager()
	loc := makeClassic48(t)
	if err := m.Add(&loc); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, _, err := m.AllocateSID("LOC1", nil); err != nil {
		t.Fatalf("alloc: %v", err)
	}
	if err := m.Delete("LOC1", false); !errors.Is(err, ErrLocatorInUse) {
		t.Errorf("Delete in-use: got %v, want ErrLocatorInUse", err)
	}
	if err := m.Delete("LOC1", true); err != nil {
		t.Errorf("force Delete: %v", err)
	}
}

func TestManager_ManualFunction(t *testing.T) {
	m := NewManager()
	loc := makeClassic48(t)
	if err := m.Add(&loc); err != nil {
		t.Fatalf("Add: %v", err)
	}
	want := uint32(0x42)
	sid, binding, err := m.AllocateSID("LOC1", &want)
	if err != nil {
		t.Fatalf("AllocateSID manual: %v", err)
	}
	if binding.Function != want {
		t.Errorf("manual: got function=%#x want %#x", binding.Function, want)
	}
	expectedSID := netip.MustParseAddr("fd00:1:1:42::")
	if sid != expectedSID {
		t.Errorf("manual sid: got %s, want %s", sid, expectedSID)
	}
}

func TestManager_ReleaseUnknownIsNoOp(t *testing.T) {
	m := NewManager()
	m.ReleaseSID(netip.MustParseAddr("fd00:dead::1")) // must not panic
}
