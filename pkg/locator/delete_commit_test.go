package locator

import (
	"errors"
	"testing"
)

// DeleteAndCommit removes the locator only once commit succeeds, and does
// not call it for a delete that would be refused anyway.
func TestManager_DeleteAndCommit(t *testing.T) {
	m := NewManager()
	loc := makeClassic48(t)
	if err := m.Add(&loc); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.AllocateSID("LOC1", nil); err != nil {
		t.Fatal(err)
	}
	called := false
	commit := func() error { called = true; return nil }
	if err := m.DeleteAndCommit("LOC1", false, commit); !errors.Is(err, ErrLocatorInUse) || called {
		t.Fatalf("delete of a locator in use: err=%v, commit called=%v", err, called)
	}
	if err := m.DeleteAndCommit("NOPE", true, commit); !errors.Is(err, ErrLocatorNotFound) || called {
		t.Fatalf("delete of an unknown locator: err=%v, commit called=%v", err, called)
	}
	injected := errors.New("injected")
	if err := m.DeleteAndCommit("LOC1", true, func() error { return injected }); !errors.Is(err, injected) {
		t.Fatalf("failed commit: err=%v", err)
	}
	if _, ok := m.Get("LOC1"); !ok {
		t.Fatal("a failed commit removed the locator")
	}
	if got := m.bindings.ListByLocator("LOC1"); len(got) != 1 {
		t.Fatalf("a failed commit dropped the bindings: %v", got)
	}
	if err := m.DeleteAndCommit("LOC1", true, commit); err != nil || !called {
		t.Fatalf("forced delete: err=%v, commit called=%v", err, called)
	}
	if _, ok := m.Get("LOC1"); ok {
		t.Fatal("the locator is still registered")
	}
}
