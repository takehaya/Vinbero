package wasm

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func mustCaps(t *testing.T, names ...string) Capabilities {
	t.Helper()
	caps, err := ParseCapabilities(names)
	if err != nil {
		t.Fatalf("parse capabilities %v: %v", names, err)
	}
	return caps
}

func TestParseCapabilities(t *testing.T) {
	caps := mustCaps(t, "headend", " advertise ")
	if !caps.Has(CapHeadend) || !caps.Has(CapAdvertise) {
		t.Fatalf("granted %v, want headend and advertise", caps.Names())
	}
	if caps.Has(CapLocalSID) {
		t.Error("a capability that was not asked for was granted")
	}
	if _, err := ParseCapabilities([]string{"root"}); err == nil {
		t.Error("an unknown capability was accepted")
	} else if !errors.Is(err, ErrAdmission) {
		t.Errorf("error = %v, want ErrAdmission", err)
	}
}

// A plugin granted nothing cannot import the desired-set functions at all.
// That is what makes this a capability rather than a permission check:
// there is no call site left to forget.
func TestUngrantedModuleIsRefused(t *testing.T) {
	inst, err := instantiate(t, "apply", Config{Capabilities: mustCaps(t)})
	if err == nil {
		_ = inst.Close(context.Background())
		t.Fatal("a module importing the apply functions was admitted with no capability")
	}
	if !errors.Is(err, ErrAdmission) {
		t.Fatalf("error = %v, want ErrAdmission", err)
	}
	// The message has to name what was asked for, or an operator cannot
	// tell which grant is missing.
	if !strings.Contains(err.Error(), "apply_begin") {
		t.Errorf("error does not name the ungranted import: %v", err)
	}
}

// Any write capability covers the shared apply functions; which kinds may
// actually be declared is checked where the transaction is opened.
func TestGrantedModuleIsAdmitted(t *testing.T) {
	for _, name := range []string{"headend", "advertise", "local_sid"} {
		t.Run(name, func(t *testing.T) {
			inst, err := instantiate(t, "apply", Config{Capabilities: mustCaps(t, name)})
			if err != nil {
				t.Fatalf("a module granted %q was refused: %v", name, err)
			}
			_ = inst.Close(context.Background())
		})
	}
}

// A plugin that only observes needs no grant, and must still run: log and
// the clock are diagnostics rather than authority.
func TestObserveOnlyPluginNeedsNoCapability(t *testing.T) {
	inst, err := instantiate(t, "echo", Config{Capabilities: mustCaps(t)})
	if err != nil {
		t.Fatalf("a plugin that only observes was refused: %v", err)
	}
	defer func() { _ = inst.Close(context.Background()) }()

	// It can still be delivered events and can still log.
	if _, err := inst.HandleEvents(context.Background(), []byte("batch")); err != nil {
		t.Fatalf("handle events: %v", err)
	}
	if !inst.Capabilities().Has(CapHeadend) && len(inst.Capabilities().Names()) != 0 {
		t.Fatalf("capabilities = %v, want none", inst.Capabilities().Names())
	}
}

func TestCapabilityNamesAreStable(t *testing.T) {
	caps := mustCaps(t, "local_sid", "advertise", "headend")
	got := strings.Join(caps.Names(), ",")
	if got != "advertise,headend,local_sid" {
		t.Fatalf("Names() = %q, want a sorted list", got)
	}
}
