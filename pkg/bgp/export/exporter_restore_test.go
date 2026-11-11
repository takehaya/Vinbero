package export

import (
	"slices"
	"testing"

	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// A binding restored from the state file that cannot be enabled at boot (its
// locator was registered over the API and is not back yet) is left without
// auto-advertise; the start goes on and enables the others.
func TestEnableBindings_RestoredFailureDoesNotStopTheStart(t *testing.T) {
	e, _, _ := newTestExporter(t)
	cfgBinding := testBinding()
	cfgBinding.Redistribute = []string{"static"}
	restored := testBinding()
	restored.VRFName = "vrf2"
	restored.DefaultLocator = "LOC-API"
	restored.Redistribute = []string{"static"}
	if err := e.vrfBindings.Restore([]vrfbgp.Binding{restored.Normalize()}); err != nil {
		t.Fatal(err)
	}
	if err := e.vrfBindings.Bind(cfgBinding); err != nil {
		t.Fatal(err)
	}
	enabled, err := e.enableBindings()
	if err != nil {
		t.Fatalf("enableBindings: %v", err)
	}
	if !slices.Equal(enabled, []string{"vrf1"}) {
		t.Errorf("enabled %v, want [vrf1]", enabled)
	}
}

// A config binding that cannot be enabled still fails the start.
func TestEnableBindings_ConfigFailureStopsTheStart(t *testing.T) {
	e, _, _ := newTestExporter(t)
	b := testBinding()
	b.DefaultLocator = "LOC-MISSING"
	b.Redistribute = []string{"static"}
	if err := e.vrfBindings.Bind(b); err != nil {
		t.Fatal(err)
	}
	if _, err := e.enableBindings(); err == nil {
		t.Fatal("a config binding with a missing locator did not fail the start")
	}
}
