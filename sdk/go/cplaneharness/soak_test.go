package cplaneharness_test

import (
	"fmt"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"github.com/takehaya/vinbero/sdk/go/cplaneharness"
)

// The live set stays bounded: each route is immediately withdrawn. Enough
// churn to exhaust the 16 MiB budget if the guest never collects garbage.
const soakRounds = 50000
const soakMemoryPages = 256

// The standard Go artifact must keep processing and declaring state under
// the host's default memory limit after repeated allocation and collection.
func TestPluginSurvivesSustainedChurn(t *testing.T) {
	h := cplaneharness.New(t, exampleModule(t), cplaneharness.Options{
		Limits: wasm.Limits{MaxMemoryPages: soakMemoryPages},
	})
	for i := 0; i < soakRounds; i++ {
		prefix := fmt.Sprintf("10.%d.%d.0/24", i/256%256, i%256)
		if _, err := h.Route(&v1.PluginRoute{
			Family:           "vpnv4",
			Peer:             "192.0.2.1",
			EndpointBehavior: 0xFE01,
			Rd:               "65000:1",
			Prefix:           prefix,
			Srv6Sid:          "fd00:2::100",
		}); err != nil {
			t.Fatalf("advertise at round %d: %v", i, err)
		}
		if _, err := h.Route(&v1.PluginRoute{
			Family:     "vpnv4",
			Peer:       "192.0.2.1",
			IsWithdraw: true,
			Rd:         "65000:1",
			Prefix:     prefix,
		}); err != nil {
			t.Fatalf("withdraw at round %d: %v", i, err)
		}
	}

	// It is still working at the end, not merely still alive.
	decl, ok := h.LastDeclaration()
	if !ok {
		t.Fatal("the plugin stopped declaring during the churn")
	}
	if len(decl.Entries) != 0 {
		t.Fatalf("after withdrawing everything the plugin still declares %d entries", len(decl.Entries))
	}
}

// Restarting under sustained churn is the other half: a plugin that leaks
// only across restarts would pass the churn test alone.
func TestPluginSurvivesRepeatedRestarts(t *testing.T) {
	h := cplaneharness.New(t, exampleModule(t), cplaneharness.Options{
		Limits: wasm.Limits{MaxMemoryPages: soakMemoryPages},
	})
	for i := 0; i < 50; i++ {
		if _, err := h.Route(advertise("10.0.0.0/24", "fd00:2::100")); err != nil {
			t.Fatalf("advertise at restart %d: %v", i, err)
		}
		h.Restart()
	}
	if _, err := h.Route(advertise("10.0.0.0/24", "fd00:2::100")); err != nil {
		t.Fatalf("the plugin stopped working after repeated restarts: %v", err)
	}
}
