package cplaneharness_test

import (
	"fmt"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"github.com/takehaya/vinbero/sdk/go/cplaneharness"
)

// soakRounds is how many advertise-and-withdraw pairs the soak drives.
// Large enough that a plugin which never reclaims memory runs out well
// before the end -- the leaking build of this same example dies around
// round 2000 in the memory this test allows.
const soakRounds = 5000

// soakMemoryPages is the linear memory the plugin gets: 1 MiB. Deliberately
// tight, because the point is to find out whether memory is reclaimed, and
// a generous limit would let a leak hide behind the round count.
const soakMemoryPages = 16

// A control-plane plugin runs for the life of the daemon and sees every
// route change in the network, so the question that decides whether a
// toolchain is usable at all is whether its memory comes back.
//
// The live set here is bounded on purpose: every prefix advertised is
// withdrawn again, so what the plugin legitimately holds stays small and
// anything the memory grows by is garbage. A plugin that never reclaims
// fails; one that does runs indefinitely in a megabyte.
//
// This is the test that qualified TinyGo. Built with the default
// -gc=leaking it fails partway through; with -gc=conservative it finishes.
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
