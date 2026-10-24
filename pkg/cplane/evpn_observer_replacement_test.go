package cplane

import (
	"os"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/cplane/native"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
)

func TestEVPNObserverReplacementClearsInheritedOutput(t *testing.T) {
	for _, backend := range []string{BackendNative, BackendWASM} {
		for _, observe := range []string{`,"observe_only":true`, ""} {
			mode := "explicit"
			if observe == "" {
				mode = "default"
			}
			t.Run(backend+"/"+mode, func(t *testing.T) {
				source := &compositionSource{newFakeSource()}
				source.rib = []bgp.RouteEvent{evpnPolicyFixture(t, false, "65000:7"), evpnPolicyFixture(t, true, "65000:7")}
				reg := Registration{Name: "observer-replacement", Backend: backend, Capabilities: wasm.Capabilities{wasm.CapEVPN: {}}, Input: &v1.CplaneInputPolicy{Version: 1, Contexts: []*v1.CplaneInputContext{{Name: "l2", Grants: []*v1.CplaneInputGrant{{Families: []string{"evpn"}, RouteTargets: []string{"65000:7"}}}, DelegateEvpn: true, BridgeDomain: 100}}}}
				if backend == BackendNative {
					reg.NativeID, reg.NativeVersion = native.EVPNIMET, native.ImplementationVersion
				} else {
					var err error
					reg.Module, err = os.ReadFile("../../out/cplane-evpn-imet.wasm")
					if err != nil {
						if os.Getenv("VINBERO_CPLANE_PARITY") == "1" {
							t.Fatal(err)
						}
						t.Skip("make cplane-evpn-imet", err)
					}
				}
				observerReplacement(t, source, reg, `{"context":"l2","source":"fd00:feed::1"`, observe)
			})
		}
	}
}
