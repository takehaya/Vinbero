package apply

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

func vpnEventWithRT(prefix, rt string) bgp.RouteEvent {
	return bgp.RouteEvent{
		Family: bgp.FamilyVPNv4,
		VPN: &bgp.VPNRoute{
			Family: bgp.FamilyVPNv4, Prefix: prefix, RD: "65000:9",
			SRv6SID: "fd00:1:1:d::", RTs: []string{rt},
		},
	}
}

// A replay after a family's first import RT gives each route the result a
// fresh delivery would get: a route no VRF imports leaves the data plane. The
// denials are summarized in one line, and live denials warn again afterwards.
func TestQuietVPNDenialsReplayEndsDefaultAllow(t *testing.T) {
	fh := newFakeHeadend()
	vm := vrfbgp.NewManager()
	core, logs := observer.New(zapcore.InfoLevel)
	a := NewApplier(fh, testLocatorManager(t), vm, &fakeFib{}, "LOC1", 65000, zap.New(core))

	kept, denied := vpnEventWithRT("10.1.0.0/24", "65000:100"), vpnEventWithRT("10.2.0.0/24", "65000:999")
	a.Apply(kept)
	a.Apply(denied)
	if _, ok := fh.v4created["10.2.0.0/24"]; !ok {
		t.Fatal("default-allow did not install the route")
	}

	if err := vm.Bind(vrfbgp.Binding{VRFName: "vrf-a", ImportRTs: []string{"65000:100"}}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	logs.TakeAll()
	if err := a.QuietVPNDenials(func() error {
		a.Apply(kept)
		a.Apply(denied)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := fh.v4created["10.2.0.0/24"]; ok {
		t.Error("replay left a route no VRF imports in the data plane")
	}
	if _, ok := fh.v4created["10.1.0.0/24"]; !ok {
		t.Error("replay removed an imported route")
	}
	if n := logs.FilterLevelExact(zapcore.WarnLevel).Len(); n != 0 {
		t.Errorf("replay logged %d warnings, want 0", n)
	}
	sum := logs.FilterMessage("VPN loc-rib replay dropped routes no VRF imports").All()
	if len(sum) != 1 || sum[0].ContextMap()["routes"] != int64(1) {
		t.Errorf("summary = %+v, want one line with routes=1", sum)
	}

	logs.TakeAll()
	a.Apply(denied)
	if n := logs.FilterLevelExact(zapcore.WarnLevel).Len(); n != 1 {
		t.Errorf("live denial logged %d warnings, want 1", n)
	}
}
