package cplane

import (
	"testing"

	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

func TestCompositionBindingReconcilePreservesUnchangedAdvertisement(t *testing.T) {
	p, adv, _, _ := compositionVPNFixture(t, "10.7.0.0/24")
	bindings := p.guard.bindings.(*fakeBindingSource)
	initialAdds, initialWithdrawals := adv.counts()
	// A red-only edit still notifies every plugin, including this blue one.
	bindings.set("red", vrfbgp.Binding{VRFName: "red", RD: "65000:99"}.Normalize())
	if _, err := p.ReconcileAdvertised(t.Context()); err != nil {
		t.Fatal(err)
	}
	bindings.remove("red")
	if _, err := p.ReconcileAdvertised(t.Context()); err != nil {
		t.Fatal(err)
	}
	if adds, withdrawals := adv.counts(); adds != initialAdds || withdrawals != initialWithdrawals {
		t.Fatalf("unchanged blue route flapped: adds %d -> %d, withdrawals %d -> %d", initialAdds, adds, initialWithdrawals, withdrawals)
	}

	blue, _ := bindings.Get(testVRF)
	blue.RD = "65000:77"
	bindings.set(testVRF, blue)
	if _, err := p.ReconcileAdvertised(t.Context()); err != nil {
		t.Fatal(err)
	}
	if adds, withdrawals := adv.counts(); adds != initialAdds+1 || withdrawals != initialWithdrawals+1 {
		t.Fatalf("changed blue route was not replaced: adds=%d withdrawals=%d", adds, withdrawals)
	}
	if routes := p.advertise.LiveRoutes(p.owner); len(routes) != 1 || routes[0].RD != blue.RD {
		t.Fatalf("old binding remained advertised: %+v", routes)
	}
	bindings.remove(testVRF)
	if _, err := p.ReconcileAdvertised(t.Context()); err == nil {
		t.Fatal("missing binding unexpectedly accepted")
	}
	if p.advertise.LiveCount(p.owner) != 0 {
		t.Fatal("revoked binding retained its old advertisement")
	}
}

func TestCompositionBindingReconcileRepairsPendingIdenticalDesired(t *testing.T) {
	p, _, desired, _ := compositionVPNFixture(t, "10.7.0.0/24")
	bindings := p.guard.bindings.(*fakeBindingSource)
	blue, _ := bindings.Get(testVRF)
	bindings.remove(testVRF)
	desired.DesiredRevision++
	if err := putComposition(p, desired); err == nil {
		t.Fatal("missing binding unexpectedly accepted")
	}
	bindings.set(testVRF, blue)
	if _, err := p.ReconcileAdvertised(t.Context()); err != nil {
		t.Fatal(err)
	}
	wanted, applied, failure := p.OutputState()
	if wanted != desired.DesiredRevision || applied != wanted || failure != "" {
		t.Fatalf("binding recovery left pending output: desired=%d applied=%d failure=%q", wanted, applied, failure)
	}
}
