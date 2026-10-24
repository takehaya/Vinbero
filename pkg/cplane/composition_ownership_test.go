package cplane

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/headend"
)

func TestCompositionOccupiedReplacementPreservesWorkingKeys(t *testing.T) {
	for _, pair := range [][2]string{{"10.0.0.1/32", "10.0.0.2/32"}, {"fd00:10::1/128", "fd00:10::2/128"}, {"10.0.0.1/32", "fd00:10::2/128"}, {"fd00:10::1/128", "10.0.0.2/32"}} {
		for _, leased := range []bool{false, true} {
			name := pair[0] + "->" + pair[1]
			if leased {
				name += "/lease"
			}
			t.Run(name, func(t *testing.T) {
				p, f := familyComposition(t)
				if err := putComposition(p, headendComposition(1, pair[0])); err != nil {
					t.Fatal(err)
				}
				af, kind := AFv4, LeaseHeadendV4
				if netip.MustParsePrefix(pair[1]).Addr().Is6() {
					af, kind = AFv6, LeaseHeadendV6
				}
				other := bpf.OwnerTag("plugin:other")
				if leased {
					if err := p.leases.Acquire(kind, pair[1], other); err != nil {
						t.Fatal(err)
					}
				} else {
					var err error
					if af == AFv4 {
						err = f.CreateHeadendV4(pair[1], &bpf.HeadendEntry{}, other)
					} else {
						err = f.CreateHeadendV6(pair[1], &bpf.HeadendEntry{}, other)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				before := len(f.writes)
				err := putComposition(p, headendComposition(2, pair[1]))
				if leased && !errors.Is(err, ErrLeaseHeld) || !leased && !errors.Is(err, bpf.ErrEntryOwnerMismatch) {
					t.Fatalf("expected ownership refusal, got %v", err)
				}
				if len(f.writes) != before {
					t.Fatal("refused replacement mutated working or foreign keys")
				}
				oldaf := AFv4
				if netip.MustParsePrefix(pair[0]).Addr().Is6() {
					oldaf = AFv6
				}
				entries, err := p.headend.OwnedEntries(p.owner, oldaf)
				if err != nil || len(entries) != 1 || entries[0].TriggerPrefix != pair[0] {
					t.Fatalf("lost working key: %v %v", entries, err)
				}
			})
		}
	}
}

type reserveRaceOps struct {
	*fakeHeadendOps
	reserve func()
}

func (f *reserveRaceOps) GetHeadendV6Owner(prefix string) (bpf.OwnerTag, bool, error) {
	owner, ok, err := f.fakeHeadendOps.GetHeadendV6Owner(prefix)
	if f.reserve != nil {
		reserve := f.reserve
		f.reserve = nil
		reserve()
	}
	return owner, ok, err
}

func TestHeadendBothFamilyReservationRollback(t *testing.T) {
	p, f := familyComposition(t)
	if err := putComposition(p, headendComposition(1, "10.0.0.1/32")); err != nil {
		t.Fatal(err)
	}
	maps := &reserveRaceOps{fakeHeadendOps: f.fakeHeadendOps, reserve: func() {
		if err := p.leases.Acquire(LeaseHeadendV6, "fd00:10::2/128", "plugin:other"); err != nil {
			t.Fatal(err)
		}
	}}
	r, err := headend.NewReconciler(maps, p.leases)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.ApplySets(p.owner, desire("10.0.0.2/32"), desire("fd00:10::2/128"), 2)
	if !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("expected raced lease refusal, got %v", err)
	}
	if _, held := p.leases.HolderOf(LeaseHeadendV4, "10.0.0.2/32"); held {
		t.Fatal("first-family new lease leaked")
	}
	if f.v4["10.0.0.1/32"] == nil {
		t.Fatal("reservation failure pruned working key")
	}
	if holder, held := p.leases.HolderOf(LeaseHeadendV4, "10.0.0.1/32"); !held || holder != p.owner {
		t.Fatal("rollback released existing lease")
	}
}

func TestHeadendBothFamilyWriteFailureReleasesOnlyUnwrittenKeys(t *testing.T) {
	for _, failure := range []string{"10.0.0.1/32", "fd00:10::1/128"} {
		t.Run(failure, func(t *testing.T) {
			p, f := familyComposition(t)
			f.failOn = failure
			_, err := p.headend.ApplySets(p.owner, desire("10.0.0.1/32"), desire("fd00:10::1/128"), 2)
			if err == nil {
				t.Fatal("expected write failure")
			}
			v4holder, v4held := p.leases.HolderOf(LeaseHeadendV4, "10.0.0.1/32")
			if v4held != (failure != "10.0.0.1/32") || v4held && v4holder != p.owner {
				t.Fatal("wrong written-key lease retention")
			}
			if _, held := p.leases.HolderOf(LeaseHeadendV6, "fd00:10::1/128"); held {
				t.Fatal("unwritten IPv6 lease leaked")
			}
			f.failOn = ""
			if _, err := p.headend.ApplySets(p.owner, desire("10.0.0.1/32"), desire("fd00:10::1/128"), 2); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type ownerDeleteFailureOps struct {
	*serviceFake
	fail bool
}

func (f *ownerDeleteFailureOps) DeleteHeadendV4(prefix string, owner bpf.OwnerTag) error {
	if f.fail {
		delete(f.v4, prefix)
		return errors.New("owner deletion failed")
	}
	return f.serviceFake.DeleteHeadendV4(prefix, owner)
}
func (f *ownerDeleteFailureOps) DeleteHeadendV6(prefix string, owner bpf.OwnerTag) error {
	if f.fail {
		delete(f.v6, prefix)
		return errors.New("owner deletion failed")
	}
	return f.serviceFake.DeleteHeadendV6(prefix, owner)
}
func TestColdOrdinaryReservationStatsAndCleanup(t *testing.T) {
	for _, prefix := range []string{"10.0.0.1/32", "fd00:10::1/128"} {
		t.Run(prefix, func(t *testing.T) {
			p, f := familyComposition(t)
			if err := putComposition(p, headendComposition(1, prefix)); err != nil {
				t.Fatal(err)
			}
			maps := &ownerDeleteFailureOps{serviceFake: f, fail: true}
			r, err := headend.NewReconciler(maps, p.leases)
			if err != nil {
				t.Fatal(err)
			}
			p.headend = r
			if err := p.Flush(); err == nil {
				t.Fatal("expected owner cleanup failure")
			}
			if len(f.v4)+len(f.v6) != 0 || compositionStats(p).HeadendEntries != 1 {
				t.Fatal("live owner-only reservation lost")
			}
			fresh, err := headend.NewReconciler(maps, nil)
			if err != nil {
				t.Fatal(err)
			}
			cold, err := NewPluginOps(PluginOpsConfig{Owner: p.owner, HeadendReconciler: fresh, Capabilities: p.caps, Guard: p.guard})
			if err != nil {
				t.Fatal(err)
			}
			if compositionStats(cold).HeadendEntries != 1 {
				t.Fatal("cold owner-only reservation lost")
			}
			maps.fail = false
			if err := cold.Flush(); err != nil {
				t.Fatal(err)
			}
			if compositionStats(cold).HeadendEntries != 0 || len(f.owner4)+len(f.owner6) != 0 {
				t.Fatal("reservation cleanup did not converge")
			}
		})
	}
}

func TestHeadendLegacyInventoryBackend(t *testing.T) {
	p, f := familyComposition(t)
	// Restrict the method set to the older MapOps contract.
	legacy := struct{ headend.MapOps }{MapOps: f}
	r, err := headend.NewReconciler(legacy, p.leases)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ApplySets(p.owner, desire("10.0.0.1/32"), desire("fd00:10::1/128"), 2); err != nil {
		t.Fatal(err)
	}
	for _, af := range []AddressFamily{AFv4, AFv6} {
		if count, err := r.OwnedCount(p.owner, af); err != nil || count != 1 {
			t.Fatalf("legacy inventory %d %v", count, err)
		}
	}
}
