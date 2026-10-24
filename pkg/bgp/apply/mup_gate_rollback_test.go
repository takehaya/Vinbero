package apply

import (
	"errors"
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/headend"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
	"go.uber.org/zap"
)

type rollbackMaps struct {
	*recoveryMaps
	failCreate bool
}

func (m *rollbackMaps) CreateMupUplinkV4Owned(instance uint32, ep string, teid uint32, bits uint8, entry *bpf.HeadendEntry, owner bpf.OwnerTag) error {
	if m.failCreate {
		return errors.New("uplink create failed")
	}
	return m.CreateMupUplinkV4(instance, ep, teid, bits, entry)
}
func (m *rollbackMaps) DeleteMupUplinkV4Owned(instance uint32, ep string, teid uint32, bits uint8, owner bpf.OwnerTag) error {
	if m.failDelete {
		return errors.New("uplink delete failed")
	}
	return m.DeleteMupUplinkV4(instance, ep, teid, bits)
}

func TestMUPFailedUplinkAndGateRollbackRetainsOneReference(t *testing.T) {
	for _, shared := range []bool{false, true} {
		for _, recoverByWrite := range []bool{false, true} {
			name := "legacy/withdraw"
			if shared {
				name = "shared/withdraw"
			}
			if recoverByWrite {
				name += "/retry-create"
			}
			t.Run(name, func(t *testing.T) {
				m := &rollbackMaps{recoveryMaps: &recoveryMaps{fakeHeadend: newFakeHeadend()}, failCreate: true}
				var options []Option
				if shared {
					r, err := headend.NewReconciler(m, nil)
					if err != nil {
						t.Fatal(err)
					}
					options = append(options, WithHeadendWriter(r))
				}
				a := NewApplier(m, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop(), options...)
				m.failGateDelete = true
				r := bgp.MUPRoute{Type: bgp.MUPRouteTypeT2ST, RD: "65000:7", Endpoint: "192.0.2.1", TEID: 1, TEIDLen: 32, SRv6SID: "fd00:2::1"}
				key := mupT2STKey{rd: r.RD, endpoint: r.Endpoint, teid: r.TEID, teidLen: r.TEIDLen}
				ev := bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &r}
				a.Apply(ev)
				st := a.mupT2ST[key]
				if st == nil || !st.gateHeld || st.installedSID != "" || a.mupGateRefs["192.0.2.1/32"] != 1 {
					t.Fatalf("rollback state lost: %+v refs=%v", st, a.mupGateRefs)
				}
				a.Apply(ev)
				if a.mupGateRefs["192.0.2.1/32"] != 1 {
					t.Fatal("retry acquired another gate reference")
				}
				if recoverByWrite {
					m.failCreate = false
					a.RetryMUPOwnedCleanup()
					if st.installedSID != r.SRv6SID || len(m.mupUplink) != 1 || a.mupGateRefs["192.0.2.1/32"] != 1 {
						t.Fatal("retry did not reuse held gate")
					}
				}
				ev.IsWithdraw = true
				a.Apply(ev)
				if a.mupT2ST[key] == nil || !st.gateHeld || st.installedSID != "" || len(m.mupUplink) != 0 {
					t.Fatal("gate-only withdrawal failure was forgotten or uplink falsely marked installed")
				}
				m.failGateDelete = false
				a.RetryMUPOwnedCleanup()
				if a.mupT2ST[key] != nil || len(a.mupGateRefs) != 0 || m.v4created["192.0.2.1/32"] != nil {
					t.Fatal("withdraw retry leaked gate")
				}
			})
		}
	}
}

func TestMUPReannounceAfterGateOnlyDeleteFailureReinstallsUplink(t *testing.T) {
	m := &rollbackMaps{recoveryMaps: &recoveryMaps{fakeHeadend: newFakeHeadend()}}
	a := NewApplier(m, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
	r := bgp.MUPRoute{Type: bgp.MUPRouteTypeT2ST, RD: "65000:7", Endpoint: "192.0.2.1", TEID: 1, TEIDLen: 32, SRv6SID: "fd00:2::1"}
	ev := bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &r}
	a.Apply(ev)
	m.failGateDelete = true
	ev.IsWithdraw = true
	a.Apply(ev)
	if len(m.mupUplink) != 0 {
		t.Fatal("uplink not deleted")
	}
	ev.IsWithdraw = false
	a.Apply(ev)
	if len(m.mupUplink) != 1 || a.mupGateRefs["192.0.2.1/32"] != 1 {
		t.Fatal("same-SID reannounce skipped missing uplink or doubled reference")
	}
	m.failGateDelete = false
	ev.IsWithdraw = true
	a.Apply(ev)
	if len(a.mupGateRefs) != 0 {
		t.Fatal("final withdraw leaked reference")
	}
}
