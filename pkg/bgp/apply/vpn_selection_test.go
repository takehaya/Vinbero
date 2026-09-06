package apply

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// Equal SIDs can carry different steering and encapsulation attributes. The
// numeric ADD-PATH tie-break must pick a stable member without releasing the
// unselected path's policy reference: that path can be promoted on withdrawal.
func TestVPNSelectionDuplicateSIDKeepsStandbyPolicy(t *testing.T) {
	for _, family := range []bgp.Family{bgp.FamilyVPNv4, bgp.FamilyVPNv6} {
		for _, order := range [][]uint32{{10, 2}, {2, 10}} {
			t.Run(fmt.Sprintf("%s/%v", family, order), func(t *testing.T) {
				fh := newFakeHeadend()
				a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
				prefix := "10.0.0.0/24"
				triggers := fh.v4created
				if family == bgp.FamilyVPNv6 {
					prefix, triggers = "2001:db8:1::/64", fh.v6created
				}
				endpoint := netip.MustParseAddr("fd00::1")
				event := func(id uint32, withdraw bool) bgp.RouteEvent {
					ev := vpnEvent(prefix, "65000:1", "fd00:1:1:a::", endpoint.String(), withdraw)
					ev.Family, ev.VPN.Family, ev.Source.PathID = family, family, id
					if !withdraw {
						ev.VPN.Color = id
						if id == 2 {
							ev.VPN.SIDStructure = bgp.SIDStructure{LocatorBlockLen: 32, LocatorNodeLen: 16, FunctionLen: 16}
						}
					} else {
						ev.VPN.SRv6SID, ev.VPN.NextHop = "", ""
					}
					return ev
				}
				for _, id := range order {
					a.Apply(event(id, false))
				}
				check := func(id uint32, mode v1.Srv6HeadendBehavior) {
					t.Helper()
					trigger := triggers[prefix]
					if trigger == nil {
						t.Fatal("missing trigger")
					}
					members := fh.ecmpGroups[trigger.GroupId]
					policyID := a.srPolicy.idOf(id, endpoint)
					if policyID == 0 || len(members) != 1 || members[0].Entry.PolicyId != policyID || members[0].Entry.Mode != uint8(mode) {
						t.Fatalf("member does not use path %d's policy %d and mode %v: %+v", id, policyID, mode, members)
					}
					if trigger.PolicyId != policyID || trigger.Mode != uint8(mode) {
						t.Fatalf("fallback differs from the selected member: %+v", trigger)
					}
				}
				check(2, v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_RED)
				standbyID := a.srPolicy.idOf(10, endpoint)
				if standbyID == 0 {
					t.Fatal("deduplicated path lost its policy reference")
				}
				a.Apply(event(2, false))
				a.Apply(event(2, true))
				check(10, v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS)
				if a.srPolicy.idOf(2, endpoint) != 0 || a.srPolicy.idOf(10, endpoint) != standbyID {
					t.Fatal("withdraw leaked the selected reference or reallocated the standby policy")
				}
				a.Apply(event(10, true))
				if a.srPolicy.idOf(10, endpoint) != 0 {
					t.Fatal("last withdrawal leaked a policy reference")
				}
			})
		}
	}
}

func TestVPNSelectionCappedMembersPromoteStandby(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reverse=%t", reverse), func(t *testing.T) {
			fh := newFakeHeadend()
			a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
			const prefix = "10.0.0.0/24"
			endpoint := netip.MustParseAddr("fd00::1")
			var events []bgp.RouteEvent
			var expected []string
			for i := 1; i <= bpf.EcmpMaxPaths+2; i++ {
				sid := fmt.Sprintf("fd00:1:1:%x::", i)
				ev := vpnEvent(prefix, "65000:1", sid, endpoint.String(), false)
				ev.Source.PathID, ev.VPN.Color = uint32(i), uint32(i)
				events = append(events, ev)
				expected = append(expected, sid)
			}
			slices.Sort(expected)
			if reverse {
				slices.Reverse(events)
			}
			for _, ev := range events {
				a.Apply(ev)
			}
			trigger := fh.v4created[prefix]
			if trigger == nil {
				t.Fatal("missing trigger")
			}
			if got := groupSIDs(t, fh, trigger.GroupId); !slices.Equal(got, expected[:bpf.EcmpMaxPaths]) {
				t.Fatalf("selected %v, want %v", got, expected[:bpf.EcmpMaxPaths])
			}
			for _, ev := range events {
				if a.srPolicy.idOf(ev.VPN.Color, endpoint) == 0 {
					t.Fatalf("tracked path %d lost its reference", ev.Source.PathID)
				}
			}
			withdraw := vpnEvent(prefix, "65000:1", "", endpoint.String(), true)
			withdraw.Source.PathID = 1
			a.Apply(withdraw)
			if got := groupSIDs(t, fh, trigger.GroupId); !slices.Equal(got, expected[1:bpf.EcmpMaxPaths+1]) {
				t.Fatalf("after withdrawal got %v, want standby promotion to %v", got, expected[1:bpf.EcmpMaxPaths+1])
			}
			if a.srPolicy.idOf(1, endpoint) != 0 {
				t.Fatal("withdrawn path retained its reference")
			}
		})
	}
}

func TestVPNSelectionInvalidSteeringReplacementKeepsForwarding(t *testing.T) {
	for _, nextHop := range []string{"", "not-an-address", "192.0.2.1"} {
		t.Run(nextHop, func(t *testing.T) {
			fh := newFakeHeadend()
			a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
			ev := vpnEvent("10.0.0.0/24", "65000:1", "fd00:1:1:a::", "fd00::1", false)
			ev.VPN.Color = 100
			a.Apply(ev)
			endpoint := netip.MustParseAddr("fd00::1")
			if a.srPolicy.idOf(100, endpoint) == 0 {
				t.Fatal("initial path did not reserve its policy")
			}
			ev.VPN.NextHop = nextHop
			a.Apply(ev)
			trigger := fh.v4created[ev.VPN.Prefix]
			if trigger == nil || trigger.PolicyId != 0 || netip.AddrFrom16(trigger.DstAddr).String() != ev.VPN.SRv6SID {
				t.Fatalf("replacement did not preserve unsteered forwarding: %+v", trigger)
			}
			if a.srPolicy.idOf(100, endpoint) != 0 {
				t.Fatal("replacement leaked the old steering reference")
			}
		})
	}
}
