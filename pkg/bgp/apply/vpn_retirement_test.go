package apply

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

type failingVPNRetirement struct {
	*fakeHeadend
	triggerErr error
	groupErr   error
	dropGroup  bool
}

func (f *failingVPNRetirement) DeleteHeadendV4(prefix string, owner bpf.OwnerTag) error {
	if f.triggerErr != nil {
		return f.triggerErr
	}
	return f.fakeHeadend.DeleteHeadendV4(prefix, owner)
}

func (f *failingVPNRetirement) DeleteHeadendV6(prefix string, owner bpf.OwnerTag) error {
	if f.triggerErr != nil {
		return f.triggerErr
	}
	return f.fakeHeadend.DeleteHeadendV6(prefix, owner)
}

func (f *failingVPNRetirement) DeleteEcmpGroup(id uint32, owner bpf.OwnerTag) error {
	if f.groupErr != nil {
		if f.dropGroup {
			delete(f.ecmpGroups, id)
		}
		return f.groupErr
	}
	return f.fakeHeadend.DeleteEcmpGroup(id, owner)
}

func TestVPNRetirementFailureReservesGroupUntilCleanup(t *testing.T) {
	for _, family := range []bgp.Family{bgp.FamilyVPNv4, bgp.FamilyVPNv6} {
		for _, failure := range []string{"trigger", "owner", "group", "partial-group"} {
			for _, recovery := range []string{"withdraw", "readvertise"} {
				t.Run(fmt.Sprintf("%s/%s/%s", family, failure, recovery), func(t *testing.T) {
					fh := &failingVPNRetirement{fakeHeadend: newFakeHeadend()}
					a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
					fp := newFakeProber()
					a.SetProber(fp)
					prefixes := []string{"10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"}
					triggers := fh.v4created
					if family == bgp.FamilyVPNv6 {
						prefixes, triggers = []string{"2001:db8:1::/64", "2001:db8:2::/64", "2001:db8:3::/64"}, fh.v6created
					}
					event := func(index int, withdraw bool) bgp.RouteEvent {
						ev := vpnEvent(prefixes[index], "65000:1", fmt.Sprintf("fd00:1:1:%x::", index+1), "fd00::1", withdraw)
						ev.Family, ev.VPN.Family = family, family
						if withdraw {
							ev.VPN.SRv6SID, ev.VPN.NextHop = "", ""
						}
						return ev
					}
					a.Apply(event(0, false))
					original := triggers[prefixes[0]]
					if original == nil {
						t.Fatal("missing original trigger")
					}
					id := original.GroupId
					switch failure {
					case "trigger":
						fh.triggerErr = errors.New("trigger delete failed")
					case "owner":
						fh.triggerErr = bpf.ErrEntryOwnerMismatch
					case "group", "partial-group":
						fh.groupErr = errors.New("group delete failed")
						fh.dropGroup = failure == "partial-group"
					}
					a.Apply(event(0, true))
					if (len(fh.ecmpGroups[id]) == 0 && !fh.dropGroup) || slices.Contains(a.vpnGroups.freeIDs, id) {
						t.Fatal("failed retirement released the original group")
					}
					if a.vpnGroups.dests[vpnDestKey{family, prefixes[0]}] == nil {
						t.Fatal("failed retirement lost retry state")
					}
					if len(fp.registered[id]) == 0 {
						t.Fatal("remaining group lost its probe registration")
					}
					if (triggers[prefixes[0]] != nil) != (fh.triggerErr != nil) {
						t.Fatal("trigger deletion did not match the injected failure")
					}
					a.Apply(event(1, false))
					if next := triggers[prefixes[1]]; next == nil || next.GroupId == id {
						t.Fatalf("new prefix reused a group whose retirement failed: %+v", next)
					}
					fh.triggerErr, fh.groupErr = nil, nil
					if recovery == "readvertise" {
						a.Apply(event(0, false))
						if restored := triggers[prefixes[0]]; restored == nil || restored.GroupId != id {
							t.Fatalf("unchanged readvertisement did not restore its trigger: %+v", restored)
						}
						if len(fp.registered[id]) == 0 {
							t.Fatal("restored group has no probe registration")
						}
					}
					a.Apply(event(0, true))
					if triggers[prefixes[0]] != nil || len(fh.ecmpGroups[id]) != 0 || len(fp.registered[id]) != 0 {
						t.Fatal("successful retry left forwarding or probe state")
					}
					if a.vpnGroups.dests[vpnDestKey{family, prefixes[0]}] != nil || !slices.Contains(a.vpnGroups.freeIDs, id) {
						t.Fatal("successful cleanup did not release tracking and group ID")
					}
					a.Apply(event(2, false))
					if next := triggers[prefixes[2]]; next == nil || next.GroupId != id {
						t.Fatalf("completed retirement did not make its ID reusable: %+v", next)
					}
				})
			}
		}
	}
}
