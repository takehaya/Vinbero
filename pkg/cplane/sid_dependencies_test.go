package cplane

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
)

type sidDependencyFixture struct {
	ops            *PluginOps
	sids           *LocalSIDSet
	advertiser     *fakeAdvertiser
	advertisements *AdvertiseSet
	oldSID         netip.Addr
	notifications  []AllocatedSID
}

func newSIDDependencyFixture(t *testing.T) *sidDependencyFixture {
	t.Helper()
	f := &sidDependencyFixture{
		sids:       NewLocalSIDSet(&fakeAllocator{}, newFakeSIDOps(), nil, nil),
		advertiser: &fakeAdvertiser{},
	}
	allocated, _, err := f.sids.Apply(ownerA, []LocalSID{{Name: "self", Locator: "main", Slot: 33}}, unlimited)
	if err != nil {
		t.Fatal(err)
	}
	f.oldSID = allocated[0].SID
	f.advertisements = NewAdvertiseSet(f.advertiser, NewLeases())
	if _, err := f.advertisements.Apply(context.Background(), ownerA, []AdvertisedRoute{
		vpnRoute("10.7.0.0/24", f.oldSID.String()),
	}, unlimited); err != nil {
		t.Fatal(err)
	}
	f.ops, err = NewPluginOps(PluginOpsConfig{
		Owner: ownerA, Headend: newFakeHeadendOps(), Capabilities: testCaps(), Guard: testGuard(),
		LocalSIDs: f.sids, Advertise: f.advertisements, Quotas: Quotas{MaxLocalSIDs: 1},
		OnLocalSIDs: func(allocated []AllocatedSID) bool {
			f.notifications = append(f.notifications, allocated...)
			return true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *sidDependencyFixture) assertReferencesOwned(t *testing.T) {
	t.Helper()
	for _, route := range f.advertisements.LiveRoutes(ownerA) {
		if route.SRv6SID != "" && !f.sids.OwnsSID(ownerA, netip.MustParseAddr(route.SRv6SID)) {
			t.Fatalf("live advertisement references released SID: %+v", route)
		}
	}
}

func TestExampleReplacementKeepsReferencedSIDsWhenPublicationFails(t *testing.T) {
	for _, tt := range []struct {
		name     string
		config   []byte
		wantSIDs int
	}{
		{"disable sending", nil, 0},
		{"change locator", exampleConfig(0xFE01, "second", "10.7.0.0/24", testVRF, 33, "2001:db8::1"), 1},
		{"change endpoint slot", exampleConfig(0xFE01, "main", "10.7.0.0/24", testVRF, 34, "2001:db8::1"), 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newSIDDependencyFixture(t)
			f.advertiser.failWithdraw = "10.7.0.0/24"
			inst, err := wasm.Instantiate(context.Background(), wasm.Config{
				Name: "custom-behavior", Module: examplePlugin(t), ConfigBlob: tt.config,
				Ops: f.ops, Capabilities: testCaps(),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = inst.Close(context.Background()) }()
			if err := f.ops.Publish(); err == nil {
				t.Fatal("publication succeeded despite the failed withdrawal")
			}
			f.assertReferencesOwned(t)
			f.ops.RetryPending()
			if err := inst.Tick(context.Background(), int64(time.Second)); err != nil {
				t.Fatal(err)
			}
			f.assertReferencesOwned(t)
			if !f.sids.OwnsSID(ownerA, f.oldSID) || f.advertisements.LiveCount(ownerA) != 1 {
				t.Fatal("a refused withdrawal did not retain the original SID and advertisement")
			}

			f.advertiser.failWithdraw = ""
			f.ops.RetryPending()
			f.assertReferencesOwned(t)
			if tt.wantSIDs > 0 {
				if len(f.notifications) != 1 {
					t.Fatalf("resolved SID notifications=%d, want 1", len(f.notifications))
				}
				sid := f.notifications[0]
				raw, err := proto.Marshal(&v1.PluginEventBatch{Events: []*v1.PluginEvent{{
					Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_LOCAL_SID, Sequence: 1,
					LocalSid: &v1.PluginLocalSidAllocated{Name: sid.Name, Sid: sid.SID.String(), Locator: sid.Locator},
				}}})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := inst.HandleEvents(context.Background(), raw); err != nil {
					t.Fatal(err)
				}
			}
			f.assertReferencesOwned(t)
			if f.sids.LiveCount(ownerA) != tt.wantSIDs || f.advertisements.LiveCount(ownerA) != tt.wantSIDs {
				t.Fatal("replacement did not converge after withdrawal recovered")
			}
		})
	}
}

func TestInvalidSIDSetDoesNotWithdrawExistingAdvertisements(t *testing.T) {
	for _, names := range [][]string{{"new", "new"}, {"first", "second"}} {
		f := newSIDDependencyFixture(t)
		var desired []LocalSID
		for _, name := range names {
			desired = append(desired, LocalSID{Name: name, Locator: "main", Slot: 33})
		}
		if err := f.ops.applyTransaction(&applyTxn{
			kind: v1.PluginApplyKind_PLUGIN_APPLY_KIND_LOCAL_SID, sids: desired, seq: 1,
		}); err == nil {
			t.Fatal("duplicate names or an over-quota SID set was accepted")
		}
		f.assertReferencesOwned(t)
		if f.advertisements.LiveCount(ownerA) != 1 || !f.sids.OwnsSID(ownerA, f.oldSID) {
			t.Fatal("refused SID declaration changed existing forwarding state")
		}
	}
}
