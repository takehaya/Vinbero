package apply

import (
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/headend"
	"github.com/takehaya/vinbero/pkg/ownership"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// Give the existing BGP fake the read surface needed for plugin desired sets.
type sharedHeadendMaps struct{ *fakeHeadend }

func (m sharedHeadendMaps) ListHeadendV4() (map[string]*bpf.HeadendEntry, error) {
	return m.v4created, nil
}

func (m sharedHeadendMaps) ListHeadendV6() (map[string]*bpf.HeadendEntry, error) {
	return m.v6created, nil
}

func TestVPNAndPluginUseSharedHeadendOwnership(t *testing.T) {
	fh := newFakeHeadend()
	r, err := headend.NewReconciler(sharedHeadendMaps{fh}, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop(), WithHeadendWriter(r))
	const prefix = "10.0.0.0/24"
	plugin := bpf.OwnerPluginBundle("test")
	want := []headend.Desired{{TriggerPrefix: prefix, Entry: &bpf.HeadendEntry{}}}
	advert := vpnEvent(prefix, "65000:1", "fd00:1:1:a::", "fd00::1", false)
	a.Apply(advert)
	if _, err := r.ApplySet(plugin, headend.AFv4, want, -1); !errors.Is(err, ownership.ErrLeaseHeld) {
		t.Fatalf("plugin overwrote a live BGP route: %v", err)
	}
	a.Apply(vpnEvent(prefix, "65000:1", "", "fd00::1", true))
	if _, err := r.ApplySet(plugin, headend.AFv4, want, -1); err != nil {
		t.Fatalf("BGP withdrawal stranded a lease: %v", err)
	}
	a.Apply(advert)
	if fh.v4owners[prefix] != plugin {
		t.Fatal("BGP overwrote a plugin-owned route")
	}
	if _, err := r.PruneOwner(plugin, headend.AFv4); err != nil {
		t.Fatal(err)
	}
	a.Apply(advert)
	if fh.v4owners[prefix] != bpf.OwnerBGPVPN(65000, "") || fh.v4created[prefix].GroupId == 0 {
		t.Fatal("BGP failed to restore its ECMP trigger after plugin flush")
	}
}

// Simulate an operator replacement between observing a legacy owner and deleting
// it. Migration must not force-delete the replacement under the stale identity.
type replacedLegacyOwner struct {
	headend.Writer
	maps *fakeHeadend
}

func (w replacedLegacyOwner) GetHeadendV4Owner(prefix string) (bpf.OwnerTag, bool, error) {
	owner, found, err := w.Writer.GetHeadendV4Owner(prefix)
	w.maps.v4owners[prefix] = bpf.OwnerRPC
	return owner, found, err
}

func TestLegacyMigrationDoesNotDeleteReplacementOwner(t *testing.T) {
	fh := newFakeHeadend()
	const prefix = "10.0.0.0/24"
	fh.v4owners[prefix] = bpf.OwnerBGPVPN(65000, "65000:1")
	fh.v4created[prefix] = &bpf.HeadendEntry{}
	r, err := headend.NewReconciler(sharedHeadendMaps{fh}, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop(), WithHeadendWriter(replacedLegacyOwner{r, fh}))
	a.Apply(vpnEvent(prefix, "65000:1", "fd00:1:1:a::", "fd00::1", false))
	if fh.v4owners[prefix] != bpf.OwnerRPC || fh.v4created[prefix] == nil || len(fh.v4forced) != 0 {
		t.Fatal("migration deleted a replacement installed after its owner lookup")
	}
}
