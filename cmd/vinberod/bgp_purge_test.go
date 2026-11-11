package main

import (
	"errors"
	"testing"

	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// What an earlier run left in the pinned headend maps goes before the data
// plane is attached: every trigger and downlink the BGP applier of this ASN
// wrote, in the global VRF (where a run that looked every packet up in the
// global VRF put the tenant routes) and in tenant VRFs. Entries of an
// operator, a plugin, a MUP gate and another ASN stay. Needs root (it loads
// the BPF collection).
func TestPurgeBGPHeadendsRemovesAnEarlierRunsEntries(t *testing.T) {
	objs, err := bpf.ReadCollection(nil, nil)
	if err != nil {
		t.Skipf("BPF collection load failed (needs sudo): %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	m := bpf.NewMapOperations(objs)
	t.Cleanup(func() { _, _ = m.ForceFlushHeadendV4(); _, _ = m.ForceFlushHeadendV6() })

	const asn = 65100
	entry := func() *bpf.HeadendEntry {
		segs, n, _ := bpf.ParseSegments([]string{"fd00:2::1"})
		return &bpf.HeadendEntry{Mode: uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS), NumSegments: n, Segments: segs}
	}
	gone := []bpf.HeadendID{{VRF: 0, Prefix: "10.2.0.0/24"}, {VRF: 7, Prefix: "10.2.0.0/24"}, {VRF: 0, Prefix: "10.3.0.0/24"}, {VRF: 7, Prefix: "10.4.0.1/32"}}
	gownr := []bpf.OwnerTag{bpf.OwnerBGPVPN(asn, ""), bpf.OwnerBGPVPN(asn, ""), bpf.OwnerBGPVPN(asn, ""), bpf.OwnerBGPMUP(asn, "65100:1")}
	for i, id := range gone {
		if err := m.CreateHeadendV4In(id.VRF, id.Prefix, entry(), gownr[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.CreateHeadendV6In(7, "2001:db8:2::/64", entry(), bpf.OwnerBGPVPN(asn, "")); err != nil {
		t.Fatal(err)
	}
	// The F-TEID entries of an earlier run's T2ST sessions, in the global
	// VRF and a tenant one, and a plugin's.
	for _, inst := range []uint32{0, 7} {
		if err := m.CreateMupUplinkV4Owned(inst, "192.0.2.1", 0x100, 32, entry(), bpf.OwnerBGPMUP(asn, "65100:1")); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.CreateMupUplinkV4Owned(7, "192.0.2.2", 0x100, 32, entry(), bpf.OwnerPluginBundle("p")); err != nil {
		t.Fatal(err)
	}
	keep := map[bpf.HeadendID]bpf.OwnerTag{
		{VRF: 0, Prefix: "10.9.0.0/24"}:  bpf.OwnerRPC,
		{VRF: 7, Prefix: "10.9.0.0/24"}:  bpf.OwnerPluginBundle("p"),
		{VRF: 7, Prefix: "192.0.2.1/32"}: bpf.OwnerTag("builtin:v1:mup-gate"),
		{VRF: 0, Prefix: "10.8.0.0/24"}:  bpf.OwnerBGPVPN(65001, ""),
	}
	for id, o := range keep {
		if err := m.CreateHeadendV4In(id.VRF, id.Prefix, entry(), o); err != nil {
			t.Fatal(err)
		}
	}

	if err := purgeBGPHeadends(m, asn, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	v4, err := m.ListHeadendV4OwnerIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(v4) != len(keep) {
		t.Errorf("v4 owners left = %v, want only %v", v4, keep)
	}
	for id, o := range keep {
		if v4[id] != o {
			t.Errorf("%s (%s) was removed", id, o)
		}
	}
	if v6, err := m.ListHeadendV6OwnerIDs(); err != nil || len(v6) != 0 {
		t.Errorf("v6 owners left = %v %v, want none", v6, err)
	}
	if ids, err := m.ListHeadendV4IDs(); err != nil || len(ids) != len(keep) {
		t.Errorf("v4 entries left = %v %v", ids, err)
	}
	uplinks, err := m.ListMupUplinkV4Owners()
	if err != nil || len(uplinks) != 1 {
		t.Errorf("uplinks left = %v %v, want the plugin's only", uplinks, err)
	}
	for _, o := range uplinks {
		if o != bpf.OwnerPluginBundle("p") {
			t.Errorf("uplink of %s left", o)
		}
	}
}

type failingPurge struct{}

func (failingPurge) ListHeadendV4OwnerIDs() (map[bpf.HeadendID]bpf.OwnerTag, error) {
	return nil, errors.New("map unreadable")
}
func (failingPurge) ListHeadendV6OwnerIDs() (map[bpf.HeadendID]bpf.OwnerTag, error) {
	return map[bpf.HeadendID]bpf.OwnerTag{}, nil
}
func (failingPurge) DeleteHeadendV4In(uint32, string, bpf.OwnerTag) error { return nil }
func (failingPurge) DeleteHeadendV6In(uint32, string, bpf.OwnerTag) error { return nil }
func (failingPurge) ListMupUplinkV4Owners() (map[bpf.MupUplinkV4Key]bpf.OwnerTag, error) {
	return nil, nil
}
func (failingPurge) ListMupUplinkV6Owners() (map[bpf.MupUplinkV6Key]bpf.OwnerTag, error) {
	return nil, nil
}
func (failingPurge) DeleteMupUplinkV4Owned(uint32, string, uint32, uint8, bpf.OwnerTag) error {
	return nil
}
func (failingPurge) DeleteMupUplinkV6Owned(uint32, string, uint32, uint8, bpf.OwnerTag) error {
	return nil
}

// A purge that cannot finish stops the boot: forwarding must not start over
// entries that may belong to another VRF.
func TestPurgeBGPHeadendsFailureIsFatal(t *testing.T) {
	if err := purgeBGPHeadends(failingPurge{}, 65100, zap.NewNop()); err == nil {
		t.Fatal("a failed purge must fail the boot")
	}
}
