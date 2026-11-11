package apply

import (
	"errors"
	"testing"

	"github.com/takehaya/vinbero/pkg/bpf"
)

// purgeMaps models the owner inventory of both headend maps, keyed by id,
// and of the MUP uplink v4 map.
type purgeMaps struct {
	v4, v6  map[bpf.HeadendID]bpf.OwnerTag
	uplinks map[bpf.MupUplinkV4Key]bpf.OwnerTag
	failOn  bpf.HeadendID
}

func (m *purgeMaps) ListMupUplinkV4Owners() (map[bpf.MupUplinkV4Key]bpf.OwnerTag, error) {
	return m.uplinks, nil
}

func (m *purgeMaps) ListMupUplinkV6Owners() (map[bpf.MupUplinkV6Key]bpf.OwnerTag, error) {
	return nil, nil
}

func (m *purgeMaps) DeleteMupUplinkV4Owned(instance uint32, ep string, teid uint32, bits uint8, owner bpf.OwnerTag) error {
	k := recoveryKey4(instance, ep, teid, bits)
	if m.uplinks[k] != owner {
		return bpf.ErrEntryOwnerMismatch
	}
	delete(m.uplinks, k)
	return nil
}

func (m *purgeMaps) DeleteMupUplinkV6Owned(uint32, string, uint32, uint8, bpf.OwnerTag) error {
	return nil
}

func (m *purgeMaps) ListHeadendV4OwnerIDs() (map[bpf.HeadendID]bpf.OwnerTag, error) {
	return m.v4, nil
}

func (m *purgeMaps) ListHeadendV6OwnerIDs() (map[bpf.HeadendID]bpf.OwnerTag, error) {
	return m.v6, nil
}

func (m *purgeMaps) del(t map[bpf.HeadendID]bpf.OwnerTag, v uint32, p string, owner bpf.OwnerTag) error {
	id := bpf.HeadendID{VRF: v, Prefix: p}
	if id == m.failOn {
		return errors.New("delete failed")
	}
	if t[id] != owner {
		return bpf.ErrEntryOwnerMismatch
	}
	delete(t, id)
	return nil
}

func (m *purgeMaps) DeleteHeadendV4In(v uint32, p string, owner bpf.OwnerTag) error {
	return m.del(m.v4, v, p, owner)
}

func (m *purgeMaps) DeleteHeadendV6In(v uint32, p string, owner bpf.OwnerTag) error {
	return m.del(m.v6, v, p, owner)
}

// The boot purge removes every entry this node's applier wrote for a route,
// in every VRF and both families, and nothing else: operator, plugin, gate
// and other-ASN entries stay. A failed removal is reported, not skipped
// silently, so the boot does not start forwarding over it.
func TestPurgeBuiltinHeadends(t *testing.T) {
	const asn = 65000
	vpn := bpf.OwnerBGPVPN(asn, "")
	mup := bpf.OwnerBGPMUP(asn, "65000:7")
	keep := map[bpf.HeadendID]bpf.OwnerTag{
		{Prefix: "10.9.0.0/24"}:         bpf.OwnerRPC,
		{VRF: 3, Prefix: "10.9.0.0/24"}: bpf.OwnerPluginBundle("p"),
		{Prefix: "192.0.2.1/32"}:        bpf.OwnerBGPMUPGate(asn),
		{Prefix: "192.0.2.2/32"}:        "builtin:v1:mup-gate",
		{VRF: 4, Prefix: "10.8.0.0/24"}: bpf.OwnerBGPVPN(65001, ""),
		{VRF: 4, Prefix: "10.7.0.0/24"}: bpf.OwnerBGPVPNGroup(asn),
		{Prefix: "10.6.0.0/24"}:         bpf.OwnerBGPEVPN(asn),
	}
	gone4 := map[bpf.HeadendID]bpf.OwnerTag{
		{Prefix: "10.0.0.0/24"}:         vpn,
		{VRF: 7, Prefix: "10.0.0.0/24"}: vpn,
		{Prefix: "10.2.0.1/32"}:         mup,
	}
	m := &purgeMaps{v4: map[bpf.HeadendID]bpf.OwnerTag{}, v6: map[bpf.HeadendID]bpf.OwnerTag{
		{VRF: 9, Prefix: "2001:db8::/64"}: vpn,
	}, uplinks: map[bpf.MupUplinkV4Key]bpf.OwnerTag{
		recoveryKey4(0, "192.0.2.1", 7, 32): mup,
		recoveryKey4(5, "192.0.2.1", 7, 32): mup,
		recoveryKey4(5, "192.0.2.9", 7, 32): bpf.OwnerPluginBundle("p"),
	}}
	for id, o := range keep {
		m.v4[id] = o
	}
	for id, o := range gone4 {
		m.v4[id] = o
	}
	n, err := PurgeBuiltinHeadends(m, asn)
	if err != nil || n != len(gone4)+3 {
		t.Fatalf("removed %d, err %v; want %d, nil", n, err, len(gone4)+3)
	}
	if len(m.uplinks) != 1 {
		t.Errorf("uplinks left = %v, want the plugin's only", m.uplinks)
	}
	if len(m.v6) != 0 || len(m.v4) != len(keep) {
		t.Fatalf("left v4 %v v6 %v, want only %v", m.v4, m.v6, keep)
	}
	for id, o := range keep {
		if m.v4[id] != o {
			t.Errorf("%s (%s) was removed", id, o)
		}
	}

	m.v4[bpf.HeadendID{VRF: 7, Prefix: "10.0.0.0/24"}] = vpn
	m.failOn = bpf.HeadendID{VRF: 7, Prefix: "10.0.0.0/24"}
	if _, err := PurgeBuiltinHeadends(m, asn); err == nil {
		t.Fatal("a failed removal must be reported")
	}
}
