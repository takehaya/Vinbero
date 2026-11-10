package vrf

import (
	"slices"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// membersFixture: vrf-a (device ifindex 10, closed) has as members an
// attached port with its untagged AC (eth3), an attached port without one
// (eth2), a VLAN subinterface of the attached eth1 covered by {eth1, 100}
// (eth1.100) and one that is not (eth1.200), and a dummy, a bridge and an
// SVI that XDP never sees. vrf-open (ifindex 20) opted out.
func membersFixture(t *testing.T) (*Manager, Links) {
	t.Helper()
	m := NewManager()
	for _, d := range []struct {
		name string
		dev  Device
	}{
		{"vrf-a", Device{TableID: 100, Ifindex: 10}},
		{"vrf-open", Device{TableID: 200, Ifindex: 20, NoUnreachableDefault: true}},
	} {
		if _, err := m.SetDevice(d.name, d.dev); err != nil {
			t.Fatal(err)
		}
	}
	for _, ac := range []AC{{Interface: "eth3"}, {Interface: "eth1", VLAN: 100}} {
		if _, err := m.AddAC("vrf-a", ac); err != nil {
			t.Fatal(err)
		}
	}
	links := Links{
		1:  {Name: "eth1", XDP: true},
		2:  {Name: "eth2", XDP: true, Master: 10},
		3:  {Name: "eth3", XDP: true, Master: 10},
		4:  {Name: "eth1.100", Master: 10, VLANOf: 1, VLANID: 100},
		5:  {Name: "eth1.200", Master: 10, VLANOf: 1, VLANID: 200},
		6:  {Name: "lo-a", Master: 10},
		7:  {Name: "br-a", Master: 10},
		8:  {Name: "br-a.5", Master: 10, VLANOf: 7, VLANID: 5},
		9:  {Name: "eth9", XDP: true, Master: 20},
		10: {Name: "vrf-a", IsVrf: true, VrfTable: 100},
		20: {Name: "vrf-open", IsVrf: true, VrfTable: 200},
		11: {Name: "eth11", XDP: true},
	}
	return m, links
}

// Only ports the data plane classifies count: an attached member without
// its untagged AC, and a VLAN subinterface of an attached port without its
// {parent, VLAN} AC. Dummies, bridges and SVIs are not reported, nor is a
// VRF that opted out, nor anything while the tables are open.
func TestMembersWithoutAC(t *testing.T) {
	m, links := membersFixture(t)
	got := m.MembersWithoutAC(links, "")
	var names []string
	for _, g := range got {
		names = append(names, g.VRF+"/"+g.Interface)
	}
	if !slices.Equal(names, []string{"vrf-a/eth2", "vrf-a/eth1.200"}) {
		t.Errorf("uncovered = %v, want vrf-a/eth2 and vrf-a/eth1.200", names)
	}
	if got[1].AC != (AC{Interface: "eth1", VLAN: 200}) {
		t.Errorf("eth1.200 needs %+v, want {eth1 200}", got[1].AC)
	}
	if len(m.MembersWithoutAC(links, "vrf-open")) != 0 {
		t.Error("an opted-out VRF reported members")
	}
	m.SetTablesClosed(false)
	if len(m.MembersWithoutAC(links, "")) != 0 {
		t.Error("open tables reported members")
	}
}

// One warning per uncovered member, naming the VRF and the port.
func TestWarnMembersWithoutAC(t *testing.T) {
	m, links := membersFixture(t)
	core, logs := observer.New(zap.WarnLevel)
	m.WarnMembersWithoutAC(links, "vrf-a", zap.New(core))
	got := logs.FilterMessageSnippet("is not an access circuit of its VRF").All()
	if len(got) != 2 || got[0].ContextMap()["interface"] != "eth2" || got[0].ContextMap()["vrf"] != "vrf-a" {
		t.Errorf("warnings = %v, want eth2 and eth1.200 in vrf-a", logs.All())
	}
}

// An L2 circuit counts as on a closed VRF's port only when the port's
// master is a managed VRF whose table ends in the unreachable default.
func TestL2CircuitsOnClosedVRFs(t *testing.T) {
	m, links := membersFixture(t)
	got := m.L2CircuitsOnClosedVRFs(links, []uint32{2, 9, 11, 2})
	if len(got) != 1 || got[0].Interface != "eth2" || got[0].VRF != "vrf-a" {
		t.Errorf("circuits = %+v, want only eth2 in vrf-a (eth9 is in an opted-out VRF, eth11 in none)", got)
	}
	if name, ok := m.ClosedVRFOfPort(links, 3); !ok || name != "vrf-a" {
		t.Errorf("ClosedVRFOfPort(eth3) = %q %v", name, ok)
	}
	if _, ok := m.ClosedVRFOfPort(links, 9); ok {
		t.Error("ClosedVRFOfPort(eth9) is closed, but vrf-open opted out")
	}
	m.SetTablesClosed(false)
	if len(m.L2CircuitsOnClosedVRFs(links, []uint32{2})) != 0 {
		t.Error("open tables reported a circuit")
	}
}

// Closedness belongs to the table: a VRF that opted out but shares its table
// with one that did not is closed too, for the L2 check, the member report
// and the create check.
func TestClosedByTable(t *testing.T) {
	m := NewManager()
	if _, err := m.SetDevice("vrf-x", Device{TableID: 600, Ifindex: 30}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetDevice("vrf-y", Device{TableID: 600, Ifindex: 31, NoUnreachableDefault: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetDevice("vrf-z", Device{TableID: 700, Ifindex: 32, NoUnreachableDefault: true}); err != nil {
		t.Fatal(err)
	}
	links := Links{
		5:  {Name: "eth5", XDP: true, Master: 31},
		6:  {Name: "eth6", XDP: true, Master: 32},
		7:  {Name: "eth7", XDP: true, Master: 33},
		30: {Name: "vrf-x", IsVrf: true, VrfTable: 600},
		31: {Name: "vrf-y", IsVrf: true, VrfTable: 600},
		32: {Name: "vrf-z", IsVrf: true, VrfTable: 700},
		33: {Name: "vrf-raw", IsVrf: true, VrfTable: 600}, // not managed by Vinbero
	}
	if name, ok := m.ClosedVRFOfPort(links, 5); !ok || name != "vrf-y" {
		t.Errorf("ClosedVRFOfPort(eth5) = %q %v, want vrf-y closed through table 600", name, ok)
	}
	if name, ok := m.ClosedVRFOfPort(links, 7); !ok || name != "vrf-raw" {
		t.Errorf("ClosedVRFOfPort(eth7) = %q %v, want the unmanaged vrf-raw closed through table 600", name, ok)
	}
	if _, ok := m.ClosedVRFOfPort(links, 6); ok {
		t.Error("eth6 is in vrf-z, alone on its opted-out table 700, and must not be closed")
	}
	got := m.MembersWithoutAC(links, "")
	if len(got) != 1 || got[0].VRF != "vrf-y" || got[0].Interface != "eth5" {
		t.Errorf("uncovered = %+v, want vrf-y/eth5 only", got)
	}
	if len(m.L2CircuitsOnClosedVRFs(links, []uint32{5, 6, 7})) != 2 {
		t.Error("the circuits on eth5 and eth7 are not both reported")
	}
	if !m.TableClosedAfterCreate(600, true) || m.TableClosedAfterCreate(700, true) || !m.TableClosedAfterCreate(800, false) {
		t.Error("TableClosedAfterCreate: want 600 closed for an opt-out, 700 open, 800 closed without one")
	}
}
