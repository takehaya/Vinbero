package vrf

import (
	"errors"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// Every member port of a VRF device that is not an AC of that VRF gets one
// warning naming the VRF and the port. A port with an AC on any VLAN, an
// opted-out VRF (no unreachable default, so nothing is dropped) and a VRF
// without a device are not reported; a VRF whose members cannot be listed
// is warned about once and the others are still checked.
func TestWarnMembersWithoutAC(t *testing.T) {
	m := NewManager()
	mustSet := func(name string, d Device) {
		t.Helper()
		if _, err := m.SetDevice(name, d); err != nil {
			t.Fatal(err)
		}
	}
	mustSet("vrf-a", Device{TableID: 100, Ifindex: 10})
	mustSet("vrf-open", Device{TableID: 200, Ifindex: 20, NoUnreachableDefault: true})
	mustSet("vrf-err", Device{TableID: 300, Ifindex: 30})
	if _, err := m.AddAC("vrf-a", AC{Interface: "eth3", VLAN: 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddAC("vrf-a", AC{Interface: "eth4", VLAN: 7}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddAC("vpn-only", AC{Interface: "eth9"}); err != nil {
		t.Fatal(err)
	}
	members := func(ifindex uint32) ([]string, error) {
		switch ifindex {
		case 10:
			return []string{"eth4", "eth2", "eth3"}, nil
		case 20:
			return []string{"eth5"}, nil
		case 30:
			return nil, errors.New("boom")
		}
		t.Errorf("members of %d asked", ifindex)
		return nil, nil
	}

	core, logs := observer.New(zap.WarnLevel)
	m.WarnMembersWithoutAC(members, zap.New(core))

	ports := logs.FilterMessageSnippet("is not an access circuit of its VRF").All()
	if len(ports) != 1 {
		t.Fatalf("warnings = %v, want one for eth2", logs.All())
	}
	fields := ports[0].ContextMap()
	if fields["vrf"] != "vrf-a" || fields["interface"] != "eth2" {
		t.Errorf("warning fields = %v, want vrf-a / eth2", fields)
	}
	if logs.FilterMessageSnippet("cannot check the VRF member ports").Len() != 1 {
		t.Errorf("the failing VRF was not reported: %v", logs.All())
	}
}
