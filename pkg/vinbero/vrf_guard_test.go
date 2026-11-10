package vinbero

import (
	"testing"

	"github.com/takehaya/vinbero/pkg/vrf"
)

// The guard looks at every port of every VRF device on the table, managed
// or not, and at the members VRFs on the table are to have; nothing else.
func TestL2CircuitOnTable(t *testing.T) {
	links := vrf.Links{
		10: {Name: "vrf-a", IsVrf: true, VrfTable: 600},
		11: {Name: "vrf-x", IsVrf: true, VrfTable: 700},
		1:  {Name: "eth1", Master: 10},
		2:  {Name: "eth2", Master: 11},
		3:  {Name: "eth3"},
		4:  {Name: "eth4", Master: 10},
	}
	circuits := map[uint32][]uint16{1: {5, 9}, 2: {0}, 3: {0}}
	cases := []struct {
		what    string
		table   uint32
		members map[string]string
		want    string // port, "" for none
		wantVRF string
	}{
		{"a port of a VRF device on the table", 600, nil, "eth1", "vrf-a"},
		{"a VRF device on another table", 700, nil, "eth2", "vrf-x"},
		{"no port on the table carries one", 800, nil, "", ""},
		{"a member to enslave", 800, map[string]string{"eth3": "vrf-b"}, "eth3", "vrf-b"},
		{"a member enslaved elsewhere now", 800, map[string]string{"eth2": "vrf-b"}, "eth2", "vrf-b"},
	}
	for _, c := range cases {
		got := l2CircuitOnTable(links, circuits, c.table, c.members)
		switch {
		case c.want == "" && got != nil:
			t.Errorf("%s: got %v, want none", c.what, got)
		case c.want != "" && (got == nil || got.Port != c.want || got.VRF != c.wantVRF):
			t.Errorf("%s: got %v, want %s of %s", c.what, got, c.want, c.wantVRF)
		}
	}
	if got := l2CircuitOnTable(links, circuits, 600, nil); got == nil || got.VLAN != 5 {
		t.Errorf("got %v, want the lowest VLAN of eth1's circuits", got)
	}
}
