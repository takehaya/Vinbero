package vinbero

import (
	"testing"

	"github.com/takehaya/vinbero/pkg/vrf"
)

// The guard looks at every port of every VRF device on the table, managed
// or not, at the ports of the device being adopted whatever its table, and
// at the members the create is to enslave; nothing else.
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
		name    string
		table   uint32
		members []string
		want    string // port, "" for none
		wantVRF string
	}{
		{"a port of another VRF device on the table", "vrf-b", 600, nil, "eth1", "vrf-a"},
		{"a VRF device on another table", "vrf-b", 700, nil, "eth2", "vrf-x"},
		{"no port on the table carries one", "vrf-b", 800, nil, "", ""},
		{"a member to enslave", "vrf-b", 800, []string{"eth3"}, "eth3", "vrf-b"},
		{"the adopted device's own port", "vrf-x", 800, nil, "eth2", "vrf-x"},
	}
	for _, c := range cases {
		got := l2CircuitOnTable(links, circuits, c.name, c.table, c.members)
		switch {
		case c.want == "" && got != nil:
			t.Errorf("%s: got %v, want none", c.what, got)
		case c.want != "" && (got == nil || got.Port != c.want || got.VRF != c.wantVRF):
			t.Errorf("%s: got %v, want %s of %s", c.what, got, c.want, c.wantVRF)
		}
	}
	if got := l2CircuitOnTable(links, circuits, "vrf-b", 600, nil); got == nil || got.VLAN != 5 {
		t.Errorf("got %v, want the lowest VLAN of eth1's circuits", got)
	}
}
