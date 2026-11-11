package server

import (
	"slices"
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// A freed index of a full peer range asks for a replay of the EVPN routes
// only, through the replayer's request (which does not block).
func TestBdPeerFreedReplayRequestsEVPN(t *testing.T) {
	var got [][]bgp.Family
	bdPeerFreedReplay(func(f []bgp.Family) { got = append(got, f) })()
	if len(got) != 1 || !slices.Equal(got[0], []bgp.Family{bgp.FamilyEVPN}) {
		t.Fatalf("requests = %v, want one EVPN replay", got)
	}
}
