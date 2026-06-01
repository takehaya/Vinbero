package netresource

import (
	"testing"

	"go.uber.org/zap"
)

// BridgeIfindexByBDID resolves a unique bd_id to its bridge ifindex, but fails
// closed for an absent bd_id, bd_id 0, and -- critically -- a duplicate bd_id
// (CreateBridge does not enforce uniqueness), so the EVPN binding axis never
// steers to an arbitrarily-chosen bridge.
func TestBridgeIfindexByBDID(t *testing.T) {
	m := &ResourceManager{
		logger: zap.NewNop(),
		state: &ManagedState{
			Bridges: []ManagedBridge{
				{Name: "br10", BdID: 10, Ifindex: 100},
				{Name: "br20", BdID: 20, Ifindex: 200},
				{Name: "br20-dup", BdID: 20, Ifindex: 201}, // duplicate bd_id 20
			},
		},
	}

	if ifindex, ok := m.BridgeIfindexByBDID(10); !ok || ifindex != 100 {
		t.Errorf("unique bd_id 10 should resolve to ifindex 100; got %d,%v", ifindex, ok)
	}
	if _, ok := m.BridgeIfindexByBDID(20); ok {
		t.Error("ambiguous bd_id 20 (two bridges) must fail closed, not pick a first match")
	}
	if _, ok := m.BridgeIfindexByBDID(99); ok {
		t.Error("absent bd_id must return ok=false")
	}
	if _, ok := m.BridgeIfindexByBDID(0); ok {
		t.Error("bd_id 0 (L3VPN-only) must return ok=false")
	}
}
