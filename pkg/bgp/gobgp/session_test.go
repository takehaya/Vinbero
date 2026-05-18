package gobgp

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// newTestSession returns a Session wired to a no-op logger. Every test
// uses ListenPort=-1 so the embedded BgpServer never binds TCP/179 --
// the suite runs without elevated privileges or a free port.
func newTestSession(t *testing.T) *Session {
	t.Helper()
	return NewSession(zap.NewNop())
}

func startTestSession(t *testing.T, s *Session) {
	t.Helper()
	cfg := bgp.GlobalConfig{LocalASN: 65000, RouterID: "10.255.0.1", ListenPort: -1}
	if err := s.Start(context.Background(), cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = s.Stop(context.Background()) })
}

func TestSession_StartStop(t *testing.T) {
	s := newTestSession(t)
	if err := s.Start(context.Background(), bgp.GlobalConfig{LocalASN: 65000, RouterID: "10.255.0.1", ListenPort: -1}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := s.Stop(context.Background()); err != nil {
		t.Errorf("Stop: %v", err)
	}
	// Stop is idempotent: a second call on a stopped session is a no-op.
	if err := s.Stop(context.Background()); err != nil {
		t.Errorf("second Stop: %v", err)
	}
}

func TestSession_DoubleStartRejected(t *testing.T) {
	s := newTestSession(t)
	startTestSession(t, s)
	err := s.Start(context.Background(), bgp.GlobalConfig{LocalASN: 65000, RouterID: "10.255.0.2", ListenPort: -1})
	if err == nil {
		t.Errorf("second Start should fail")
	}
}

func TestSession_StopWithoutStart(t *testing.T) {
	s := newTestSession(t)
	if err := s.Stop(context.Background()); err != nil {
		t.Errorf("Stop on unstarted session: %v", err)
	}
}

func TestSession_AddPeerBeforeStart(t *testing.T) {
	s := newTestSession(t)
	err := s.AddPeer(context.Background(), bgp.PeerConfig{Neighbor: "10.255.0.9", PeerASN: 65001})
	if err == nil {
		t.Errorf("AddPeer before Start should fail")
	}
}

func TestSession_AddListDeletePeer(t *testing.T) {
	s := newTestSession(t)
	startTestSession(t, s)

	peer := bgp.PeerConfig{
		Neighbor:     "10.255.0.2",
		PeerASN:      65001,
		HoldTimeSec:  90,
		KeepaliveSec: 30,
		Families:     []bgp.Family{bgp.FamilyVPNv4, bgp.FamilyIPv6Unicast},
	}
	if err := s.AddPeer(context.Background(), peer); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	peers, err := s.Peers(context.Background())
	if err != nil {
		t.Fatalf("Peers: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("Peers returned %d, want 1", len(peers))
	}
	if peers[0].Neighbor != peer.Neighbor || peers[0].PeerASN != peer.PeerASN {
		t.Errorf("Peers[0] = %+v, want neighbor=%s asn=%d", peers[0], peer.Neighbor, peer.PeerASN)
	}
	// No reachable neighbor in a unit test, so the FSM never leaves the
	// early states -- just assert the field is populated.
	if peers[0].SessionState == "" {
		t.Errorf("Peers[0].SessionState is empty")
	}

	if err := s.DeletePeer(context.Background(), peer.Neighbor); err != nil {
		t.Fatalf("DeletePeer: %v", err)
	}
	peers, err = s.Peers(context.Background())
	if err != nil {
		t.Fatalf("Peers after delete: %v", err)
	}
	if len(peers) != 0 {
		t.Errorf("Peers after delete returned %d, want 0", len(peers))
	}
}

func TestSession_PeersWhenEmpty(t *testing.T) {
	s := newTestSession(t)
	startTestSession(t, s)
	peers, err := s.Peers(context.Background())
	if err != nil {
		t.Fatalf("Peers: %v", err)
	}
	if len(peers) != 0 {
		t.Errorf("Peers on a peerless session = %d, want 0", len(peers))
	}
}

// TestSession_DeleteUnknownPeer documents the adapter's behavior when an
// unknown neighbor is deleted: the call must not panic. Whether GoBGP
// reports an error or treats it as a no-op is left to GoBGP; the test
// only pins crash-freedom so a future GoBGP bump cannot regress it
// silently.
func TestSession_DeleteUnknownPeer(t *testing.T) {
	s := newTestSession(t)
	startTestSession(t, s)
	_ = s.DeletePeer(context.Background(), "10.255.0.99")
}

func TestSession_AddPeerUnknownFamily(t *testing.T) {
	s := newTestSession(t)
	startTestSession(t, s)
	err := s.AddPeer(context.Background(), bgp.PeerConfig{
		Neighbor: "10.255.0.3",
		PeerASN:  65002,
		Families: []bgp.Family{bgp.Family("ipv4_flowspec")},
	})
	if err == nil {
		t.Errorf("AddPeer with unknown family should fail")
	}
}
