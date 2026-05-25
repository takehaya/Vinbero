// Package gobgp is the GoBGP-backed implementation of the pkg/bgp
// interfaces. It embeds an in-process gobgp BgpServer; nothing here
// starts a gRPC listener, so the BGP speaker is driven purely through
// the Go API.
//
// Phase 1c implements bgp.Session (peer lifecycle) only. The route
// exchange interfaces (RouteAdvertiser / RouteSubscriber /
// SRPolicyController) land in Phase 1d / 1e.
package gobgp

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
	gobgpapi "github.com/osrg/gobgp/v4/api"
	gobgpsrv "github.com/osrg/gobgp/v4/pkg/server"
	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// Session is the GoBGP-backed bgp.Session. A zero Session is not
// usable; construct one with NewSession. Start / Stop are not safe for
// concurrent use -- the daemon drives them from a single goroutine.
//
// It also satisfies bgp.RouteAdvertiser; advertised tracks the gobgp
// path UUID for each advertised route so Withdraw can delete the exact
// path. advMu guards that map since advertise / withdraw can be driven
// from concurrent RPC handlers.
//
// srvMu guards the server handle itself: Start / Stop publish and clear
// it while RPC handlers read it, so the pointer must not be touched
// without the lock. Read it through bgpServer().
type Session struct {
	logger *zap.Logger

	srvMu  sync.RWMutex
	server *gobgpsrv.BgpServer

	advMu      sync.Mutex
	advertised map[bgp.RouteKey]uuid.UUID
}

// bgpServer returns the running BgpServer, or nil when the session is
// not started. The pointer is snapshotted under srvMu so a concurrent
// Stop cannot race the read.
func (s *Session) bgpServer() *gobgpsrv.BgpServer {
	s.srvMu.RLock()
	defer s.srvMu.RUnlock()
	return s.server
}

// compile-time assertions for the interfaces *Session satisfies.
var (
	_ bgp.Session         = (*Session)(nil)
	_ bgp.RouteAdvertiser = (*Session)(nil)
)

// NewSession returns an unstarted Session.
func NewSession(logger *zap.Logger) *Session {
	return &Session{
		logger:     logger.Named("bgp.gobgp"),
		advertised: make(map[bgp.RouteKey]uuid.UUID),
	}
}

// Start brings up the in-process BgpServer and runs the OPEN handshake
// for the configured global identity. Calling Start on an already-
// started Session is an error so a double-wire bug surfaces loudly.
func (s *Session) Start(ctx context.Context, cfg bgp.GlobalConfig) error {
	if s.server != nil {
		return bgp.ErrSessionAlreadyStarted
	}
	srv := gobgpsrv.NewBgpServer()
	// Serve() is the blocking API event loop; it must run in its own
	// goroutine for the duration of the session.
	go srv.Serve()
	req := &gobgpapi.StartBgpRequest{
		Global: &gobgpapi.Global{
			Asn:        cfg.LocalASN,
			RouterId:   cfg.RouterID,
			ListenPort: cfg.ListenPort,
		},
	}
	if err := srv.StartBgp(ctx, req); err != nil {
		srv.Stop()
		return fmt.Errorf("start bgp (asn=%d router_id=%s): %w", cfg.LocalASN, cfg.RouterID, err)
	}
	s.srvMu.Lock()
	s.server = srv
	s.srvMu.Unlock()
	s.logger.Info("BGP session started",
		zap.Uint32("local_asn", cfg.LocalASN),
		zap.String("router_id", cfg.RouterID),
		zap.Int32("listen_port", cfg.ListenPort),
	)
	return nil
}

// Stop tears the session down. It is safe to call on a Session that was
// never started (no-op) so callers can defer it unconditionally. Even
// when StopBgp errors, the Serve() goroutine is still reaped and the
// handle cleared so the Session does not wedge -- the StopBgp error is
// returned afterwards for the caller to log.
func (s *Session) Stop(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	s.srvMu.Lock()
	srv := s.server
	s.server = nil
	s.srvMu.Unlock()
	stopErr := srv.StopBgp(ctx, &gobgpapi.StopBgpRequest{})
	srv.Stop()
	s.logger.Info("BGP session stopped")
	if stopErr != nil {
		return fmt.Errorf("stop bgp: %w", stopErr)
	}
	return nil
}

// AddPeer configures a neighbor. The peer starts the FSM immediately;
// reaching ESTABLISHED is asynchronous and observed via Peers.
func (s *Session) AddPeer(ctx context.Context, p bgp.PeerConfig) error {
	srv := s.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	afiSafis, err := familiesToAfiSafis(p.Families)
	if err != nil {
		return fmt.Errorf("add peer %s: %w", p.Neighbor, err)
	}
	peer := &gobgpapi.Peer{
		Conf: &gobgpapi.PeerConf{
			NeighborAddress: p.Neighbor,
			PeerAsn:         p.PeerASN,
		},
		Timers: &gobgpapi.Timers{
			Config: &gobgpapi.TimersConfig{
				HoldTime:          uint64(p.HoldTimeSec),
				KeepaliveInterval: uint64(p.KeepaliveSec),
			},
		},
		AfiSafis: afiSafis,
	}
	if err := srv.AddPeer(ctx, &gobgpapi.AddPeerRequest{Peer: peer}); err != nil {
		return fmt.Errorf("add peer %s: %w", p.Neighbor, err)
	}
	s.logger.Info("BGP peer added", zap.String("neighbor", p.Neighbor), zap.Uint32("peer_asn", p.PeerASN))
	return nil
}

// DeletePeer removes a neighbor.
func (s *Session) DeletePeer(ctx context.Context, neighbor string) error {
	srv := s.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	if err := srv.DeletePeer(ctx, &gobgpapi.DeletePeerRequest{Address: neighbor}); err != nil {
		return fmt.Errorf("delete peer %s: %w", neighbor, err)
	}
	s.logger.Info("BGP peer deleted", zap.String("neighbor", neighbor))
	return nil
}

// Peers returns a snapshot of every configured neighbor's session state.
func (s *Session) Peers(ctx context.Context) ([]bgp.PeerState, error) {
	srv := s.bgpServer()
	if srv == nil {
		return nil, bgp.ErrSessionNotStarted
	}
	// Small initial cap: peer counts are typically single digits to low
	// dozens, so one allocation covers the common case.
	out := make([]bgp.PeerState, 0, 16)
	err := srv.ListPeer(ctx, &gobgpapi.ListPeerRequest{}, func(p *gobgpapi.Peer) {
		st := bgp.PeerState{}
		if c := p.GetConf(); c != nil {
			st.Neighbor = c.GetNeighborAddress()
			st.PeerASN = c.GetPeerAsn()
		}
		if ps := p.GetState(); ps != nil {
			st.SessionState = sessionStateString(ps.GetSessionState())
		}
		out = append(out, st)
	})
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}
	return out, nil
}

// familyToAPI maps a Vinbero Family to a gobgp AFI/SAFI pair.
func familyToAPI(f bgp.Family) (*gobgpapi.Family, error) {
	switch f {
	case bgp.FamilyVPNv4:
		return &gobgpapi.Family{Afi: gobgpapi.Family_AFI_IP, Safi: gobgpapi.Family_SAFI_MPLS_VPN}, nil
	case bgp.FamilyVPNv6:
		return &gobgpapi.Family{Afi: gobgpapi.Family_AFI_IP6, Safi: gobgpapi.Family_SAFI_MPLS_VPN}, nil
	case bgp.FamilyIPv6Unicast:
		return &gobgpapi.Family{Afi: gobgpapi.Family_AFI_IP6, Safi: gobgpapi.Family_SAFI_UNICAST}, nil
	case bgp.FamilySRPolicyIPv6:
		return &gobgpapi.Family{Afi: gobgpapi.Family_AFI_IP6, Safi: gobgpapi.Family_SAFI_SR_POLICY}, nil
	case bgp.FamilyEVPN:
		return &gobgpapi.Family{Afi: gobgpapi.Family_AFI_L2VPN, Safi: gobgpapi.Family_SAFI_EVPN}, nil
	default:
		return nil, fmt.Errorf("unknown BGP family %q", f)
	}
}

func familiesToAfiSafis(fs []bgp.Family) ([]*gobgpapi.AfiSafi, error) {
	out := make([]*gobgpapi.AfiSafi, 0, len(fs))
	for _, f := range fs {
		fam, err := familyToAPI(f)
		if err != nil {
			return nil, err
		}
		out = append(out, &gobgpapi.AfiSafi{
			Config: &gobgpapi.AfiSafiConfig{Family: fam, Enabled: true},
		})
	}
	return out, nil
}

// sessionStateString normalizes the gobgp enum (e.g.
// "SESSION_STATE_ESTABLISHED") to the lowercase form Vinbero surfaces
// ("established").
func sessionStateString(s gobgpapi.PeerState_SessionState) string {
	return strings.ToLower(strings.TrimPrefix(s.String(), "SESSION_STATE_"))
}
