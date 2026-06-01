package server

import (
	"context"
	"fmt"
	"net/http"

	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/takehaya/vinbero/api/vinbero/v1/vinberov1connect"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/apply"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/netlinkwatch"
	"github.com/takehaya/vinbero/pkg/netresource"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// Server represents the Connect RPC server
type Server struct {
	cfg          *config.Config
	mapOps       *bpf.MapOperations
	resMgr       *netresource.ResourceManager
	fdbWatcher   *netlinkwatch.FDBWatcher
	locatorMgr   *locator.Manager
	vrfBgpMgr    *vrfbgp.Manager
	advertiser   bgp.RouteAdvertiser
	srPolicyAdv  bgp.SRPolicyController
	evpnAdv      bgp.EVPNController
	mupAdv       bgp.MUPController
	srPolicyCtrl srPolicyController
	vrfExporter  VrfExporter                // runtime auto-advertise hook; nil when off
	evpnCoord    *EvpnCoordinator           // EVPN RT2/RT3 BD lifecycle (device + binding axes); nil when off
	evpnES       EvpnEsHook                 // EVPN RT4 auto-advertise ES hook; nil when off
	esReElectDF  func(esi [bpf.ESILen]byte) // applier DF re-election; nil when BGP is off
	logger       *zap.Logger
	mux          *http.ServeMux
	server       *http.Server
}

// NewServer creates a new Server instance. locatorMgr and vrfBgpMgr are
// shared with the BGP route applier so RPC-created locators / VRF
// bindings and the BGP receive path see the same state; pass fresh
// managers when BGP is disabled. advertiser is nil when BGP is
// disabled, in which case BgpRouteService RPCs fail with
// FailedPrecondition.
// srPolicyApplier is *apply.Applier when the in-process BGP speaker is
// enabled, or nil otherwise. Taking the concrete type (not the interface)
// keeps a typed-nil from leaking into srPolicyCtrl, so the FailedPrecondition
// guard in SrPolicyServer works.
func NewServer(cfg *config.Config, mapOps *bpf.MapOperations, resMgr *netresource.ResourceManager, fdbWatcher *netlinkwatch.FDBWatcher, locatorMgr *locator.Manager, vrfBgpMgr *vrfbgp.Manager, advertiser bgp.RouteAdvertiser, srPolicyAdv bgp.SRPolicyController, evpnAdv bgp.EVPNController, mupAdv bgp.MUPController, srPolicyApplier *apply.Applier, vrfExporter VrfExporter, evpnCoord *EvpnCoordinator, evpnES EvpnEsHook, logger *zap.Logger) *Server {
	s := &Server{
		cfg:         cfg,
		mapOps:      mapOps,
		resMgr:      resMgr,
		fdbWatcher:  fdbWatcher,
		locatorMgr:  locatorMgr,
		vrfBgpMgr:   vrfBgpMgr,
		advertiser:  advertiser,
		srPolicyAdv: srPolicyAdv,
		evpnAdv:     evpnAdv,
		mupAdv:      mupAdv,
		vrfExporter: vrfExporter,
		evpnCoord:   evpnCoord,
		evpnES:      evpnES,
		logger:      logger,
		mux:         http.NewServeMux(),
	}
	if srPolicyApplier != nil {
		s.srPolicyCtrl = srPolicyApplier
		s.esReElectDF = srPolicyApplier.ReelectDF
	}
	return s
}

// Setup registers all service handlers
func (s *Server) Setup() {
	// Plugin service is constructed first so SidFunctionServer can resolve
	// per-slot aux BTF types when callers use plugin_aux_json. The actual
	// handler registration happens further down with the other services.
	//
	// roEnforce gates the asm-level RO-write check. An invalid
	// config string falls back to warn-only so a typo in vinbero.yaml
	// can't accidentally lock out previously-working plugins; the parse
	// failure is surfaced via the audit log instead.
	roEnforce, err := bpf.ParseROEnforceMode(s.cfg.Setting.Validate.RoEnforce)
	if err != nil {
		s.logger.Warn("invalid settings.validate.ro_enforce; defaulting to warn",
			zap.String("value", s.cfg.Setting.Validate.RoEnforce),
			zap.Error(err),
		)
		roEnforce = bpf.ROEnforceWarn
	}
	s.logger.Info("plugin RO-write enforcement",
		zap.String("mode", roEnforce.String()),
	)
	pluginServer := NewPluginServer(s.mapOps, s.cfg.BpfConstants(), roEnforce, s.logger)

	// VrfBgp service (VRF <-> BGP route-target bindings).
	vrfBgpServer := NewVrfBgpServer(s.vrfBgpMgr, s.vrfExporter, s.evpnCoord)
	vrfBgpPath, vrfBgpHandler := vinberov1connect.NewVrfBgpServiceHandler(vrfBgpServer)
	s.mux.Handle(vrfBgpPath, vrfBgpHandler)
	s.logger.Info("Registered VrfBgpService", zap.String("path", vrfBgpPath))

	// BgpRoute service (operator-explicit BGP advertise / withdraw).
	bgpRouteServer := NewBgpRouteServer(s.advertiser, s.srPolicyAdv, s.evpnAdv, s.mupAdv)
	bgpRoutePath, bgpRouteHandler := vinberov1connect.NewBgpRouteServiceHandler(bgpRouteServer)
	s.mux.Handle(bgpRoutePath, bgpRouteHandler)
	s.logger.Info("Registered BgpRouteService", zap.String("path", bgpRoutePath))

	// SrPolicy service (color-based steering; local CRUD + read-only view
	// of BGP-learned policies). srPolicyCtrl is nil when BGP is disabled,
	// in which case the RPCs return FailedPrecondition. srPolicyAdv +
	// next_hop let a local policy with advertise=true originate into SAFI 73.
	srPolicyServer := NewSrPolicyServer(s.srPolicyCtrl, s.srPolicyAdv, s.cfg.BGP.Global.NextHop)
	srPolicyPath, srPolicyHandler := vinberov1connect.NewSrPolicyServiceHandler(srPolicyServer)
	s.mux.Handle(srPolicyPath, srPolicyHandler)
	s.logger.Info("Registered SrPolicyService", zap.String("path", srPolicyPath))

	// Mup service (local BGP MUP route origination, SAFI 85). s.mupAdv is nil
	// when BGP is disabled, in which case the RPCs return FailedPrecondition.
	mupServer := NewMupServer(s.mupAdv, s.cfg.BGP.Global.NextHop)
	mupPath, mupHandler := vinberov1connect.NewMupServiceHandler(mupServer)
	s.mux.Handle(mupPath, mupHandler)
	s.logger.Info("Registered MupService", zap.String("path", mupPath))

	// Locator service (SRv6 locator manager). Registered before
	// SidFunctionService so the latter can receive the manager and
	// honor locator_ref in SidFunctionCreate.
	locatorServer := NewLocatorServer(s.locatorMgr)
	path, handler := vinberov1connect.NewLocatorServiceHandler(locatorServer)
	s.mux.Handle(path, handler)
	s.logger.Info("Registered LocatorService", zap.String("path", path))

	// SidFunction service
	sidFunctionServer := NewSidFunctionServer(s.mapOps, pluginServer, s.locatorMgr)
	path, handler = vinberov1connect.NewSidFunctionServiceHandler(sidFunctionServer)
	s.mux.Handle(path, handler)
	s.logger.Info("Registered SidFunctionService", zap.String("path", path))

	// Headendv4 service
	headendv4Server := NewHeadendv4Server(s.mapOps)
	path, handler = vinberov1connect.NewHeadendv4ServiceHandler(headendv4Server)
	s.mux.Handle(path, handler)
	s.logger.Info("Registered Headendv4Service", zap.String("path", path))

	// Headendv6 service
	headendv6Server := NewHeadendv6Server(s.mapOps)
	path, handler = vinberov1connect.NewHeadendv6ServiceHandler(headendv6Server)
	s.mux.Handle(path, handler)
	s.logger.Info("Registered Headendv6Service", zap.String("path", path))

	// HeadendL2 service
	headendL2Server := NewHeadendL2Server(s.mapOps)
	path, handler = vinberov1connect.NewHeadendL2ServiceHandler(headendL2Server)
	s.mux.Handle(path, handler)
	s.logger.Info("Registered HeadendL2Service", zap.String("path", path))

	// BdPeer service (for P2MP BUM flooding)
	bdPeerServer := NewBdPeerServer(s.mapOps)
	path, handler = vinberov1connect.NewBdPeerServiceHandler(bdPeerServer)
	s.mux.Handle(path, handler)
	s.logger.Info("Registered BdPeerService", zap.String("path", path))

	// Ethernet Segment service (RFC 7432 ESI master table)
	esServer := NewEthernetSegmentServer(s.mapOps, s.esReElectDF, s.evpnES, s.logger)
	path, handler = vinberov1connect.NewEthernetSegmentServiceHandler(esServer)
	s.mux.Handle(path, handler)
	s.logger.Info("Registered EthernetSegmentService", zap.String("path", path))

	// NetworkResource service (VRF/Bridge management)
	netResourceServer := NewNetworkResourceServer(s.resMgr, s.fdbWatcher, s.mapOps, s.vrfBgpMgr, s.evpnCoord, s.logger)
	path, handler = vinberov1connect.NewNetworkResourceServiceHandler(netResourceServer)
	s.mux.Handle(path, handler)
	s.logger.Info("Registered NetworkResourceService", zap.String("path", path))

	// FDB service (list, create/delete static entries)
	fdbServer := NewFdbServer(s.mapOps)
	path, handler = vinberov1connect.NewFdbServiceHandler(fdbServer)
	s.mux.Handle(path, handler)
	s.logger.Info("Registered FdbService", zap.String("path", path))

	// VlanTable service (VLAN cross-connect for End.DX2V)
	vlanTableServer := NewVlanTableServer(s.mapOps)
	path, handler = vinberov1connect.NewVlanTableServiceHandler(vlanTableServer)
	s.mux.Handle(path, handler)
	s.logger.Info("Registered VlanTableService", zap.String("path", path))

	// Plugin service (dynamic BPF plugin registration). pluginServer was
	// created at the top of Setup() so SidFunctionServer could hold a
	// reference for plugin_aux_json encoding.
	path, handler = vinberov1connect.NewPluginServiceHandler(pluginServer)
	s.mux.Handle(path, handler)
	s.logger.Info("Registered PluginService", zap.String("path", path))

	// Stats service (read-only, for observability). Depends on pluginServer
	// for resolving per-slot stat labels to plugin program names.
	statsServer := NewStatsServer(s.mapOps, pluginServer)
	path, handler = vinberov1connect.NewStatsServiceHandler(statsServer)
	s.mux.Handle(path, handler)
	s.logger.Info("Registered StatsService", zap.String("path", path))

	// Health check endpoint
	s.mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
}

// Start starts the HTTP server
func (s *Server) Start() error {
	addr := s.cfg.InternalConfig.Server.BindAddress
	s.server = &http.Server{
		Addr: addr,
		// Use h2c to support HTTP/2 without TLS (required for gRPC)
		Handler: h2c.NewHandler(s.mux, &http2.Server{}),
	}

	s.logger.Info("Starting Connect RPC server", zap.String("address", addr))
	return s.server.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	s.logger.Info("Shutting down Connect RPC server")
	return s.server.Shutdown(ctx)
}

// ListenAndServe is a convenience method that sets up and starts the server
func (s *Server) ListenAndServe() error {
	s.Setup()
	return s.Start()
}

// Mux returns the underlying http.ServeMux for custom handler registration
func (s *Server) Mux() *http.ServeMux {
	return s.mux
}

// StartAsync starts the server in a goroutine and returns any startup errors via channel
func (s *Server) StartAsync() error {
	errCh := make(chan error, 1)
	go func() {
		s.Setup()
		if err := s.Start(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("server error: %w", err)
		}
		close(errCh)
	}()

	// Give the server a moment to start and check for immediate errors
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}
