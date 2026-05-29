package main

import (
	"context"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/apply"
	"github.com/takehaya/vinbero/pkg/bgp/gobgp"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/fib"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/logger"
	"github.com/takehaya/vinbero/pkg/server"
	"github.com/takehaya/vinbero/pkg/vinbero"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
	"github.com/urfave/cli/v2"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

func main() {
	app := newApp()
	if err := app.Run(os.Args); err != nil {
		log.Fatalf("%+v", err)
	}
}

func newApp() *cli.App {
	return &cli.App{
		Name:    "vinberod",
		Version: fmt.Sprintf("%s, %s, %s, %s", version, commit, date, builtBy),
		Usage:   "High Performance SRv6 Function Subset",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Value:   "/etc/vinbero/vinbero.yaml",
				Usage:   "config file path",
			},
			&cli.BoolFlag{
				Name:  "bgp-enabled",
				Usage: "Enable BGP EVPN control plane",
			},
		},
		Action:                 run,
		EnableBashCompletion:   true,
		UseShortOptionHandling: true,
	}
}

func run(cliCtx *cli.Context) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := loadConfig(cliCtx.String("config"))
	if err != nil {
		return err
	}

	lg, cleanup, err := logger.NewLogger(cfg.InternalConfig.Logger)
	if err != nil {
		return fmt.Errorf("initialize logger: %w", err)
	}
	defer func() {
		if err := cleanup(context.Background()); err != nil {
			lg.Warn("failed to cleanup logger", zap.Error(err))
		}
	}()

	vin, err := vinbero.NewVinbero(cfg, lg)
	if err != nil {
		return fmt.Errorf("initialize vinbero: %w", err)
	}
	defer func() { _ = vin.Close() }()

	if err := vin.LoadXDPProgram(); err != nil {
		return fmt.Errorf("load XDP program: %w", err)
	}
	lg.Info("Vinbero XDP program loaded successfully")

	if err := vin.LoadTCProgram(); err != nil {
		return fmt.Errorf("load TC program: %w", err)
	}
	lg.Info("Vinbero TC BUM program loaded successfully")

	// Initialize resource manager (reconcile state before FDB watcher)
	if err := vin.InitResourceManager(); err != nil {
		return fmt.Errorf("init resource manager: %w", err)
	}

	// Start FDB watcher
	if err := vin.StartFDBWatcher(ctx); err != nil {
		return fmt.Errorf("start FDB watcher: %w", err)
	}

	// The locator.Manager and vrfbgp.Manager are shared between the RPC
	// server and the BGP route applier, so locators / VRF bindings
	// created over RPC are visible to the BGP receive path.
	locatorMgr := locator.NewManager()
	vrfBgpMgr := vrfbgp.NewManager()

	// The BGP session is constructed (unstarted) before the RPC server
	// so the server can hold it as a RouteAdvertiser for BgpRouteService.
	// bgpSession / advertiser stay nil when BGP is disabled -- a typed
	// nil must not leak into the interface, so advertiser is only
	// assigned inside the enabled branch.
	var bgpSession *gobgp.Session
	var advertiser bgp.RouteAdvertiser
	// srPolicyAdvertiser is the SR Policy advertise direction (SAFI 73),
	// satisfied by the same gobgp session. Like advertiser, it stays nil
	// when BGP is disabled so no typed nil leaks into the interface.
	var srPolicyAdvertiser bgp.SRPolicyController
	// evpnAdvertiser is the EVPN advertise direction (AFI 25 / SAFI 70),
	// satisfied by the same gobgp session; nil when BGP is disabled.
	var evpnAdvertiser bgp.EVPNController
	// mupAdvertiser is the BGP MUP advertise direction (SAFI 85), satisfied by
	// the same gobgp session; nil when BGP is disabled.
	var mupAdvertiser bgp.MUPController
	// applier holds the SR Policy table SrPolicyService also drives, so it is
	// shared via NewServer below: BGP-received and operator-defined policies
	// must share one table or collide on policy_id. nil when BGP is disabled
	// -> SrPolicyService RPCs return FailedPrecondition.
	var applier *apply.Applier
	if cliCtx.Bool("bgp-enabled") {
		// Load config-time VRF <-> route-target bindings before the BGP
		// session starts receiving. EVPN routes require a bridge-domain
		// binding to be installed; applying bindings here (rather than via
		// VrfBgpBind after boot) means a route that arrives early is not
		// dropped for lack of one. Only relevant when BGP is enabled.
		for _, b := range cfg.BGP.VrfBindings {
			if b.BDID > math.MaxUint16 {
				return fmt.Errorf("bgp.vrf_bindings %q: bd_id %d out of range (max %d)", b.VRFName, b.BDID, math.MaxUint16)
			}
			if err := vrfBgpMgr.Bind(vrfbgp.Binding{
				VRFName:        b.VRFName,
				ImportRTs:      b.ImportRTs,
				ExportRTs:      b.ExportRTs,
				DefaultLocator: b.DefaultLocator,
				BDID:           uint16(b.BDID),
			}); err != nil {
				return fmt.Errorf("bgp.vrf_bindings %q: %w", b.VRFName, err)
			}
		}

		bgpSession = gobgp.NewSession(lg)
		advertiser = bgpSession
		srPolicyAdvertiser = bgpSession
		evpnAdvertiser = bgpSession
		mupAdvertiser = bgpSession
		applier = apply.NewApplier(
			vin.GetMapOperations(),
			locatorMgr,
			vrfBgpMgr,
			fib.NewKernelInjector(),
			cfg.BGP.Global.SourceLocator,
			cfg.BGP.Global.LocalASN,
			lg,
		)
	}

	srv := server.NewServer(cfg, vin.GetMapOperations(), vin.GetResourceManager(), vin.GetFDBWatcher(), locatorMgr, vrfBgpMgr, advertiser, srPolicyAdvertiser, evpnAdvertiser, mupAdvertiser, applier, lg)
	if err := srv.StartAsync(); err != nil {
		return fmt.Errorf("start server: %w", err)
	}
	// Defer the RPC server shutdown right after StartAsync so an early
	// return below (e.g. BGP start failure) tears it down instead of
	// leaking it. The normal path falls through to the same defer.
	defer func() {
		if err := shutdown(srv, lg); err != nil {
			lg.Error("server shutdown error", zap.Error(err))
		}
	}()

	if bgpSession != nil {
		// Registered before the Start attempt so a partial failure
		// (global up, peers half-added) still gets torn down.
		defer func() {
			if err := bgpSession.Stop(context.Background()); err != nil {
				lg.Warn("BGP session stop failed", zap.Error(err))
			}
		}()
		if err := startBGPSession(ctx, bgpSession, cfg.BGP); err != nil {
			return fmt.Errorf("start BGP: %w", err)
		}
		// applier was created above (shared with SrPolicyService). It drives
		// the data plane from received BGP routes: VPNv4/v6 -> headend maps,
		// IPv6 unicast -> kernel FIB, SR Policy -> sr_policy_map.
		// Drop BGP-learned kernel FIB routes on shutdown so they do not
		// outlive the process. Runs after cancelSub (deferred below) so no
		// route can be re-installed while cleanup is in flight.
		defer func() {
			if err := applier.CleanupFIB(); err != nil {
				lg.Warn("BGP FIB cleanup failed", zap.Error(err))
			}
		}()
		cancelSub, err := bgpSession.Subscribe("", applier.Apply)
		if err != nil {
			return fmt.Errorf("subscribe BGP routes: %w", err)
		}
		defer cancelSub()
	}

	lg.Info("Vinbero started successfully")

	// Wait for shutdown signal; cleanup runs via the deferred shutdown
	// (RPC server) and bgpSession.Stop above.
	<-ctx.Done()
	lg.Info("Received shutdown signal, cleaning up...")
	return nil
}

// startBGPSession brings up the in-process BGP speaker and registers
// every neighbor from the config. Peer FSMs run asynchronously; this
// function returns once they are configured, not once they reach
// ESTABLISHED.
func startBGPSession(ctx context.Context, session bgp.Session, cfg config.BGPConfig) error {
	if err := session.Start(ctx, bgp.GlobalConfig{
		LocalASN:   cfg.Global.LocalASN,
		RouterID:   cfg.Global.RouterID,
		ListenPort: cfg.Global.ListenPort,
	}); err != nil {
		return err
	}
	for _, p := range cfg.Peers {
		families := make([]bgp.Family, 0, len(p.Families))
		for _, f := range p.Families {
			fam, err := bgp.ParseFamily(f)
			if err != nil {
				return fmt.Errorf("peer %s: %w", p.Neighbor, err)
			}
			families = append(families, fam)
		}
		if err := session.AddPeer(ctx, bgp.PeerConfig{
			Neighbor:        p.Neighbor,
			PeerASN:         p.PeerASN,
			HoldTimeSec:     p.HoldTimeSec,
			KeepaliveSec:    p.KeepaliveSec,
			Families:        families,
			Passive:         p.Passive,
			ConnectRetrySec: p.ConnectRetrySec,
		}); err != nil {
			return err
		}
	}
	return nil
}

func loadConfig(path string) (*config.Config, error) {
	if !config.FileExists(path) {
		return nil, fmt.Errorf("config file not found: %s", path)
	}
	cfg, err := config.LoadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	return cfg, nil
}

func shutdown(srv *server.Server, lg *zap.Logger) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		lg.Error("Shutdown error", zap.Error(err))
		return err
	}
	lg.Info("Shutdown completed")
	return nil
}
