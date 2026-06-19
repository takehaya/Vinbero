package main

import (
	"context"
	"fmt"
	"log"
	"math"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/apply"
	"github.com/takehaya/vinbero/pkg/bgp/export"
	"github.com/takehaya/vinbero/pkg/bgp/gobgp"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/fib"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/logger"
	"github.com/takehaya/vinbero/pkg/server"
	"github.com/takehaya/vinbero/pkg/vinbero"
	"github.com/takehaya/vinbero/pkg/vrf"
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
	// exporter / routeWatcher drive the auto-advertise path (VRF export).
	// They stay nil unless BGP is enabled with bgp.global.auto_advertise.
	var exporter *export.Exporter
	// evpnExporter drives EVPN auto-advertise: RT2 (local bridge MAC), RT3 (BUM
	// flood for a bound bridge domain), and RT4 (local Ethernet Segment). nil
	// unless BGP is enabled with bgp.global.evpn_auto_advertise.
	var evpnExporter *export.EVPNExporter
	if cliCtx.Bool("bgp-enabled") {
		// Load config-time VRF <-> route-target bindings before the BGP
		// session starts receiving. EVPN routes require a bridge-domain
		// binding to be installed; applying bindings here (rather than via
		// VrfBgpBind after boot) means a route that arrives early is not
		// dropped for lack of one. Only relevant when BGP is enabled.
		// Register config-declared locators before VRF bindings: the
		// auto-advertise exporter resolves each binding's default_locator at
		// EnableVRF time, and EnableVRF runs at startup before any RPC arrives.
		for _, lc := range cfg.BGP.Locators {
			loc, err := configToLocator(lc)
			if err != nil {
				return fmt.Errorf("bgp.locators %q: %w", lc.Name, err)
			}
			if err := locatorMgr.Add(loc); err != nil {
				return fmt.Errorf("bgp.locators %q: %w", lc.Name, err)
			}
		}
		for _, b := range cfg.BGP.VrfBindings {
			if b.BDID > math.MaxUint16 {
				return fmt.Errorf("bgp.vrf_bindings %q: bd_id %d out of range (max %d)", b.VRFName, b.BDID, math.MaxUint16)
			}
			binding, err := configToBinding(b)
			if err != nil {
				return fmt.Errorf("bgp.vrf_bindings %q: %w", b.VRFName, err)
			}
			if err := vrfBgpMgr.Bind(binding); err != nil {
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
		applier.SetMUPDefaultAllow(cfg.BGP.Global.MupDefaultAllow)
		// The config vrf_bindings were registered before the applier existed,
		// so program the uplink instance state (ifindex map) once here; later
		// runtime mutations re-drive it through the VrfBgpService hook.
		applier.ReconcileMUPUplinkInstances()
		// Auto-advertise (VRF export) is opt-in via bgp.global.auto_advertise.
		// The exporter shares the locator manager, VRF bindings, and BGP
		// advertiser with the rest of the daemon and owns its route watcher.
		if cfg.BGP.Global.AutoAdvertise {
			exporter = export.New(
				advertiser,
				vin.GetMapOperations(),
				locatorMgr,
				vrfBgpMgr,
				export.NetlinkVRFResolver{},
				cfg.BGP.Global.NextHop,
				export.UnderlayConfig{
					Redistribute: cfg.BGP.Global.UnderlayRedistribute,
					MaxPrefixes:  cfg.BGP.Global.UnderlayMaxPrefixes,
				},
				lg,
			)
		}
		// EVPN auto-advertise (RT2/RT3/RT4) is opt-in via
		// bgp.global.evpn_auto_advertise. It shares the locator manager, VRF
		// bindings, and BGP advertiser; the FDBWatcher feeds it local MACs and both
		// the bridge-device (BridgeCreate/Delete) and binding (VrfBgpBind/Unbind)
		// lifecycles enable/disable each bound bridge domain.
		if cfg.BGP.Global.EVPNAutoAdvertise {
			evpnExporter = export.NewEVPNExporter(
				bgpSession,
				vin.GetMapOperations(),
				locatorMgr,
				cfg.BGP.Global.NextHop,
				lg,
			)
		}
	}

	// exporter implements server.VrfExporter; avoid leaking a typed nil into
	// the interface so the VrfBgpServer's nil check holds when BGP is off.
	var vrfExp server.VrfExporter
	if exporter != nil {
		vrfExp = exporter
	}
	// The EVPN coordinator drives RT2/RT3 across both the bridge-device axis
	// (BridgeCreate/Delete) and the binding axis (VrfBgpBind/Unbind), resolving a
	// bridge domain to its bridge ifindex and replaying its FDB on enable. evpnES
	// is the RT4 (Ethernet Segment) hook. Both stay nil unless EVPN auto-advertise
	// is on, so the handlers' nil checks hold.
	var evpnCoord *server.EvpnCoordinator
	var evpnES server.EvpnEsHook
	if evpnExporter != nil {
		evpnCoord = server.NewEvpnCoordinator(
			evpnExporter,
			vin.GetResourceManager().BridgeIfindexByBDID,
			vin.GetFDBWatcher().DumpBridge,
			lg,
		)
		evpnES = evpnExporter
	}
	srv := server.NewServer(cfg, vin.GetMapOperations(), vin.GetResourceManager(), vin.GetFDBWatcher(), locatorMgr, vrfBgpMgr, advertiser, srPolicyAdvertiser, evpnAdvertiser, mupAdvertiser, applier, vrfExp, evpnCoord, evpnES, lg)

	// Load VRFs (ingress facet) from config and program them once at boot
	// (later runtime mutations go through VrfService). A failed interface
	// resolution here is fatal: a config-declared AC that does not exist is a
	// misconfiguration the operator should see at startup.
	if err := loadVRFs(cfg.VRFs, srv.VrfManager(), vin.GetMapOperations(), lg); err != nil {
		return fmt.Errorf("vrf: %w", err)
	}

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

		// Auto-advertise: the exporter enables each VRF binding with a
		// redistribute set and starts watching. Starting after Subscribe means
		// its ListExisting replay advertises boot-time prefixes through an
		// already-running advertiser; the deferred Stop withdraws them before
		// the session drops.
		if exporter != nil {
			if err := exporter.Start(ctx); err != nil {
				return fmt.Errorf("start auto-advertise: %w", err)
			}
			defer exporter.Stop()
		}
		// EVPN RT2 auto-advertise: feed the FDBWatcher's local MAC events to the
		// EVPN exporter. The sink is set here, after the FDBWatcher has already
		// started (StartFDBWatcher, above), so MACs present at that boot
		// ListExisting replay are NOT captured; a MAC learned after a BridgeCreate
		// enables its bridge domain is. BridgeCreate / VrfBgpBind replay a bridge's
		// existing FDB via the coordinator, so a bridge that predates the bind is
		// still picked up.
		if evpnExporter != nil {
			vin.GetFDBWatcher().SetMACSink(evpnExporter)
			// Teardown ordering: detach the sink BEFORE Close so an in-flight FDB
			// event cannot re-advertise a MAC after Close has withdrawn it. Close
			// also empties the BD table, so any OnLocalMAC that still races in is a
			// no-op (unknown BD); the detach makes that the common case rather than
			// relying on it. Close (withdraw RT2s/RT3 + release SIDs) runs before the
			// BGP session drops, like exporter.Stop above (LIFO defers).
			defer func() {
				vin.GetFDBWatcher().SetMACSink(nil)
				evpnExporter.Close()
			}()
		}
	}

	// Start the RPC server only after the exporter is watching, so a
	// VrfBgpBind that arrives drives an already-running auto-advertise path
	// rather than registering a table the watcher has not started yet. The
	// deferred shutdown runs first on teardown (LIFO), stopping new RPCs before
	// the exporter withdraws and the BGP session drops.
	if err := srv.StartAsync(); err != nil {
		return fmt.Errorf("start server: %w", err)
	}
	defer func() {
		if err := shutdown(srv, lg); err != nil {
			lg.Error("server shutdown error", zap.Error(err))
		}
	}()

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

// loadVRFs programs the VRFs' ingress facet from config at boot: it sets the
// global policy, registers each VRF's access circuits, and reconciles the
// data-plane maps. A config-declared interface that does not resolve is fatal
// (surfaced at startup, not silently dropped).
func loadVRFs(cfg config.VRFsConfig, mgr *vrf.Manager, prog vrf.Programmer, lg *zap.Logger) error {
	var action uint8
	switch cfg.DenyAction {
	case "", "drop":
		action = vrf.DenyActionDrop
	case "pass":
		action = vrf.DenyActionPass
	default:
		return fmt.Errorf("deny_action %q: want \"drop\" or \"pass\"", cfg.DenyAction)
	}
	mgr.SetPolicy(vrf.Policy{DefaultDeny: cfg.DefaultDeny, DenyAction: action})
	for _, v := range cfg.Entries {
		for _, ac := range v.ACs {
			if _, err := mgr.AddAC(v.Name, vrf.AC{Interface: ac.Interface, VLAN: ac.VLAN}); err != nil {
				return err
			}
		}
	}
	if cfg.DefaultDeny {
		lg.Warn("VRF default-deny enabled: unmapped ACs are dropped at XDP ingress; map every forwarding interface (underlay/control included) to a VRF or host-bound BGP/NDP is black-holed")
	}
	return mgr.Reconcile(vrf.ResolveByName, prog)
}

// configToBinding converts a config VRF binding into the runtime vrfbgp
// Binding. The caller is responsible for validating b.BDID's range first.
// vrfbgp.Binding.Normalize (called from Manager.Bind) expands the legacy
// ImportRTs / ExportRTs when Families is empty, so a vinbero.yml written
// before the rt-afi-safi schema keeps working unchanged.
func configToBinding(b config.VrfBindingConfig) (vrfbgp.Binding, error) {
	fams, err := configFamilies(b.Families)
	if err != nil {
		return vrfbgp.Binding{}, err
	}
	mupSrc, err := vrfbgp.ParseMUPGTP4SourcePrefix(b.MupGTP4SourcePrefix, b.RD)
	if err != nil {
		return vrfbgp.Binding{}, err
	}
	return vrfbgp.Binding{
		VRFName:             b.VRFName,
		RD:                  b.RD,
		ImportRTs:           b.ImportRTs,
		ExportRTs:           b.ExportRTs,
		Redistribute:        b.Redistribute,
		MaxPrefixes:         b.MaxPrefixes,
		DefaultLocator:      b.DefaultLocator,
		BDID:                uint16(b.BDID),
		Families:            fams,
		MupGTP4SourcePrefix: mupSrc,
	}, nil
}

// configFamilies converts the YAML families map into the runtime
// representation. Returns nil when no families are declared so
// vrfbgp.Binding.Normalize takes the legacy-expansion path.
//
// config.Validate normally rejects unknown direction strings at Load time,
// but if the two recognized-direction lists ever drift the daemon must
// surface the mismatch loudly rather than silently fall back to Direction(0)
// (which would match no RT).
func configFamilies(in map[string]config.FamilyConfig) (map[bgp.Family]vrfbgp.FamilyPolicy, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[bgp.Family]vrfbgp.FamilyPolicy, len(in))
	for famStr, fc := range in {
		rts := make([]vrfbgp.RouteTarget, 0, len(fc.RouteTargets))
		for _, rt := range fc.RouteTargets {
			dir, err := vrfbgp.ParseDirection(rt.Direction)
			if err != nil {
				return nil, fmt.Errorf("family %q rt %q: %w", famStr, rt.RT, err)
			}
			rts = append(rts, vrfbgp.RouteTarget{RT: rt.RT, Direction: dir})
		}
		out[bgp.Family(famStr)] = vrfbgp.FamilyPolicy{RouteTargets: rts}
	}
	return out, nil
}

// configToLocator converts a config locator declaration into a locator.Locator.
func configToLocator(lc config.LocatorConfig) (*locator.Locator, error) {
	prefix, err := netip.ParsePrefix(lc.Prefix)
	if err != nil {
		return nil, fmt.Errorf("invalid prefix %q: %w", lc.Prefix, err)
	}
	var behavior locator.Behavior
	switch lc.Behavior {
	case "", "classic":
		behavior = locator.BehaviorClassic
	case "usid":
		behavior = locator.BehaviorUSID
	default:
		return nil, fmt.Errorf("unknown behavior %q (want classic|usid)", lc.Behavior)
	}
	return &locator.Locator{
		Name:              lc.Name,
		Prefix:            prefix,
		BlockLen:          lc.BlockLen,
		NodeLen:           lc.NodeLen,
		FunctionLen:       lc.FunctionLen,
		ArgumentLen:       lc.ArgumentLen,
		Behavior:          behavior,
		FunctionAutoStart: lc.FunctionAutoStart,
		FunctionAutoEnd:   lc.FunctionAutoEnd,
	}, nil
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
