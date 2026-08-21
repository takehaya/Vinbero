package main

import (
	"context"
	"fmt"
	"log"
	"math"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/apply"
	"github.com/takehaya/vinbero/pkg/bgp/demux"
	"github.com/takehaya/vinbero/pkg/bgp/export"
	"github.com/takehaya/vinbero/pkg/bgp/gobgp"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/cplane"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"github.com/takehaya/vinbero/pkg/fib"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/logger"
	"github.com/takehaya/vinbero/pkg/netresource"
	"github.com/takehaya/vinbero/pkg/prober"
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
			binding, err := configToBinding(b)
			if err != nil {
				return fmt.Errorf("bgp.vrf_bindings %q: %w", b.VRFName, err)
			}
			if err := vrfBgpMgr.Bind(binding); err != nil {
				return fmt.Errorf("bgp.vrf_bindings %q: %w", b.VRFName, err)
			}
		}

		bgpSession = gobgp.NewSession(lg)
		// The operator's own advertisements, made over RPC, originate
		// under a producer name of their own. The SR Policy, EVPN and MUP
		// controllers stay on the bare session: each has a single writer
		// today, so there is nothing for a name to separate them from.
		advertiser = bgpSession.AsProducer(gobgp.ProducerOperator)
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
			// Under its own producer name. The exporter follows the
			// routing table and the operator's RPC is what an operator
			// asked for; sharing one name makes them one producer, and
			// gobgp keeps a single local path per NLRI, so whichever
			// spoke last would silently replace the other's route and
			// then withdraw it out from under them.
			exporter = export.New(
				bgpSession.AsProducer(gobgp.ProducerExport),
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
		// the bridge facet (VrfBridgeAttach/Detach) and binding (VrfBgpBind/Unbind)
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
	// The EVPN coordinator drives RT2/RT3 across both the bridge facet axis
	// (VrfBridgeAttach/Detach) and the binding axis (VrfBgpBind/Unbind), resolving a
	// bridge domain to its bridge ifindex and replaying its FDB on enable. evpnES
	// is the RT4 (Ethernet Segment) hook. Both stay nil unless EVPN auto-advertise
	// is on, so the handlers' nil checks hold.
	var evpnCoord *server.EvpnCoordinator
	var evpnES server.EvpnEsHook
	if evpnExporter != nil {
		evpnCoord = server.NewEvpnCoordinator(
			evpnExporter,
			// The coordinator resolves a binding's bridge domain through the
			// VRF object's bridge facet, by VRF name.
			func(vrfName string) (vrf.Bridge, bool) {
				v, ok := vrfBgpMgr.VRF().Get(vrfName)
				if !ok || v.Bridge == nil {
					return vrf.Bridge{}, false
				}
				return *v.Bridge, true
			},
			vin.GetFDBWatcher().DumpBridge,
			lg,
		)
		evpnES = evpnExporter
	}
	// evpnReplay rescues EVPN routes that arrived before their import surface
	// (binding + bridge facet) existed: VrfBridgeAttach / commitBinding fire
	// it after the surface widens, and the applier re-applies the loc-rib
	// snapshot idempotently. Independent of evpn_auto_advertise -- a
	// receive-only PE imports without advertising. Best-effort: before the
	// session starts ListRoutes returns ErrSessionNotStarted (boot loads
	// bindings and facets before the session, so there is nothing to rescue),
	// and any later failure self-heals on the next peer event.
	//
	// The snapshot goes through the demux's built-in filter rather than
	// straight to the lister: this replay feeds the built-in applier, so it
	// must withhold plugin-claimed routes exactly as live delivery does.
	// routeDemux is built further down, and the closure reads it when it
	// runs, by which time it is set.
	var routeDemux *demux.Demux
	var evpnReplay func()
	if bgpSession != nil {
		evpnReplay = func() {
			err := applier.ReplayEVPN(func(h bgp.RouteHandler) error {
				return bgpSession.ListRoutes(bgp.FamilyEVPN, routeDemux.BuiltinSnapshotHandler(h))
			})
			if err != nil {
				lg.Warn("EVPN loc-rib replay", zap.Error(err))
			}
		}
	}
	// SRv6 liveness prober: probes every ECMP group member over its actual
	// segment list and masks dead paths in ecmp_live_map ahead of BGP
	// convergence. Needs the BGP applier (it feeds the group memberships)
	// and a resolvable encap source for the probe packets.
	var liveProber *prober.Prober
	// Effective values, normalized once so New, the log line, and the
	// status RPC all report the same thing (New would otherwise correct a
	// zero internally while the RPC echoed the raw config).
	proberIntervalMs := cfg.Prober.IntervalMs
	if proberIntervalMs == 0 {
		proberIntervalMs = 100
	}
	proberMultiplier := cfg.Prober.Multiplier
	if proberMultiplier == 0 {
		proberMultiplier = 3
	}
	if cfg.Prober.Enable {
		if applier == nil {
			lg.Warn("prober.enable requires --bgp-enabled; prober stays off")
		} else if src, perr := proberSource(cfg, applier); perr != nil {
			lg.Warn("prober disabled: cannot resolve probe source", zap.Error(perr))
		} else {
			p, perr := prober.New(vin.GetMapOperations(), src, prober.Config{
				Interval:   time.Duration(proberIntervalMs) * time.Millisecond,
				Multiplier: int(proberMultiplier),
			}, lg)
			if perr != nil {
				lg.Warn("prober disabled", zap.Error(perr))
			} else {
				liveProber = p
				applier.SetProber(liveProber)
				liveProber.Start()
				defer liveProber.Stop()
				lg.Info("prober started",
					zap.Stringer("source", src),
					zap.Uint32("interval_ms", proberIntervalMs),
					zap.Uint32("multiplier", proberMultiplier))
			}
		}
	}

	srv := server.NewServer(cfg, vin.GetMapOperations(), vin.GetResourceManager(), vin.GetFDBWatcher(), locatorMgr, vrfBgpMgr, advertiser, srPolicyAdvertiser, evpnAdvertiser, mupAdvertiser, applier, vrfExp, evpnCoord, evpnES, evpnReplay, lg)
	if liveProber != nil {
		srv.SetProber(liveProber, proberIntervalMs, proberMultiplier)
	}

	// Seed the VRF objects with the kernel devices and bridges the resource
	// manager reconciled from its state file (InitResourceManager ran before
	// the manager existed), so a persisted facet is a full first-class VRF
	// from boot. Then load the config: kernel-device and bridge facets
	// (adopt-idempotent over the seed) and the ingress facet, programmed once
	// at boot (later runtime mutations go through VrfService). Failures are
	// fatal: a config-declared AC, device or bridge that cannot materialize is
	// a misconfiguration the operator should see at startup.
	if err := seedVrfDevices(vin.GetResourceManager(), srv.VrfManager()); err != nil {
		return fmt.Errorf("vrf: %w", err)
	}
	if err := seedVrfBridges(vin.GetResourceManager(), srv.VrfManager(), cfg.VRFs, lg); err != nil {
		return fmt.Errorf("vrf: %w", err)
	}
	if err := loadVRFs(cfg.VRFs, srv.VrfManager(), vin.GetMapOperations(), vin.GetResourceManager(), vin.GetResourceManager(), lg); err != nil {
		return fmt.Errorf("vrf: %w", err)
	}
	// StartFDBWatcher's registration loop ran before loadVRFs, so a bridge
	// first created by the config attach path is not watched yet; sweep every
	// bridge facet (RegisterBridge is a pure map op, double-registering the
	// state-seeded ones is harmless).
	for _, v := range srv.VrfManager().List() {
		if v.Bridge != nil {
			vin.GetFDBWatcher().RegisterBridge(int(v.Bridge.Ifindex), v.Bridge.BdID)
		}
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
		// One subscription per daemon, fanned out by the demux. The applier
		// is consumer zero; later consumers (plugins) register with the same
		// demux rather than opening their own watch. The demux drops
		// local-origin paths on both the replay and the live stream, so this
		// node's own advertisements never reach the applier.
		routeDemux = demux.New(bgpSession, bgpSession, lg)
		// Behaviors a plugin claims are withheld from the built-in applier,
		// which would otherwise read an unrecognized codepoint as an
		// ordinary service SID. Vinbero's own behaviors are not claimable.
		claimRegistry := demux.NewClaimRegistry(gobgp.BuiltinEndpointBehaviors())
		routeDemux.SetClaimRegistry(claimRegistry)
		if _, err := routeDemux.RegisterBuiltin("applier", nil, applier.Apply); err != nil {
			return fmt.Errorf("register BGP applier: %w", err)
		}

		// Plugins are kept across a restart unless the operator turned it
		// off. A daemon that forgot them would come back holding the
		// entries they wrote -- pinned maps outlive the process -- under
		// an owner nothing can reconcile any more.
		var cplaneStore *cplane.Store
		if cfg.Setting.CplanePlugins.Enabled {
			cplaneStore, err = cplane.NewStore(cfg.Setting.CplanePlugins.Path)
			if err != nil {
				return fmt.Errorf("open control-plane plugin store: %w", err)
			}
			// Their behaviors are claimed before the first route moves.
			// Starting the demux replays everything already in the rib, so
			// a route carrying a stored plugin's codepoint would otherwise
			// reach the built-in appliers first and be installed as an
			// ordinary service SID, under their owner, in the plugin's way.
			if err := cplane.ReserveStoredClaims(cplaneStore, claimRegistry, lg.Named("cplane")); err != nil {
				lg.Warn("reserving the behaviors of stored control-plane plugins", zap.Error(err))
			}
		}

		if err := routeDemux.Start(); err != nil {
			return fmt.Errorf("subscribe BGP routes: %w", err)
		}
		defer routeDemux.Stop()

		// Control-plane plugins. They are only built where BGP is running:
		// a plugin with no event source could declare state but never react
		// to anything, which is not a mode worth supporting quietly.
		//
		// The encap source is resolved when a plugin actually declares an
		// entry, not here: locators are registered over RPC after the
		// daemon starts, so an address captured now is usually the one
		// that did not exist yet, and an entry written with a zero source
		// blackholes without saying so.
		cplaneMgr, err := cplane.NewManager(cplane.ManagerConfig{
			Source:     routeDemux,
			Claims:     claimRegistry,
			Headend:    vin.GetMapOperations(),
			Advertiser: bgpSession,
			// Each plugin originates under its own name, so the session
			// can tell their routes apart -- from each other and from
			// vinbero's own. gobgp keeps one local path per NLRI, and
			// without distinct names the withdraw of whichever producer
			// declared it last would delete a route another one still
			// wants, leaving that producer sure it is advertising.
			AdvertiserFor: func(producer string) cplane.Advertiser {
				return bgpSession.AsProducer(producer)
			},
			Locators:      locatorMgr,
			SIDFunctions:  vin.GetMapOperations(),
			EndtVRFGrants: vin.GetMapOperations(),
			// A plugin-dispatched End.DT4/DT6/DT46 decaps into the VRF's
			// kernel device, so the grant records that device's ifindex. A
			// VRF with only ingress ACs and no L3 device cannot be a decap
			// target; resolving fails and the declaration is retried or
			// refused, the same as a locator that is not registered yet.
			ResolveVRF: func(vrfName string) (uint32, error) {
				v, ok := vrfBgpMgr.VRF().Get(vrfName)
				if !ok || v.Device == nil || v.Device.Ifindex == 0 {
					return 0, fmt.Errorf("vrf %q has no L3 device ifindex", vrfName)
				}
				return v.Device.Ifindex, nil
			},
			EncapSource: applier.EncapSourceAddr,
			Store:        cplaneStore,
			// What a plugin's scope is stated in terms of. Both are
			// consulted when a declaration is applied rather than now,
			// because an operator registers locators and VRF bindings
			// over RPC after the daemon is up.
			LocatorInfo: locatorMgr,
			VRFBindings: vrfBgpMgr,
			// What one plugin may hold and what it may cost to run, from
			// the operator's config. Without these the daemon ran on the
			// built-in defaults whatever the file said, and reported the
			// configured value back as though it were in force.
			Quotas: cplane.Quotas{
				MaxHeadendEntries:   cfg.Setting.CplanePlugins.Quotas.MaxHeadendEntries,
				MaxAdvertisedRoutes: cfg.Setting.CplanePlugins.Quotas.MaxAdvertisedRoutes,
				MaxLocalSIDs:        cfg.Setting.CplanePlugins.Quotas.MaxLocalSIDs,
			},
			DefaultLimits: wasm.Limits{
				MaxModuleBytes: cfg.Setting.CplanePlugins.Limits.MaxModuleBytes,
				MaxMemoryPages: cfg.Setting.CplanePlugins.Limits.MaxMemoryPages,
				CallTimeout: time.Duration(cfg.Setting.CplanePlugins.Limits.CallTimeoutMs) *
					time.Millisecond,
				MaxBufferBytes: cfg.Setting.CplanePlugins.Limits.MaxBufferBytes,
			},
			Logger: lg.Named("cplane"),
		})
		if err != nil {
			return fmt.Errorf("build control-plane plugin manager: %w", err)
		}
		// Plugins are stopped, not flushed, on shutdown: the daemon going
		// away is not the operator taking a plugin away, and its entries
		// should still be there when it comes back.
		defer cplaneMgr.Close(context.Background())
		srv.SetCplaneManager(cplaneMgr)

		// Bring back what a previous run was running. A plugin that fails
		// to restore is logged and skipped inside Restore: refusing to
		// finish starting because one plugin is broken would turn a plugin
		// problem into an outage.
		if err := cplaneMgr.Restore(ctx); err != nil {
			lg.Warn("restoring control-plane plugins", zap.Error(err))
		}

		// Auto-advertise: the exporter enables each VRF binding with a
		// redistribute set and starts watching. Starting after the demux means
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
		// ListExisting replay are NOT captured; a MAC learned after a
		// VrfBridgeAttach enables its bridge domain is. VrfBridgeAttach / VrfBgpBind
		// replay a bridge's existing FDB via the coordinator, so a bridge that
		// predates the bind is still picked up.
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
			// EVPN auto-advertise for boot-provisioned bridge domains: the runtime
			// paths (VrfBridgeAttach / commitBinding) never ran for facets that came
			// from the state file or the config, so enable them here. This must run
			// after startBGPSession (the RT3 push needs a started session -- it is
			// not retried on failure) and after SetMACSink above (the FDB replay
			// reaches the exporter only once the sink is wired). Gated on EVPN
			// export RTs like both runtime paths (an empty RT list would push
			// unimportable RT3); Enable no-ops when the VRF has no bridge facet.
			for _, b := range vrfBgpMgr.List() {
				if len(b.ExportRTsForFamily(bgp.FamilyEVPN)) > 0 {
					evpnCoord.Enable(b)
				}
			}
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
			AddPathsReceive: p.AddPathsReceive,
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
func loadVRFs(cfg config.VRFsConfig, mgr *vrf.Manager, prog vrf.Programmer, dev vrf.DeviceOps, br vrf.BridgeOps, lg *zap.Logger) error {
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
		// Kernel-device facet first: table_id != 0 creates (or adopts) the
		// Linux VRF device. members / enable_l3mdev_rule without a table are a
		// typo (they configure the device), so reject rather than ignore.
		if v.TableID != 0 {
			if _, err := mgr.CreateDevice(v.Name, vrf.Device{
				TableID:          v.TableID,
				Members:          v.Members,
				EnableL3mdevRule: v.EnableL3mdevRule,
			}, dev); err != nil {
				return err
			}
		} else if len(v.Members) > 0 || v.EnableL3mdevRule {
			return fmt.Errorf("vrf %q: members / enable_l3mdev_rule require table_id (they configure the kernel device)", v.Name)
		}
		// L2 bridge-domain facet: creates (or adopts, idempotent over the
		// state-file seed) the kernel bridge. The caller sweeps the facets
		// into the FDB watcher after loadVRFs returns.
		if v.Bridge != nil {
			if v.Bridge.BdID == 0 || v.Bridge.BdID > math.MaxUint16 {
				return fmt.Errorf("vrf %q: bridge bd_id %d out of range (1..%d)", v.Name, v.Bridge.BdID, math.MaxUint16)
			}
			if _, err := mgr.AttachBridge(v.Name, vrf.Bridge{
				Name:    v.Bridge.Name,
				BdID:    uint16(v.Bridge.BdID),
				Members: v.Bridge.Members,
			}, br); err != nil {
				return err
			}
		}
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

// seedVrfDevices mirrors the kernel VRF devices the resource manager holds in
// its persisted state into the VRF objects, attaching each as a device facet.
// It runs after NewServer (the vrf.Manager lives inside the vrf-bgp manager)
// and before loadVRFs, so a config entry for the same name adopts rather than
// recreates. A persisted VRF named "global" is a fatal misconfiguration: the
// reserved global VRF is the main table and can never carry a device.
func seedVrfDevices(resMgr *netresource.ResourceManager, mgr *vrf.Manager) error {
	for _, mv := range resMgr.ListVrfs() {
		if _, err := mgr.SetDevice(mv.Name, vrf.Device{
			TableID:          mv.TableID,
			Members:          mv.Members,
			EnableL3mdevRule: mv.EnableL3mdevRule,
			Ifindex:          mv.Ifindex,
		}); err != nil {
			return fmt.Errorf("seed vrf %q from state: %w (remove the entry from the netresource state file, settings.state_path, and restart)", mv.Name, err)
		}
	}
	return nil
}

// seedVrfBridges mirrors the persisted bridges into the VRF objects as L2
// facets. A record from before the facet existed carries no owning VRF; it
// seeds under the bridge's own name as a synthetic VRF (to move it under its
// real VRF, stop the daemon, set the record's "vrf" field in the state file,
// and restart — detaching instead would delete the kernel bridge). Records
// with bd_id 0 or a duplicated bd_id are skipped with a warning: the facet
// model requires a unique non-zero bd_id, and the pre-facet lookup failed
// closed on duplicates, so skipping every claimant preserves that.
func seedVrfBridges(resMgr *netresource.ResourceManager, mgr *vrf.Manager, cfgVRFs config.VRFsConfig, lg *zap.Logger) error {
	// A config entry that declares this bridge names its intended owner: use
	// it for legacy ownerless records so an upgrade with a persisted bridge
	// plus a new config bridge: block does not seed a synthetic VRF that the
	// config attach would then collide with (a boot crash loop).
	configOwner := make(map[string]string)
	for _, v := range cfgVRFs.Entries {
		if v.Bridge != nil {
			configOwner[v.Bridge.Name] = v.Name
		}
	}
	bridges := resMgr.ListBridges()
	counts := make(map[uint16]int, len(bridges))
	for _, mb := range bridges {
		counts[mb.BdID]++
	}
	for _, mb := range bridges {
		if mb.BdID == 0 {
			lg.Warn("skipping persisted bridge with bd_id 0 (not seedable as a VRF facet; fix the state file)",
				zap.String("bridge", mb.Name))
			continue
		}
		if counts[mb.BdID] > 1 {
			lg.Warn("skipping persisted bridges with a duplicated bd_id (fail closed; fix the state file)",
				zap.String("bridge", mb.Name), zap.Uint16("bd_id", mb.BdID))
			continue
		}
		owner := mb.VRF
		if owner == "" {
			owner = configOwner[mb.Name]
		}
		if owner == "" {
			owner = mb.Name
		}
		if _, err := mgr.SetBridge(owner, vrf.Bridge{
			Name:    mb.Name,
			BdID:    mb.BdID,
			Members: mb.Members,
			Ifindex: mb.Ifindex,
		}); err != nil {
			return fmt.Errorf("seed bridge %q from state: %w (fix the entry in the netresource state file, settings.state_path, and restart)", mb.Name, err)
		}
	}
	return nil
}

// configToBinding converts a config VRF binding into the runtime vrfbgp
// Binding. vrfbgp.Binding.Normalize (called from Manager.Bind) expands the
// legacy ImportRTs / ExportRTs into the L3VPN families when Families is
// empty, so a vinbero.yml written before the rt-afi-safi schema keeps
// working unchanged; an EVPN policy must be declared under families.
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

// proberSource picks the address probe packets originate from. Echo
// replies come back to it natively (no SRv6), so it must be an address the
// kernel actually owns and delivers locally. bgp.global.next_hop is
// exactly that -- the loopback the PE advertises as its BGP next hop --
// while the encap source (the locator base) is usually not assigned to any
// interface and would silently blackhole every reply, judging all paths
// down. The locator base remains the fallback for setups without next_hop.
func proberSource(cfg *config.Config, applier *apply.Applier) (netip.Addr, error) {
	var candidate netip.Addr
	if nh := cfg.BGP.Global.NextHop; nh != "" {
		addr, err := netip.ParseAddr(nh)
		if err != nil || !addr.Is6() || addr.Is4In6() {
			return netip.Addr{}, fmt.Errorf("bgp.global.next_hop %q is not a usable IPv6 address", nh)
		}
		candidate = addr
	} else {
		addr, err := applier.EncapSourceAddr()
		if err != nil {
			return netip.Addr{}, err
		}
		candidate = addr
	}
	// The candidate must actually be assigned to an interface: replies come
	// back as plain IPv6 addressed to it, and an unowned source (the
	// locator base often is) would silently blackhole every reply and take
	// every healthy path down. Better no prober than a lying one.
	owned, err := localAddrOwned(candidate)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("enumerate local addresses: %w", err)
	}
	if !owned {
		return netip.Addr{}, fmt.Errorf("probe source %s is not assigned to any interface; assign it (or set bgp.global.next_hop to an owned loopback)", candidate)
	}
	return candidate, nil
}

// localAddrOwned reports whether the kernel owns addr on some interface.
func localAddrOwned(addr netip.Addr) (bool, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false, err
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		got, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		if got.Unmap() == addr {
			return true, nil
		}
	}
	return false, nil
}
