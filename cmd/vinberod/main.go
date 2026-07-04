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
	"github.com/takehaya/vinbero/pkg/netresource"
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
	if err := validateVrfBridgeBindings(cfg); err != nil {
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
			// The binding axis resolves a bd_id through the VRF objects'
			// bridge facets (unique by construction), not the raw state file.
			vrfBgpMgr.VRF().BridgeIfindexByBDID,
			vin.GetFDBWatcher().DumpBridge,
			lg,
		)
		evpnES = evpnExporter
	}
	srv := server.NewServer(cfg, vin.GetMapOperations(), vin.GetResourceManager(), vin.GetFDBWatcher(), locatorMgr, vrfBgpMgr, advertiser, srPolicyAdvertiser, evpnAdvertiser, mupAdvertiser, applier, vrfExp, evpnCoord, evpnES, lg)

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
	// The config binds ran BEFORE the facets were seeded (they must precede
	// the BGP session so early routes are not dropped), so commitBinding's
	// facet<->bd_id check never saw them; validateVrfBridgeBindings covered
	// config-vs-config only. Cross-check every binding against the now-seeded
	// facets so a config binding cannot silently diverge from a state-file
	// bridge.
	for _, b := range vrfBgpMgr.List() {
		if b.BDID == 0 {
			continue
		}
		if v, ok := vrfBgpMgr.VRF().Get(b.VRFName); ok && v.Bridge != nil && v.Bridge.BdID != b.BDID {
			return fmt.Errorf("vrf %q: binding bd_id %d mismatches the bridge facet %q (bd_id %d); fix the config or the state file", b.VRFName, b.BDID, v.Bridge.Name, v.Bridge.BdID)
		}
	}
	// EVPN auto-advertise for boot-provisioned bridge domains: the runtime
	// axes (VrfBridgeAttach / commitBinding) never ran for facets that came
	// from the state file or the config, so enable them here. Gated on EVPN
	// export RTs like both runtime axes (an empty RT list would push
	// unimportable RT3); EnableForBinding no-ops when no facet carries the bd.
	if evpnCoord != nil {
		for _, b := range vrfBgpMgr.List() {
			if b.BDID != 0 && len(b.ExportRTsForFamily(bgp.FamilyEVPN)) > 0 {
				evpnCoord.EnableForBinding(b)
			}
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

// validateVrfBridgeBindings cross-checks the config's two bd_id declarations
// for one VRF: vrfs.entries[].bridge.bd_id (the L2 facet) and
// bgp.vrf_bindings[].bd_id (the BGP facet). The runtime paths validate this
// in commitBinding / VrfBridgeAttach, but the config bind at boot goes
// straight to vrfbgp.Manager.Bind, so a config mismatch must fail here.
func validateVrfBridgeBindings(cfg *config.Config) error {
	bridgeBd := make(map[string]uint32)
	for _, v := range cfg.VRFs.Entries {
		if v.Bridge != nil {
			bridgeBd[v.Name] = v.Bridge.BdID
		}
	}
	for _, b := range cfg.BGP.VrfBindings {
		if b.BDID == 0 {
			continue
		}
		if bd, ok := bridgeBd[b.VRFName]; ok && bd != b.BDID {
			return fmt.Errorf("vrf %q: vrfs.entries bridge bd_id %d and bgp.vrf_bindings bd_id %d mismatch", b.VRFName, bd, b.BDID)
		}
	}
	return nil
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
