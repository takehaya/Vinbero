package config

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/mcuadros/go-defaults"
	"gopkg.in/yaml.v3"
)

// recognizedFamilyNames / recognizedDirections list the operator-facing
// strings accepted in vinbero.yml. They mirror pkg/bgp.Family and the
// pkg/vrfbgp Direction parser so config stays free of those imports; the
// runtime types remain the source of truth (vrfbgp.Binding.Normalize and
// vrfbgp.ParseDirection re-validate at the runtime boundary).
var (
	recognizedFamilyNames = []string{"vpnv4", "vpnv6", "evpn", "mup_ipv4", "mup_ipv6"}
	recognizedDirections  = []string{"", "import", "export", "both"}
)

// Validate rejects a typoed family or direction in vinbero.yml so it fails
// fast at Load time rather than silently dropping route targets. It also
// rejects mixing the legacy ImportRTs / ExportRTs lists with the new
// Families map -- runtime Normalize treats Families as the source of truth
// when both are set, so a YAML that carries both forms would silently
// ignore the legacy side. Forcing one or the other at Load surfaces the
// operator mistake instead of leaking through to a routing oddity.
func (b *VrfBindingConfig) Validate() error {
	// bd_id tombstone: the binding no longer carries a bridge domain (it
	// derives from the VRF's bridge facet). yaml decoding is lenient, so
	// without this an old config's bd_id would be dropped silently and its
	// EVPN routes would fail to install with no hint at the cause. The
	// message also covers the legacy-RT half of the migration: the old
	// "flat import_rts/export_rts + bd_id" form expanded to the evpn
	// family, which flat lists no longer do -- dropping only bd_id would
	// leave an L3VPN-only binding that silently imports no EVPN routes.
	if b.BDID != 0 {
		return fmt.Errorf("vrf binding %q: bd_id was removed; declare the bridge on vrfs.entries[].bridge (the bridge domain derives from the VRF's bridge facet) and declare the EVPN route targets under families.evpn -- the legacy import_rts/export_rts lists now expand to vpnv4+vpnv6 only", b.VRFName)
	}
	if len(b.Families) > 0 && (len(b.ImportRTs) > 0 || len(b.ExportRTs) > 0) {
		return fmt.Errorf("vrf binding %q: families and import_rts/export_rts cannot both be set (the families map is the source of truth at runtime, so the legacy lists would be silently ignored)", b.VRFName)
	}
	for fam, fc := range b.Families {
		if !slices.Contains(recognizedFamilyNames, fam) {
			return fmt.Errorf("vrf binding %q: unknown family %q (want one of: %s)", b.VRFName, fam, strings.Join(recognizedFamilyNames, ", "))
		}
		for _, rt := range fc.RouteTargets {
			if !slices.Contains(recognizedDirections, strings.ToLower(rt.Direction)) {
				return fmt.Errorf("vrf binding %q family %q rt %q: unknown direction %q (want import/export/both, or empty for both)", b.VRFName, fam, rt.RT, rt.Direction)
			}
		}
	}
	return nil
}

// Config is the top-level configuration
type Config struct {
	InternalConfig InternalConfig `yaml:"internal,omitempty"`
	Setting        SettingConfig  `yaml:"settings,omitempty"`
	BGP            BGPConfig      `yaml:"bgp,omitempty"`
	VRFs           VRFsConfig     `yaml:"vrfs,omitempty"`
	Prober         ProberConfig   `yaml:"prober,omitempty"`
	Original       string
	Configpath     string
}

// ProberConfig tunes the SRv6 liveness prober for ECMP path groups. The
// prober needs the BGP applier (--bgp-enabled) and a resolvable encap
// source; enabling it without either logs a warning and stays off.
type ProberConfig struct {
	Enable bool `yaml:"enable,omitempty"`
	// IntervalMs is the per-path probe interval in milliseconds (default
	// 100). A path fails after multiplier consecutive unanswered probes,
	// so detection takes roughly interval_ms * multiplier.
	IntervalMs uint32 `yaml:"interval_ms,omitempty" default:"100"`
	// Multiplier is the loss/recovery hysteresis (default 3).
	Multiplier uint32 `yaml:"multiplier,omitempty" default:"3"`
}

// VRFsConfig configures the VRF objects: each VRF's ingress access-circuit
// membership ({interface, VLAN}), its optional kernel-device facet, and the
// global default-deny policy. A VRF's vrf_id (0 = global/default VRF, the
// underlay) is assigned by the server. default_deny drops (or passes, per
// deny_action) a packet whose AC is unmapped instead of falling into the
// global VRF; enabling it without mapping the underlay/control interfaces to
// a VRF black-holes host-bound BGP/NDP, so map every interface that must
// forward.
type VRFsConfig struct {
	Entries     []VRFConfig `yaml:"entries,omitempty"`
	DefaultDeny bool        `yaml:"default_deny,omitempty"`
	DenyAction  string      `yaml:"deny_action,omitempty"` // "drop" (default) | "pass"
}

// VRFConfig is one VRF: its name, ingress access circuits, the optional
// kernel-device facet and the optional L2 bridge facet. table_id != 0 creates
// (or adopts) the Linux VRF device at boot; members and enable_l3mdev_rule
// require it. bridge creates (or adopts) the Linux bridge as the VRF's bridge
// domain. Removing an entry does NOT delete an already-created device or
// bridge (config is additive; deletion is an explicit `vbctl vrf delete` /
// `vbctl vrf bridge-detach`).
type VRFConfig struct {
	Name             string           `yaml:"name,omitempty"`
	ACs              []VRFACConfig    `yaml:"acs,omitempty"`
	TableID          uint32           `yaml:"table_id,omitempty"`
	Members          []string         `yaml:"members,omitempty"`
	EnableL3mdevRule bool             `yaml:"enable_l3mdev_rule,omitempty"`
	Bridge           *VRFBridgeConfig `yaml:"bridge,omitempty"`
}

// VRFBridgeConfig is a VRF's L2 bridge-domain facet: the Linux bridge device
// End.DT2/DT2M deliver into and the bd_id (1..65535) scoping its FDB. The
// facet is the bridge domain's single source: an EVPN route received under
// the same VRF's bgp.vrf_bindings entry installs into this bd.
type VRFBridgeConfig struct {
	Name    string   `yaml:"name,omitempty"`
	BdID    uint32   `yaml:"bd_id,omitempty"`
	Members []string `yaml:"members,omitempty"`
}

// VRFACConfig is one {interface, VLAN} access circuit of a VRF.
type VRFACConfig struct {
	Interface string `yaml:"interface,omitempty"`
	VLAN      uint16 `yaml:"vlan,omitempty"`
}

// BGPConfig is the optional in-process BGP speaker configuration. It is
// only consulted when vinberod is started with --bgp-enabled; an empty
// section leaves BGP off.
type BGPConfig struct {
	Global      BGPGlobalConfig    `yaml:"global,omitempty"`
	Peers       []BGPPeerConfig    `yaml:"peers,omitempty"`
	VrfBindings []VrfBindingConfig `yaml:"vrf_bindings,omitempty"`
	// Locators are SRv6 locator pools registered at startup, before the BGP
	// session settles. Auto-advertise needs each VRF binding's default_locator
	// to exist when the exporter enables it, and the receive applier needs the
	// source_locator present to materialize headend entries -- both run before
	// any RPC, so config is the only way to have them ready in time. Locators
	// can still also be created over the LocatorService RPC.
	Locators []LocatorConfig `yaml:"locators,omitempty"`
}

// LocatorConfig declares an SRv6 locator pool statically. It mirrors the
// LocatorService RPC fields so the BGP paths that need a locator at startup
// (auto-advertise, the receive applier's encap source) do not depend on an RPC
// arriving first.
type LocatorConfig struct {
	Name              string `yaml:"name,omitempty"`
	Prefix            string `yaml:"prefix,omitempty"`
	BlockLen          uint8  `yaml:"block_len,omitempty"`
	NodeLen           uint8  `yaml:"node_len,omitempty"`
	FunctionLen       uint8  `yaml:"function_len,omitempty"`
	ArgumentLen       uint8  `yaml:"argument_len,omitempty"`
	Behavior          string `yaml:"behavior,omitempty" default:"classic"`
	FunctionAutoStart uint32 `yaml:"function_auto_start,omitempty" default:"16"`
	FunctionAutoEnd   uint32 `yaml:"function_auto_end,omitempty" default:"65534"`
}

// VrfBindingConfig is a VRF <-> route-target binding applied at startup,
// before the BGP session begins receiving. Configuring it here (rather than
// via VrfBgpBind after boot) avoids a race where an EVPN route arrives before
// its binding exists and is dropped. An EVPN binding's bridge domain comes
// from the same VRF's bridge facet (vrfs.entries[].bridge), which boot seeds
// before the session starts.
type VrfBindingConfig struct {
	VRFName string `yaml:"vrf_name,omitempty"`
	// ImportRTs / ExportRTs are the legacy flat route-target form. New
	// configs should use Families instead; the legacy lists are kept so
	// existing vinbero.yml files keep working unchanged. Normalize expands
	// them into Families per the L3VPN / EVPN rule.
	ImportRTs []string `yaml:"import_rts,omitempty"`
	ExportRTs []string `yaml:"export_rts,omitempty"`
	// RD is the route distinguisher used when auto-advertising this VRF's
	// local prefixes. Required for auto advertise; receive-only bindings may
	// leave it empty.
	RD             string `yaml:"rd,omitempty"`
	DefaultLocator string `yaml:"default_locator,omitempty"`
	// BDID is a tombstone: the binding no longer carries a bridge domain
	// (it derives from the VRF's bridge facet). The field stays in the
	// schema so an old YAML that still sets bd_id fails loudly at boot
	// instead of the lenient yaml decode silently dropping the key.
	BDID uint32 `yaml:"bd_id,omitempty"`
	// Redistribute lists the route protocols whose VRF-local prefixes are
	// auto-advertised as VPNv4/VPNv6 when bgp.global.auto_advertise is on.
	// Recognized values are "connected" (RTPROT_KERNEL) and "static"
	// (RTPROT_STATIC). Routes Vinbero itself installed (RTPROT_BGP) are never
	// redistributed, so a received route is not re-advertised back out.
	Redistribute []string `yaml:"redistribute,omitempty"`
	// MaxPrefixes caps how many prefixes auto-advertise originates for this VRF
	// (0 = unlimited), bounding the blast radius of a VRF-route flood.
	MaxPrefixes uint32 `yaml:"max_prefixes,omitempty"`
	// Families is the rt-afi-safi binding map: an AF name -> its per-family
	// RT policy. Recognized AF keys are "vpnv4" / "vpnv6" / "evpn" /
	// "mup_ipv4" / "mup_ipv6". When empty, the legacy ImportRTs / ExportRTs
	// are expanded into the L3VPN families (vpnv4 + vpnv6); an EVPN policy
	// must be declared here explicitly.
	Families map[string]FamilyConfig `yaml:"families,omitempty"`
	// MupGTP4SourcePrefix enables RFC 9433 §6.6 source-address embedding for
	// MUP GTP4 downlink (T1ST) installs received under this binding's RD:
	// the downlink outer IPv6 source becomes this prefix with the session's
	// UPF IPv4 anchor (the same-RD T2ST endpoint) embedded right after the
	// prefix bits, so the peer GW's End.M.GTP4.E can extract it as the GTP-U
	// outer IPv4 source (its v4src_position equals this prefix length). The
	// prefix length must leave room for the 32-bit IPv4 address (<= 96);
	// "::/0" embeds at position 0. Empty keeps the plain locator-derived
	// encap source. Requires rd: a received MUP route resolves its binding
	// (and so this prefix) by RD. Validated at daemon startup via
	// vrfbgp.ParseMUPGTP4SourcePrefix.
	MupGTP4SourcePrefix string `yaml:"mup_gtp4_source_prefix,omitempty"`
}

// FamilyConfig is one address family's policy under a VRF binding.
type FamilyConfig struct {
	RouteTargets []RouteTargetConfig `yaml:"route_targets,omitempty"`
}

// RouteTargetConfig is one route-target entry under a FamilyConfig.
// Direction is one of "import" / "export" / "both"; empty is treated as
// "both" for ergonomics (matches RFC 4364 §4.3 convention).
type RouteTargetConfig struct {
	RT        string `yaml:"rt,omitempty"`
	Direction string `yaml:"direction,omitempty"`
}

// BGPGlobalConfig is the speaker's own BGP identity.
type BGPGlobalConfig struct {
	LocalASN uint32 `yaml:"local_asn,omitempty"`
	RouterID string `yaml:"router_id,omitempty"`
	// ListenPort defaults to -1: the in-process speaker does not bind
	// TCP/179, so it coexists with a host BGP daemon. Set a real port
	// only when vinberod owns BGP on the box.
	ListenPort int32 `yaml:"listen_port,omitempty" default:"-1"`
	// SourceLocator names the locator whose prefix supplies the SRv6
	// encap source address for BGP-driven headend entries (see plan
	// §6-5). Unused until Phase 1d; accepted now so config files are
	// forward-compatible.
	SourceLocator string `yaml:"source_locator,omitempty"`
	// AutoAdvertise turns on the VRF-export driven auto advertise path
	// (pkg/bgp/export): VRF-local prefixes matching a binding's redistribute
	// list are advertised as VPNv4/VPNv6 without an explicit BgpRouteService
	// call. Defaults to false so the operator-explicit path stays the only
	// behavior unless opted in.
	AutoAdvertise bool `yaml:"auto_advertise,omitempty" default:"false"`
	// EVPNAutoAdvertise turns on the EVPN RT2 auto advertise path
	// (pkg/bgp/export.EVPNExporter): a locally-learned bridge MAC in a bound
	// bridge domain is advertised as an EVPN RT2 (MAC/IP) without an explicit
	// BgpRouteService call. Shares NextHop with the L3VPN path. Defaults to false.
	EVPNAutoAdvertise bool `yaml:"evpn_auto_advertise,omitempty" default:"false"`
	// NextHop is the BGP next hop the auto-advertise path stamps on routes it
	// originates: this PE's own reachable IPv6 address (its loopback). Required
	// when auto_advertise is on. It must NOT be a locator base -- a locator
	// prefix's subnet-router anycast address is treated as local by a receiving
	// PE, which then fails to forward the SRv6-encapsulated traffic.
	NextHop string `yaml:"next_hop,omitempty"`
	// UnderlayRedistribute lists the route protocols ("connected"/"static")
	// whose main-table IPv6 prefixes are auto-advertised as IPv6 unicast
	// (underlay reachability). Empty = no underlay advertise.
	UnderlayRedistribute []string `yaml:"underlay_redistribute,omitempty"`
	// UnderlayMaxPrefixes caps how many underlay prefixes are advertised
	// (0 = unlimited).
	UnderlayMaxPrefixes uint32 `yaml:"underlay_max_prefixes,omitempty"`
	// SrPolicyMaxPolicies caps how many local (operator-defined) SR Policies the
	// SrPolicyService will hold, bounding both the BGP origination and the
	// sr_policy_map data-plane footprint a flood of CRUD RPCs can reach on the
	// unauthenticated surface (0 = unlimited).
	SrPolicyMaxPolicies uint32 `yaml:"sr_policy_max_policies,omitempty"`
	// MupMaxRoutes caps how many local MUP routes the MupService will originate,
	// bounding SAFI 85 amplification from the unauthenticated surface
	// (0 = unlimited).
	MupMaxRoutes uint32 `yaml:"mup_max_routes,omitempty"`
	// MupDefaultAllow forces every received MUP route through the historical
	// default-allow path, ignoring whether any binding has declared a mup_ipv*
	// family. It is the escape hatch for the asymmetric-expansion edge case
	// (rt-rd-unified-design §7.4): legacy bindings carry no mup_ipv* policy
	// because legacyToFamilies does not synthesize MUP entries, so adopting
	// the new mup_ipv* form on ONE binding would otherwise flip the global
	// filter on and drop every legacy binding's MUP traffic. Setting this
	// true keeps the legacy behavior while operators migrate every binding.
	// Defaults to false (per-binding mup filter when any binding opts in).
	MupDefaultAllow bool `yaml:"mup_default_allow,omitempty" default:"false"`
}

// BGPPeerConfig describes one BGP neighbor.
type BGPPeerConfig struct {
	Neighbor     string   `yaml:"neighbor,omitempty"`
	PeerASN      uint32   `yaml:"peer_asn,omitempty"`
	HoldTimeSec  uint32   `yaml:"hold_time_sec,omitempty" default:"90"`
	KeepaliveSec uint32   `yaml:"keepalive_sec,omitempty" default:"30"`
	Families     []string `yaml:"families,omitempty"` // vpnv4 / vpnv6 / ipv6_unicast / sr_policy_ipv6 / evpn / mup_ipv4
	// Passive stops this peer from dialing out; it only accepts the
	// neighbor's inbound connection. Set it on one end of each iBGP
	// full-mesh pair to avoid connection-collision flap.
	Passive bool `yaml:"passive,omitempty"`
	// ConnectRetrySec is the BGP ConnectRetry timer in seconds. Defaults to
	// 5 (gobgp's own default is 120) so a peer unreachable at startup
	// reconnects within seconds.
	ConnectRetrySec uint32 `yaml:"connect_retry_sec,omitempty" default:"5"`
	// AddPathsReceive negotiates ADD-PATH receive (RFC 7911) with this
	// neighbor, so it may send several paths for one prefix. Set it on a
	// route reflector session: a reflector sends only its best path per
	// prefix by default, which hides the other PEs' paths from ECMP. An
	// iBGP full mesh does not need it, since every PE sends its own path.
	AddPathsReceive bool `yaml:"add_paths_receive,omitempty"`
}

// BpfConstants returns the set of read-only constants rewritten into every
// BPF object vinbero loads (main data plane and plugin ELFs). The keys
// match `const volatile` names in the C sources.
func (c *Config) BpfConstants() map[string]any {
	v := uint8(0)
	if c.Setting.EnableStats {
		v = 1
	}
	return map[string]any{"enable_stats": v}
}

type SettingConfig struct {
	Entries         EntriesConfig       `yaml:"entries,omitempty"`
	EnableStats     bool                `yaml:"enable_stats,omitempty" default:"false"`
	StatePath       string              `yaml:"state_path,omitempty"`                      // Path for resource state file (default: /var/lib/vinbero/state.json)
	FdbAgingSeconds int                 `yaml:"fdb_aging_seconds,omitempty" default:"300"` // FDB entry aging timeout (0=disabled)
	PinMaps         PinMapsConfig       `yaml:"pin_maps,omitempty"`                        // Pin control-state BPF maps under /sys/fs/bpf so they survive a vinberod restart.
	Validate        ValidateConfig      `yaml:"validate,omitempty"`                        // Plugin validator policy knobs.
	CplanePlugins   CplanePluginsConfig `yaml:"cplane_plugins,omitempty"`                  // Where registered control-plane plugins are kept across a restart.
}

// CplanePluginsConfig governs whether registered control-plane plugins
// survive a daemon restart.
//
// It is on by default, unlike the map pinning above, because a plugin is
// not state an external controller can re-push: the plugin IS the
// controller, and the reason to load one is that the logic lives in the
// daemon. Meanwhile the state a plugin writes does outlive the process
// whenever maps are pinned, so a daemon that forgot its plugins would come
// back holding entries under an owner that no longer exists.
//
// Set enabled to false to keep the other model, where something outside
// re-registers every plugin after a restart.
type CplanePluginsConfig struct {
	Enabled bool   `yaml:"enabled,omitempty" default:"true"`
	Path    string `yaml:"path,omitempty" default:"/var/lib/vinbero/cplane-plugins"`
	// Quotas bound what any one plugin may hold. Zero fields take the
	// defaults, which are generous next to an ordinary plugin and small
	// next to what a runaway one costs.
	Quotas CplanePluginQuotas `yaml:"quotas,omitempty"`
	// Limits bound what any one plugin may cost to run. Zero fields take
	// the defaults.
	Limits CplanePluginLimits `yaml:"limits,omitempty"`
}

// CplanePluginQuotas is how much state one plugin may hold.
type CplanePluginQuotas struct {
	// MaxHeadendEntries counts v4 and v6 together. Negative means
	// unbounded, which is a deliberate escape hatch rather than a value
	// anyone should reach for.
	MaxHeadendEntries int `yaml:"max_headend_entries,omitempty"`
	// MaxAdvertisedRoutes is the quota that reaches other routers: a
	// plugin advertising without bound spends its peers' memory too.
	MaxAdvertisedRoutes int `yaml:"max_advertised_routes,omitempty"`
	// MaxLocalSIDs bounds what one plugin takes from a locator, which is
	// finite and shared with vinbero's own allocations.
	MaxLocalSIDs int `yaml:"max_local_sids,omitempty"`
}

// CplanePluginLimits is what one plugin may cost to run.
type CplanePluginLimits struct {
	// MaxModuleBytes caps the size of a module the daemon will load.
	MaxModuleBytes int `yaml:"max_module_bytes,omitempty"`
	// MaxMemoryPages caps the guest's linear memory, in 64 KiB pages.
	MaxMemoryPages uint32 `yaml:"max_memory_pages,omitempty"`
	// CallTimeoutMs bounds a single call into the guest. Exceeding it
	// costs the instance, not just the call: wazero cannot preempt, so the
	// only way to stop a running guest is to close the module.
	CallTimeoutMs int64 `yaml:"call_timeout_ms,omitempty"`
	// MaxBufferBytes caps one event batch or reply crossing the boundary.
	MaxBufferBytes int `yaml:"max_buffer_bytes,omitempty"`
}

// ValidateConfig knobs the plugin validator enforces on the server side.
// CLI `plugin validate` always runs in shift-left enforce regardless of
// these values — they only adjust the behaviour of `PluginRegister`.
type ValidateConfig struct {
	// RoEnforce selects how plugin writes into vinbero shared read-only
	// maps are handled at register time. "warn" (default during initial
	// rollout) logs the violation but still loads the plugin; "enforce"
	// hard-rejects the RPC. Empty string is treated as "warn".
	RoEnforce string `yaml:"ro_enforce,omitempty" default:"warn"`
}

// PinMapsConfig toggles pinning for the daemon's control-state BPF maps
// (sid_function_map, sid_aux_map, headend_*_map, fdb_map, bd_peer_map,
// bd_peer_reverse_map, dx2v_map). Ephemeral maps (stats, slot_stats,
// scratch, tailcall_ctx, PROG_ARRAY) are never pinned: their values
// either reset naturally at restart or hold program FDs that can't
// survive a new process.
type PinMapsConfig struct {
	Enabled bool   `yaml:"enabled,omitempty" default:"false"`
	Path    string `yaml:"path,omitempty" default:"/sys/fs/bpf/vinbero"`
}

// EntriesConfig holds the capacity settings for each entry type
type EntriesConfig struct {
	SidFunction EntryCapacityConfig `yaml:"sid_function,omitempty"`
	Headendv4   EntryCapacityConfig `yaml:"headendv4,omitempty"`
	Headendv6   EntryCapacityConfig `yaml:"headendv6,omitempty"`
	HeadendL2   EntryCapacityConfig `yaml:"headend_l2,omitempty"`
	Fdb         EntryCapacityConfig `yaml:"fdb,omitempty"`
	BdPeer      EntryCapacityConfig `yaml:"bd_peer,omitempty"`
	VlanTable   EntryCapacityConfig `yaml:"vlan_table,omitempty"`
	SrPolicy    EntryCapacityConfig `yaml:"sr_policy,omitempty"`
	// EcmpGroup sizes the ECMP group tables: ecmp_group_map / owner / live
	// get this capacity directly, ecmp_path_map gets capacity x 8 (one slot
	// per possible path).
	EcmpGroup EntryCapacityConfig `yaml:"ecmp_group,omitempty"`
	// ServiceIngress sizes the service-programming proxy tables: both the
	// IFACE-IN return map (service_ingress_map) and the End.AD dynamic
	// cache (ad_cache_map) are keyed by the proxy attachment circuit.
	ServiceIngress EntryCapacityConfig `yaml:"service_ingress,omitempty"`
	MaxSegments    int                 `yaml:"max_segments,omitempty" default:"10"`
}

// EntryCapacityConfig holds capacity setting for a single entry type
type EntryCapacityConfig struct {
	Capacity int `yaml:"capacity,omitempty" default:"1024"`
}

// LoadFile parses the given YAML file into a Config.
func LoadFile(filename string) (*Config, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	cfg, err := Load(string(content))
	if err != nil {
		return nil, err
	}
	cfg.Configpath = filename
	return cfg, nil
}

// Load parses the YAML input s into a Config.
func Load(s string) (*Config, error) {
	cfg := Config{}
	defaults.SetDefaults(&cfg)

	err := yaml.Unmarshal([]byte(s), &cfg)
	if err != nil {
		return nil, err
	}
	// bgp.peers[] elements do not exist during the pre-unmarshal
	// SetDefaults call, so their `default:` tags need a targeted second
	// pass. This is scoped to each peer element on purpose: a blanket
	// SetDefaults(&cfg) here would re-stamp every zero-valued field in
	// the whole config and clobber values a user set to zero
	// deliberately (e.g. settings.fdb_aging_seconds: 0 means "disabled").
	for i := range cfg.BGP.Peers {
		defaults.SetDefaults(&cfg.BGP.Peers[i])
	}
	for i := range cfg.BGP.Locators {
		defaults.SetDefaults(&cfg.BGP.Locators[i])
	}
	for i := range cfg.BGP.VrfBindings {
		if err := cfg.BGP.VrfBindings[i].Validate(); err != nil {
			return nil, err
		}
	}
	cfg.Original = s
	return &cfg, nil
}
func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}
