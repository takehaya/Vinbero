package cplane

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	gp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	sdk "github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/gobgppath"
	"google.golang.org/protobuf/proto"
)

type inputGrant struct {
	families        map[string]bool
	rts             map[string]bool
	prefixes, peers []netip.Prefix
}
type inputContext struct {
	spec      *v1.CplaneInputContext
	grants    []inputGrant
	families  []string
	endpoints []netip.Prefix
	teids     []teidScope
}
type teidScope struct {
	value uint32
	bits  uint8
}
type inputPolicy struct {
	spec           *v1.CplaneInputPolicy
	contexts       []inputContext
	maxPaths       int
	maxBatchEvents int
}
type inputDelivery struct {
	policy *inputPolicy
	held   map[sdk.BGPPathKey]bool
}

func inputPrefix(raw string, peer bool) (netip.Prefix, error) {
	if peer && !strings.Contains(raw, "/") {
		a, e := netip.ParseAddr(raw)
		if e != nil {
			return netip.Prefix{}, e
		}
		raw = netip.PrefixFrom(a, a.BitLen()).String()
	}
	p, e := netip.ParsePrefix(raw)
	if e != nil || p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("invalid prefix %q", raw)
	}
	return p.Masked(), nil
}
func parseTEIDScope(raw string) (teidScope, error) {
	parts := strings.Split(raw, "/")
	if len(parts) != 2 {
		return teidScope{}, fmt.Errorf("TEID scope must be value/bits")
	}
	value, e := strconv.ParseUint(parts[0], 0, 32)
	if e != nil {
		return teidScope{}, e
	}
	bits, e := strconv.ParseUint(parts[1], 10, 8)
	if e != nil || bits > 32 {
		return teidScope{}, fmt.Errorf("invalid TEID prefix %q", raw)
	}
	mask := ^uint32(0) << (32 - bits)
	return teidScope{uint32(value) & mask, uint8(bits)}, nil
}
func rtFamily(f string) bool {
	return f == "vpnv4" || f == "vpnv6" || f == "evpn" || f == "mup_ipv4" || f == "mup_ipv6"
}
func parseInputPolicy(raw *v1.CplaneInputPolicy, families []bgp.Family) (*inputPolicy, error) {
	if raw == nil {
		return nil, nil
	}
	spec := proto.Clone(raw).(*v1.CplaneInputPolicy)
	if spec.Version != 1 || len(spec.Contexts) > 64 {
		return nil, fmt.Errorf("input: version 1 and at most 64 contexts required")
	}
	limit := int(spec.MaxPaths)
	if limit == 0 {
		limit = 4096
	}
	if limit > 65536 {
		return nil, fmt.Errorf("input: max_paths exceeds 65536")
	}
	if spec.MaxBatchEvents > 16 {
		return nil, fmt.Errorf("input: max_batch_events must be 0, 1, or 2..16")
	}
	batchLimit := max(1, int(spec.MaxBatchEvents))
	policy := &inputPolicy{spec: spec, maxPaths: limit, maxBatchEvents: batchLimit}
	names := map[string]bool{}
	for _, c := range spec.Contexts {
		if c == nil || c.Name == "" || len(c.Name) > 63 || names[c.Name] || len(c.Grants) == 0 || len(c.Grants) > 64 {
			return nil, fmt.Errorf("input: invalid/duplicate context or grant count")
		}
		names[c.Name] = true
		ctx := inputContext{spec: c}
		familySet := map[string]bool{}
		for _, g := range c.Grants {
			if g == nil || len(g.Families) == 0 || len(g.Families) > 8 || len(g.RouteTargets) > 128 || len(g.Peers) > 128 || len(g.Prefixes) > 128 {
				return nil, fmt.Errorf("input %q: invalid grant bounds", c.Name)
			}
			grant := inputGrant{families: map[string]bool{}, rts: map[string]bool{}}
			for _, f := range g.Families {
				parsed, e := bgp.ParseFamily(f)
				if e != nil {
					return nil, e
				}
				if len(families) > 0 {
					allowed := false
					for _, want := range families {
						allowed = allowed || want == parsed
					}
					if !allowed {
						return nil, fmt.Errorf("input %q: family %s outside subscription", c.Name, f)
					}
				}
				if rtFamily(f) && len(g.RouteTargets) == 0 {
					return nil, fmt.Errorf("input %q: RT-based family %s needs route targets", c.Name, f)
				}
				if !rtFamily(f) && (len(g.RouteTargets) > 0 || len(g.Prefixes) == 0 || len(g.Peers) == 0) {
					return nil, fmt.Errorf("input %q: %s needs explicit prefixes and peers without RTs", c.Name, f)
				}
				grant.families[f] = true
				familySet[f] = true
			}
			for _, raw := range g.RouteTargets {
				rt, e := gp.ParseRouteTarget(raw)
				if e != nil {
					return nil, e
				}
				data, e := rt.Serialize()
				if e != nil {
					return nil, e
				}
				grant.rts[string(data)] = true
			}
			for _, raw := range g.Prefixes {
				p, e := inputPrefix(raw, false)
				if e != nil {
					return nil, e
				}
				grant.prefixes = append(grant.prefixes, p)
			}
			for _, raw := range g.Peers {
				p, e := inputPrefix(raw, true)
				if e != nil {
					return nil, e
				}
				grant.peers = append(grant.peers, p)
			}
			ctx.grants = append(ctx.grants, grant)
		}
		for f := range familySet {
			ctx.families = append(ctx.families, f)
		}
		sort.Strings(ctx.families)
		for _, raw := range c.EndpointPrefixes {
			p, e := inputPrefix(raw, false)
			if e != nil {
				return nil, e
			}
			ctx.endpoints = append(ctx.endpoints, p)
		}
		for _, raw := range c.TeidPrefixes {
			p, e := parseTEIDScope(raw)
			if e != nil {
				return nil, e
			}
			ctx.teids = append(ctx.teids, p)
		}
		for _, t := range c.DelegateMupTypes {
			if t != 3 && t != 4 {
				return nil, fmt.Errorf("input %q: only MUP ST1/ST2 may be delegated", c.Name)
			}
		}
		if len(c.DelegateMupTypes) > 0 && !familySet["mup_ipv4"] && !familySet["mup_ipv6"] {
			return nil, fmt.Errorf("input %q: MUP delegation without MUP input", c.Name)
		}
		if c.DelegateEvpn && (c.BridgeDomain == 0 || c.BridgeDomain > 65535 || !familySet["evpn"]) {
			return nil, fmt.Errorf("input %q: EVPN delegation needs a bridge domain and EVPN grant", c.Name)
		}
		policy.contexts = append(policy.contexts, ctx)
	}
	return policy, nil
}
func (p *inputPolicy) configure(payload []byte) ([]byte, error) {
	if p == nil {
		return payload, nil
	}
	cfg := &v1.PluginInputConfig{Version: 1, Payload: payload, Codec: bgp.BGPPathCodec}
	for _, c := range p.contexts {
		cfg.Contexts = append(cfg.Contexts, &v1.PluginInputContext{Name: c.spec.Name, Families: c.families})
	}
	return proto.Marshal(cfg)
}
func inputSDKRoute(r *v1.PluginRoute) sdk.Route {
	out := sdk.Route{Family: r.Family, Withdraw: r.IsWithdraw, Peer: r.Peer, PathID: r.PathId, Contexts: r.Contexts}
	if p := r.BgpPath; p != nil {
		out.BGPPath = &sdk.BGPPath{Codec: p.Codec, AFI: uint16(p.Afi), SAFI: uint8(p.Safi), NLRI: p.Nlri, RouteKey: p.RouteKey, Attributes: p.Attributes, EncodingError: p.EncodingError}
	}
	return out
}
func nativePrefix(n gp.NLRI) (netip.Prefix, bool) {
	switch r := n.(type) {
	case *gp.IPAddrPrefix:
		return r.Prefix, r.Prefix.IsValid()
	case *gp.LabeledVPNIPAddrPrefix:
		return r.Prefix, r.Prefix.IsValid()
	case *gp.EVPNNLRI:
		if p, ok := r.RouteTypeData.(*gp.EVPNIPPrefixRoute); ok {
			return netip.PrefixFrom(p.IPPrefix, int(p.IPPrefixLength)).Masked(), true
		}
	case *gp.MUPNLRI:
		switch p := r.RouteTypeData.(type) {
		case *gp.MUPInterworkSegmentDiscoveryRoute:
			return p.Prefix, p.Prefix.IsValid()
		case *gp.MUPType1SessionTransformedRoute:
			return p.Prefix, p.Prefix.IsValid()
		case *gp.MUPDirectSegmentDiscoveryRoute:
			return netip.PrefixFrom(p.Address, p.Address.BitLen()), true
		case *gp.MUPType2SessionTransformedRoute:
			return netip.PrefixFrom(p.EndpointAddress, p.EndpointAddress.BitLen()), true
		}
	}
	return netip.Prefix{}, false
}
func (c *inputContext) matches(family string, peer netip.Addr, path *gobgppath.Path) bool {
	rts := map[string]bool{}
	for _, attr := range path.Attributes {
		if a, ok := attr.(*gp.PathAttributeExtendedCommunities); ok {
			for _, ec := range a.Value {
				_, sub := ec.GetTypes()
				if sub == gp.EC_SUBTYPE_ROUTE_TARGET {
					if raw, e := ec.Serialize(); e == nil {
						rts[string(raw)] = true
					}
				}
			}
		}
	}
	for _, g := range c.grants {
		if !g.families[family] {
			continue
		}
		peerOK := len(g.peers) == 0
		for _, p := range g.peers {
			peerOK = peerOK || p.Contains(peer)
		}
		if !peerOK {
			continue
		}
		rtOK := len(g.rts) == 0
		for rt := range g.rts {
			rtOK = rtOK || rts[rt]
		}
		if !rtOK {
			continue
		}
		prefixOK := len(g.prefixes) == 0
		if n, ok := nativePrefix(path.NLRI); ok {
			for _, p := range g.prefixes {
				prefixOK = prefixOK || prefixWithin(p, n)
			}
		}
		if !prefixOK {
			continue
		}
		return true
	}
	return false
}
func (p *inputPolicy) memberships(r *v1.PluginRoute) ([]string, error) {
	path, err := gobgppath.Decode(inputSDKRoute(r))
	if err != nil {
		return nil, err
	}
	peer, e := netip.ParseAddr(r.Peer)
	if e != nil {
		return nil, e
	}
	var names []string
	for i := range p.contexts {
		c := &p.contexts[i]
		if c.matches(r.Family, peer, path) {
			names = append(names, c.spec.Name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// prepare executes on the delivery worker, after snapshot/live ordering.
func (d *inputDelivery) prepare(batch *v1.PluginEventBatch) (*v1.PluginEventBatch, error) {
	if d == nil || d.policy == nil {
		return batch, nil
	}
	out := &v1.PluginEventBatch{}
	for _, ev := range batch.Events {
		if ev.Kind == v1.PluginEventKind_PLUGIN_EVENT_KIND_START_OF_REPLAY && ev.ReplaySource == ReplaySourceBGP {
			d.held = map[sdk.BGPPathKey]bool{}
		}
		if ev.Kind != v1.PluginEventKind_PLUGIN_EVENT_KIND_ROUTE {
			out.Events = append(out.Events, ev)
			continue
		}
		r := ev.Route
		if r == nil {
			return nil, fmt.Errorf("input: missing route")
		}
		key, ok := inputSDKRoute(r).BGPKey()
		if !ok {
			return nil, fmt.Errorf("input: missing canonical path identity")
		}
		previous := d.held[key]
		var contexts []string
		if !r.IsWithdraw {
			var err error
			contexts, err = d.policy.memberships(r)
			if err != nil && r.BgpPath.EncodingError == "" {
				return nil, err
			}
		}
		if len(contexts) > 0 {
			if !previous && len(d.held) >= d.policy.maxPaths {
				return nil, fmt.Errorf("input: max_paths exceeded")
			}
			if d.held == nil {
				d.held = map[sdk.BGPPathKey]bool{}
			}
			d.held[key] = true
			copied := proto.Clone(ev).(*v1.PluginEvent)
			copied.Route.Contexts = contexts
			out.Events = append(out.Events, copied)
		} else if previous {
			delete(d.held, key)
			out.Events = append(out.Events, &v1.PluginEvent{Kind: ev.Kind, Sequence: ev.Sequence, Route: &v1.PluginRoute{Family: r.Family, Peer: r.Peer, PathId: r.PathId, IsWithdraw: true, BgpPath: &v1.PluginBGPPath{Codec: r.BgpPath.Codec, Afi: r.BgpPath.Afi, Safi: r.BgpPath.Safi, RouteKey: append([]byte(nil), r.BgpPath.RouteKey...)}}})
		}
	}
	return out, nil
}

type delegationSource interface {
	SetDelegation(string, func(bgp.RouteEvent) bool)
}

func (p *inputPolicy) hasDelegation() bool {
	if p != nil {
		for _, c := range p.contexts {
			if len(c.spec.DelegateMupTypes) > 0 || c.spec.DelegateEvpn {
				return true
			}
		}
	}
	return false
}
func (p *inputPolicy) delegates(ev bgp.RouteEvent, target func(bgp.RouteEvent) (string, uint16, bool)) bool {
	if p == nil {
		return false
	}
	r := EncodeRouteEvent(ev)
	if r.IsWithdraw {
		return false
	}
	path, err := gobgppath.Decode(inputSDKRoute(r))
	if err != nil {
		return false
	}
	for i := range p.contexts {
		c := &p.contexts[i]
		if !c.matches(r.Family, ev.Source.Peer, path) {
			continue
		}
		if ev.EVPN != nil && c.spec.DelegateEvpn {
			name, bd, ok := target(ev)
			_ = name
			if ok && uint32(bd) == c.spec.BridgeDomain {
				return true
			}
		}
		if ev.MUP != nil {
			name, _, ok := target(ev)
			if !ok || name != c.spec.MupVrf {
				continue
			}
			for _, t := range c.spec.DelegateMupTypes {
				if t == uint32(ev.MUP.Type) {
					return true
				}
			}
		}
	}
	return false
}
func (m *Manager) checkInputRegistration(reg Registration, policy *inputPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old := m.plugins[reg.Name]; old != nil && !proto.Equal(old.reg.Input, reg.Input) {
		return fmt.Errorf("input policy is immutable while registered; unregister and clean up before changing it")
	}
	m.unrestoredMu.Lock()
	defer m.unrestoredMu.Unlock()
	if old, ok := m.unrestored[reg.Name]; ok && !proto.Equal(old.input, reg.Input) {
		return fmt.Errorf("input policy held by unrestored owner; clean up before replacing")
	}
	if !policy.hasDelegation() {
		return nil
	}
	if m.resolveInputTarget == nil {
		return fmt.Errorf("delegation requires host input target resolver")
	}
	if _, ok := m.source.(delegationSource); !ok {
		return fmt.Errorf("source does not support explicit built-in delegation")
	}
	for name, u := range m.unrestored {
		if name == reg.Name {
			continue
		}
		for _, a := range policy.contexts {
			if u.input == nil {
				if m.services != nil {
					owners, err := m.services.inventoryOwners()
					if err != nil {
						return err
					}
					if owners[bpf.OwnerPluginBundle(name)] {
						return fmt.Errorf("unknown forwarding grant held by unrestored %s; clean up first", name)
					}
				}
				continue
			}
			for _, b := range u.input.Contexts {
				if (a.spec.DelegateEvpn && b.DelegateEvpn && a.spec.BridgeDomain == b.BridgeDomain) || (len(a.spec.DelegateMupTypes) > 0 && len(b.DelegateMupTypes) > 0 && a.spec.MupVrf == b.MupVrf) {
					return fmt.Errorf("delegation held by unrestored %s", name)
				}
			}
		}
	}
	for _, c := range policy.contexts {
		if len(c.spec.DelegateMupTypes) > 0 && !reg.Capabilities.Has(wasm.CapMUP) {
			return fmt.Errorf("MUP delegation requires mup capability")
		}
		if c.spec.DelegateEvpn && !reg.Capabilities.Has(wasm.CapEVPN) {
			return fmt.Errorf("EVPN delegation requires evpn capability")
		}
		if c.spec.MupVrf != "" && !reg.Scope.allowsVRF(c.spec.MupVrf) && len(c.spec.DelegateMupTypes) > 0 {
			return fmt.Errorf("MUP context VRF outside plugin scope")
		}
		for _, t := range c.spec.DelegateMupTypes {
			if t == 4 && (len(c.endpoints) == 0 || len(c.teids) == 0) {
				return fmt.Errorf("ST2 delegation needs explicit endpoint and TEID scopes")
			}
		}
		for name, other := range m.plugins {
			if name == reg.Name || other.input == nil {
				continue
			}
			for _, held := range other.input.policy.contexts {
				if c.spec.DelegateEvpn && held.spec.DelegateEvpn && c.spec.BridgeDomain == held.spec.BridgeDomain {
					return fmt.Errorf("bridge domain is delegated to %s", name)
				}
				if len(c.spec.DelegateMupTypes) > 0 && len(held.spec.DelegateMupTypes) > 0 && c.spec.MupVrf == held.spec.MupVrf {
					return fmt.Errorf("MUP instance is delegated to %s", name)
				}
			}
		}
	}
	return nil
}

func (m *Manager) reserveInputDelegation(reg Registration) {
	policy, err := parseInputPolicy(reg.Input, reg.Families)
	if err != nil || !policy.hasDelegation() {
		return
	}
	if ds, ok := m.source.(delegationSource); ok {
		ds.SetDelegation(reg.Name, m.delegationMatcher(policy))
		if r, ok := m.source.(BuiltinRetractor); ok {
			r.RetractClaimedFromBuiltins()
		}
	}
}

func (m *Manager) delegationMatcher(p *inputPolicy) func(bgp.RouteEvent) bool {
	return func(ev bgp.RouteEvent) bool {
		if m.resolveInputTarget == nil {
			return false
		}
		return p.delegates(ev, m.resolveInputTarget)
	}
}
