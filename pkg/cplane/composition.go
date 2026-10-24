package cplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"

	gp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	sdk "github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/gobgppath"
	"google.golang.org/protobuf/proto"
)

func compositionCount(m *v1.PluginApplyChunk) int {
	return len(m.ForwardingHeadends) + len(m.MupUplinks) + len(m.EvpnForwards) + len(m.BgpAdvertisements)
}
func (p *PluginOps) outputContext(name string) (*inputContext, error) {
	if p.policy != nil {
		for i := range p.policy.contexts {
			c := &p.policy.contexts[i]
			if c.spec.Name == name {
				return c, nil
			}
		}
	}
	return nil, fmt.Errorf("ungranted output context %q", name)
}
func contextFamily(c *inputContext, family string) bool {
	for _, f := range c.families {
		if f == family {
			return true
		}
	}
	return false
}
func outputAddress(raw string) (netip.Addr, error) {
	a, e := netip.ParseAddr(raw)
	if e != nil || !a.Is6() || a.Is4In6() || !a.IsGlobalUnicast() || a.Zone() != "" {
		return a, fmt.Errorf("usable IPv6 address required: %q", raw)
	}
	return a, nil
}
func outputEntry(segments []string, source string, mode uint8) (bpf.HeadendEntry, error) {
	var e bpf.HeadendEntry
	if len(segments) == 0 || len(segments) > bpf.MaxSegments {
		return e, fmt.Errorf("invalid segment count")
	}
	src, err := outputAddress(source)
	if err != nil {
		return e, err
	}
	e.SrcAddr = src.As16()
	e.Mode = mode
	e.NumSegments = uint8(len(segments))
	for i, raw := range segments {
		a, err := outputAddress(raw)
		if err != nil {
			return e, err
		}
		e.Segments[i] = a.As16()
	}
	e.DstAddr = e.Segments[0]
	return e, nil
}

type compositionDesired struct {
	v4, v6  []HeadendDesired
	uplinks []uplinkDesired
	peers   []peerDesired
	routes  []AdvertisedRoute
}

func (p *PluginOps) normalizeComposition(m *v1.PluginApplyChunk) (compositionDesired, error) {
	var out compositionDesired
	if m == nil || m.DesiredRevision == 0 {
		return out, fmt.Errorf("nonzero desired revision required")
	}
	if compositionCount(m) > p.maxEntries {
		return out, fmt.Errorf("composition entry limit exceeded")
	}
	for _, h := range m.ForwardingHeadends {
		if h == nil || h.Entry == nil || !p.caps.Has(wasm.CapHeadend) {
			return out, fmt.Errorf("headend capability and entry required")
		}
		if _, err := p.outputContext(h.Context); err != nil {
			return out, err
		}
		prefix, err := netip.ParsePrefix(h.Entry.TriggerPrefix)
		if err != nil {
			return out, err
		}
		af := AFv4
		if prefix.Addr().Is6() {
			af = AFv6
		}
		trigger, e, err := DecodeHeadendEntry(h.Entry, af, netip.Addr{})
		if err != nil {
			return out, err
		}
		if _, err = outputAddress(h.Entry.SrcAddr); err != nil {
			return out, err
		}
		for _, seg := range h.Entry.Segments {
			if _, err = outputAddress(seg); err != nil {
				return out, err
			}
		}
		if err = p.guard.checkHeadend(af, trigger, e.Mode); err != nil {
			return out, err
		}
		d := HeadendDesired{TriggerPrefix: trigger, Entry: e}
		if af == AFv4 {
			out.v4 = append(out.v4, d)
		} else {
			out.v6 = append(out.v6, d)
		}
	}
	for _, u := range m.MupUplinks {
		if u == nil || !p.caps.Has(wasm.CapMUP) || !p.caps.Has(wasm.CapHeadend) {
			return out, fmt.Errorf("MUP uplink requires mup and headend capabilities")
		}
		c, err := p.outputContext(u.Context)
		if err != nil {
			return out, err
		}
		if !containsUint32(c.spec.DelegateMupTypes, 4) {
			return out, fmt.Errorf("ST2 input was not delegated")
		}
		endpoint, err := netip.ParseAddr(u.Endpoint)
		if err != nil || !endpoint.Is4() || !endpoint.IsGlobalUnicast() {
			return out, fmt.Errorf("GTP4 endpoint required")
		}
		allowed := false
		for _, g := range c.endpoints {
			if g.Contains(endpoint) {
				allowed = true
			}
		}
		if !allowed {
			return out, fmt.Errorf("MUP endpoint outside grant")
		}
		if u.TeidBits > 32 {
			return out, fmt.Errorf("invalid TEID prefix length")
		}
		mask := ^uint32(0) << (32 - u.TeidBits)
		teid := u.Teid & mask
		allowed = false
		for _, g := range c.teids {
			gm := ^uint32(0) << (32 - g.bits)
			if uint32(g.bits) <= u.TeidBits && teid&gm == g.value {
				allowed = true
			}
		}
		if !allowed {
			return out, fmt.Errorf("TEID outside grant")
		}
		gate := netip.PrefixFrom(endpoint, 32).String()
		if err = p.guard.checkHeadend(AFv4, gate, uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_M_GTP4_D_TEID)); err != nil {
			return out, err
		}
		if p.resolveMUPInstance == nil {
			return out, fmt.Errorf("MUP instance resolver unavailable")
		}
		instance, err := p.resolveMUPInstance(c.spec.MupVrf)
		if err != nil {
			return out, err
		}
		e, err := outputEntry(u.Segments, u.SrcAddr, uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS))
		if err != nil {
			return out, err
		}
		e.ArgsOffset = bpf.MupArgsOffsetNone
		out.uplinks = append(out.uplinks, uplinkDesired{instance: instance, endpoint: endpoint.String(), teid: teid, bits: uint8(u.TeidBits), entry: e})
	}
	for _, v := range m.EvpnForwards {
		if v == nil || !p.caps.Has(wasm.CapEVPN) {
			return out, fmt.Errorf("EVPN capability required")
		}
		c, err := p.outputContext(v.Context)
		if err != nil {
			return out, err
		}
		if !c.spec.DelegateEvpn || c.spec.BridgeDomain == 0 || c.spec.BridgeDomain > 65535 {
			return out, fmt.Errorf("EVPN bridge domain not delegated")
		}
		e, err := outputEntry(v.Segments, v.SrcAddr, uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2))
		if err != nil {
			return out, err
		}
		e.BdId = uint16(c.spec.BridgeDomain)
		if !v.Flood {
			e.FloodExclude = 1
		}
		remote, err := outputAddress(v.RemoteSrc)
		if err != nil {
			return out, err
		}
		d := peerDesired{bd: e.BdId, entry: e, remote: remote.As16()}
		if v.Mac != "" {
			mac, err := net.ParseMAC(v.Mac)
			if err != nil || len(mac) != 6 || mac[0]&1 != 0 || bytes.Equal(mac, make([]byte, 6)) {
				return out, fmt.Errorf("unicast MAC required")
			}
			d.macs = []net.HardwareAddr{mac}
		} else if !v.Flood {
			return out, fmt.Errorf("EVPN output requires MAC or flood")
		}
		out.peers = append(out.peers, d)
	}
	// Validate conflicting desired keys before mutating any live state.
	keys := map[string]bpf.HeadendEntry{}
	for _, set := range [][]HeadendDesired{out.v4, out.v6} {
		for _, h := range set {
			if old, ok := keys[h.TriggerPrefix]; ok && old != *h.Entry {
				return out, fmt.Errorf("ambiguous headend trigger")
			}
			keys[h.TriggerPrefix] = *h.Entry
		}
	}
	us := map[string]bpf.HeadendEntry{}
	for _, u := range out.uplinks {
		if _, ok := keys[u.endpoint+"/32"]; ok {
			return out, fmt.Errorf("headend trigger conflicts with MUP gate")
		}
		if old, ok := us[u.key()]; ok && old != u.entry {
			return out, fmt.Errorf("ambiguous MUP key")
		}
		us[u.key()] = u.entry
	}
	macs := map[string]string{}
	reverse := map[string]string{}
	peers := map[string]peerDesired{}
	for _, v := range out.peers {
		if len(v.macs) > 0 {
			key := fmt.Sprintf("%d/%x", v.bd, v.remote)
			if old, ok := reverse[key]; ok && old != v.key() {
				return out, fmt.Errorf("ambiguous EVPN unicast reverse peer")
			}
			reverse[key] = v.key()
		}
		if old, ok := peers[v.key()]; ok && old.entry.SrcAddr != v.entry.SrcAddr {
			return out, fmt.Errorf("ambiguous EVPN source")
		}
		peers[v.key()] = v
		for _, mac := range v.macs {
			k := fmt.Sprintf("%d/%s", v.bd, mac)
			if old, ok := macs[k]; ok && old != v.key() {
				return out, fmt.Errorf("ambiguous EVPN MAC")
			}
			macs[k] = v.key()
		}
	}
	// Count owned forwarding keys; raw declarations have separate transaction bounds.
	if len(out.v4)+len(out.v6)+len(us)+len(peers)+len(macs) > p.quotas.MaxHeadendEntries && p.quotas.MaxHeadendEntries >= 0 {
		return out, fmt.Errorf("forwarding quota exceeded")
	}
	for _, a := range m.BgpAdvertisements {
		if a == nil || !p.caps.Has(wasm.CapAdvertise) || p.advertise == nil {
			return out, fmt.Errorf("advertise capability unavailable")
		}
		c, err := p.outputContext(a.Context)
		if err != nil {
			return out, err
		}
		if p.advertise.advertiserFor(p.owner) == nil {
			return out, fmt.Errorf("advertiser unavailable")
		}
		r, err := decodeRawAdvertisement(a)
		if err != nil {
			return out, err
		}
		if !contextFamily(c, string(r.Family)) {
			return out, fmt.Errorf("advertised family outside context")
		}
		r, err = p.guard.resolveAdvertised(r)
		if err != nil {
			return out, err
		}
		if err = p.sidIsOwned(r); err != nil {
			return out, err
		}
		r, err = normalizeAdvertised(r)
		if err != nil {
			return out, err
		}
		r, err = p.advertise.canonicalize(r)
		if err != nil {
			return out, err
		}
		out.routes = append(out.routes, r)
	}
	if len(out.routes) > p.quotas.MaxAdvertisedRoutes && p.quotas.MaxAdvertisedRoutes >= 0 {
		return out, fmt.Errorf("advertisement quota exceeded")
	}
	if err := p.guard.checkAdvertiseSet(out.routes); err != nil {
		return out, err
	}
	return out, nil
}

func compositionDigest(m *v1.PluginApplyChunk, d compositionDesired) (hash [32]byte, err error) {
	hashInput := proto.Clone(m).(*v1.PluginApplyChunk)
	hashInput.DesiredRevision = 0
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(hashInput)
	if err != nil {
		return hash, err
	}
	hasher := sha256.New()
	_, _ = hasher.Write(raw)
	for _, u := range d.uplinks {
		_, _ = fmt.Fprintf(hasher, "/instance=%d", u.instance)
	}
	derived, err := json.Marshal(d.routes)
	if err != nil {
		return hash, err
	}
	_, _ = hasher.Write(derived)
	copy(hash[:], hasher.Sum(nil))
	return hash, nil
}

// applyComposition orders dependents before their forwarding changes. Failure
// retains ownership and the latest desired set for a bounded retry.
func (p *PluginOps) applyComposition(txn *applyTxn) error {
	m := txn.composition
	d, err := p.normalizeComposition(m)
	if err != nil {
		return err
	}
	hash, err := compositionDigest(m, d)
	if err != nil {
		return err
	}
	if p.compositionValid && hash == p.compositionHash {
		return nil
	}
	p.compositionValid = false
	if p.advertise != nil {
		if err = p.advertise.WithdrawOwner(context.Background(), p.owner); err != nil {
			return err
		}
	}
	if p.services == nil && (len(d.uplinks) > 0 || len(d.peers) > 0) {
		return fmt.Errorf("service output unavailable")
	}
	if err = p.services.prune(p.owner, d.uplinks, d.peers); err != nil {
		return err
	}
	if _, err = p.headend.ApplySets(p.owner, d.v4, d.v6, p.quotas.MaxHeadendEntries); err != nil {
		return err
	}
	if p.services != nil {
		if err = p.services.apply(p.owner, d.uplinks, d.peers); err != nil {
			return err
		}
	}
	if len(d.routes) > 0 {
		if _, err = p.advertise.Apply(context.Background(), p.owner, d.routes, p.quotas.MaxAdvertisedRoutes); err != nil {
			return err
		}
	}
	p.compositionHash = hash
	p.compositionValid = true
	return nil
}

// decodeRawAdvertisement accepts the documented single-service SRv6 profile.
// Attributes that the host cannot reproduce are refused, never discarded.
func decodeRawAdvertisement(a *v1.PluginBgpAdvertisement) (AdvertisedRoute, error) {
	var r AdvertisedRoute
	r.VRF = a.Vrf
	w := a.Path
	if w == nil || w.Afi > 65535 || w.Safi > 255 {
		return r, fmt.Errorf("invalid advertised packet")
	}
	packet := &sdk.BGPPath{Codec: w.Codec, AFI: uint16(w.Afi), SAFI: uint8(w.Safi), NLRI: w.Nlri, Attributes: w.Attributes}
	path, err := gobgppath.DecodePacket(packet)
	if err != nil {
		return r, err
	}
	prefix, ok := nativePrefix(path.NLRI)
	if !ok {
		return r, fmt.Errorf("unsupported advertisement NLRI")
	}
	r.Prefix = prefix.Masked().String()
	switch n := path.NLRI.(type) {
	case *gp.LabeledVPNIPAddrPrefix:
		if w.Safi != 128 || (w.Afi != 1 && w.Afi != 2) {
			return r, fmt.Errorf("unsupported VPN family")
		}
		rd, err := n.RD.Serialize()
		if err != nil || !bytes.Equal(rd, make([]byte, 8)) || len(n.Labels.Labels) != 1 || n.Labels.Labels[0] != 0 {
			return r, fmt.Errorf("VPN output requires zero RD and label placeholders")
		}
		if prefix.Addr().Is4() {
			r.Family = bgp.FamilyVPNv4
		} else {
			r.Family = bgp.FamilyVPNv6
		}
	case *gp.IPAddrPrefix:
		if w.Afi != 2 || w.Safi != 1 {
			return r, fmt.Errorf("unsupported unicast family")
		}
		if !prefix.Addr().Is6() {
			return r, fmt.Errorf("only IPv6 unicast output supported")
		}
		r.Family = bgp.FamilyIPv6Unicast
	default:
		return r, fmt.Errorf("unsupported advertisement family")
	}
	seen := map[gp.BGPAttrType]bool{}
	for i, attr := range path.Attributes {
		if seen[attr.GetType()] {
			return r, fmt.Errorf("duplicate output attribute")
		}
		seen[attr.GetType()] = true
		encoded, err := attr.Serialize()
		if err != nil || !bytes.Equal(encoded, w.Attributes[i]) {
			return r, fmt.Errorf("non-reproducible output attribute")
		}
		switch x := attr.(type) {
		case *gp.PathAttributeOrigin:
			if byte(x.Flags)&^byte(0x10) != 0x40 {
				return r, fmt.Errorf("unsupported ORIGIN flags")
			}
			if x.Value != 0 {
				return r, fmt.Errorf("only IGP origin supported")
			}
		case *gp.PathAttributeMpReachNLRI:
			if byte(x.Flags)&^byte(0x10) != 0x80 {
				return r, fmt.Errorf("unsupported MP_REACH flags")
			}
			if len(x.Value) != 1 || x.Value[0].ID != 0 || x.LinkLocalNexthop.IsValid() || x.AFI != uint16(w.Afi) || x.SAFI != uint8(w.Safi) {
				return r, fmt.Errorf("single matching MP_REACH required")
			}
			nlri, err := x.Value[0].NLRI.Serialize()
			if err != nil || !bytes.Equal(nlri, w.Nlri) {
				return r, fmt.Errorf("MP_REACH NLRI mismatch")
			}
			r.NextHop = x.Nexthop.String()
		case *gp.PathAttributePrefixSID:
			if byte(x.Flags)&^byte(0x10) != 0xc0 {
				return r, fmt.Errorf("unsupported Prefix-SID flags")
			}
			if r.Family == bgp.FamilyIPv6Unicast || len(x.TLVs) != 1 {
				return r, fmt.Errorf("unsupported Prefix-SID shape")
			}
			svc, ok := x.TLVs[0].(*gp.SRv6ServiceTLV)
			if !ok || svc.Type != gp.TLVTypeSRv6L3Service || len(svc.SubTLVs) != 1 {
				return r, fmt.Errorf("single L3 service required")
			}
			info, ok := svc.SubTLVs[0].(*gp.SRv6InformationSubTLV)
			if !ok || len(info.SubSubTLVs) > 1 {
				return r, fmt.Errorf("single SID information required")
			}
			if len(info.SubSubTLVs) == 1 {
				if _, ok := info.SubSubTLVs[0].(*gp.SRv6SIDStructureSubSubTLV); !ok {
					return r, fmt.Errorf("unsupported SID sub-TLV")
				}
			}
		default:
			return r, fmt.Errorf("unsupported output attribute %d", attr.GetType())
		}
	}
	if !seen[gp.BGP_ATTR_TYPE_ORIGIN] || !seen[gp.BGP_ATTR_TYPE_MP_REACH_NLRI] {
		return r, fmt.Errorf("origin and MP_REACH required")
	}
	if r.Family != bgp.FamilyIPv6Unicast {
		sid, err := gobgppath.ReadServiceSID(path.Attributes, gp.TLVTypeSRv6L3Service)
		if err != nil {
			return r, err
		}
		r.SRv6SID = sid.Address.String()
		r.EndpointBehavior = sid.Behavior
		s := sid.Structure
		r.SIDStructure = bgp.SIDStructure{LocatorBlockLen: s.LocatorBlock, LocatorNodeLen: s.LocatorNode, FunctionLen: s.Function, ArgumentLen: s.Argument}
		if sid.Behavior == 0 || (sid.HasStructure && r.SIDStructure.IsZero()) {
			return r, fmt.Errorf("unsupported unspecified SID behavior or zero structure")
		}
	}
	return r, nil
}

func (p *PluginOps) OutputState() (uint64, uint64, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.desiredRevision, p.appliedRevision, p.outputFailure
}

// A binding edit can change host-derived IDs and attributes without a guest
// revision. Withdraw dependents and reconcile the latest declaration again.
func (p *PluginOps) reconcileComposition(ctx context.Context) (int, error) {
	p.applyMu.Lock()
	p.mu.Lock()
	retired := p.retired
	p.mu.Unlock()
	if retired {
		p.applyMu.Unlock()
		return 0, nil
	}
	p.mu.Lock()
	txn := p.latestComposition
	ready := p.inputReady && p.inputFault == ""
	fullyApplied := p.outputFailure == "" && !p.inputCleanupPending &&
		p.appliedRevision == p.desiredRevision && len(p.pending) == 0
	p.mu.Unlock()
	// A notification may concern another VRF. Revalidate first and preserve
	// the complete applied set only if its host-derived values still match.
	if p.compositionValid && txn != nil && ready && fullyApplied {
		if desired, err := p.normalizeComposition(txn.composition); err == nil {
			if digest, err := compositionDigest(txn.composition, desired); err == nil && digest == p.compositionHash {
				p.applyMu.Unlock()
				return 0, nil
			}
		}
	}
	p.compositionValid = false
	if p.advertise != nil {
		if err := p.advertise.WithdrawOwner(ctx, p.owner); err != nil {
			p.applyMu.Unlock()
			return 0, err
		}
	}
	p.applyMu.Unlock()
	if txn == nil || !ready {
		return 0, nil
	}
	if err := p.applyTransaction(txn); err != nil {
		p.holdForRetry(txn)
		return 0, err
	}
	return 0, nil
}
