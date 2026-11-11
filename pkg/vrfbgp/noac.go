package vrfbgp

import (
	"slices"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// headendFamilies are the families whose received routes are installed as
// headend entries of the VRF that imports them: L3VPN and MUP.
var headendFamilies = []bgp.Family{bgp.FamilyVPNv4, bgp.FamilyVPNv6, bgp.FamilyMUPIPv4, bgp.FamilyMUPIPv6}

// BindingWithoutAC is a binding that imports routes into a VRF no ingress is
// classified to.
type BindingWithoutAC struct {
	VRF      string
	VRFID    uint32
	Families []bgp.Family
}

// BindingsWithoutAC returns the bindings among names (every binding when
// names is nil) whose VRF imports L3VPN or MUP routes, by declaring one of
// those families with an import RT, and has no access circuit. Their routes
// are installed in the VRF, but no packet is looked up there: only a packet
// that enters on one of the VRF's ACs is. EVPN-only bindings are not
// listed, as EVPN forwards through bridge domains and circuits.
func (m *Manager) BindingsWithoutAC(names []string) []BindingWithoutAC {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []BindingWithoutAC
	for name, b := range m.bindings {
		if names != nil && !slices.Contains(names, name) {
			continue
		}
		var fams []bgp.Family
		for _, fam := range headendFamilies {
			if slices.ContainsFunc(b.Families[fam].RouteTargets, RouteTarget.imports) {
				fams = append(fams, fam)
			}
		}
		if len(fams) == 0 {
			continue
		}
		v, ok := m.vrf.Get(name)
		if !ok || len(v.ACs) > 0 {
			continue
		}
		out = append(out, BindingWithoutAC{VRF: name, VRFID: v.ID, Families: fams})
	}
	slices.SortFunc(out, func(a, b BindingWithoutAC) int {
		if a.VRF < b.VRF {
			return -1
		}
		if a.VRF > b.VRF {
			return 1
		}
		return 0
	})
	return out
}

// WarnBindingsWithoutAC logs one warning for each of BindingsWithoutAC(names).
// It neither fails nor creates an AC: an AC is an operator's choice of which
// port belongs to the tenant.
func (m *Manager) WarnBindingsWithoutAC(names []string, lg *zap.Logger) {
	for _, b := range m.BindingsWithoutAC(names) {
		fams := make([]string, len(b.Families))
		for i, f := range b.Families {
			fams[i] = string(f)
		}
		lg.Warn("VRF BGP binding has no access circuits; imported L3 routes are installed in this VRF, "+
			"but no ingress is classified to it; configure vrf ac-add or vrfs.entries[].acs",
			zap.String("vrf", b.VRF), zap.Uint32("vrf_id", b.VRFID), zap.Strings("families", fams))
	}
}
