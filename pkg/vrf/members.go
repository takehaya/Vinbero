package vrf

import (
	"fmt"
	"slices"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

// MemberWithoutAC is a port enslaved to a VRF's kernel device that is not an
// access circuit of that VRF.
type MemberWithoutAC struct {
	VRF       string
	Interface string
}

// MembersFunc lists the names of the ports enslaved to the kernel device
// with this ifindex.
type MembersFunc func(vrfIfindex uint32) ([]string, error)

// KernelMembers lists the ports enslaved to the device with this ifindex.
func KernelMembers(vrfIfindex uint32) ([]string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}
	var names []string
	for _, l := range links {
		if uint32(l.Attrs().MasterIndex) == vrfIfindex {
			names = append(names, l.Attrs().Name)
		}
	}
	return names, nil
}

// MembersWithoutAC returns, for every VRF with a kernel device whose table
// ends in the unreachable default, the member ports that are not an AC of
// that VRF (on any VLAN). Such a port's packets are classified to the global
// VRF, so their encapsulation looks the outer header up on the port, which
// goes to the VRF table and stops at the unreachable default. A VRF whose
// members cannot be listed is reported in the error and skipped.
func (m *Manager) MembersWithoutAC(members MembersFunc) ([]MemberWithoutAC, error) {
	var out []MemberWithoutAC
	var firstErr error
	for _, v := range m.List() {
		if v.Device == nil || v.Device.Ifindex == 0 || v.Device.NoUnreachableDefault {
			continue
		}
		names, err := members(v.Device.Ifindex)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("vrf %q: %w", v.Name, err)
			}
			continue
		}
		slices.Sort(names)
		for _, n := range names {
			if !slices.ContainsFunc(v.ACs, func(ac AC) bool { return ac.Interface == n }) {
				out = append(out, MemberWithoutAC{VRF: v.Name, Interface: n})
			}
		}
	}
	return out, firstErr
}

// WarnMembersWithoutAC logs one warning per member port of a VRF that is not
// an AC of it (MembersWithoutAC): its encapsulation is dropped at the VRF
// table until the port becomes an AC or the VRF opts out.
func (m *Manager) WarnMembersWithoutAC(members MembersFunc, lg *zap.Logger) {
	found, err := m.MembersWithoutAC(members)
	if err != nil {
		lg.Warn("cannot check the VRF member ports for access circuits", zap.Error(err))
	}
	for _, f := range found {
		lg.Warn("VRF member port is not an access circuit of its VRF: packets from it are in the global VRF, "+
			"and their encapsulation is dropped at the VRF table's unreachable default; "+
			"make the port an AC of the VRF (vbctl vrf ac-add / vrfs.entries[].acs) or opt the VRF out (no_unreachable_default)",
			zap.String("vrf", f.VRF), zap.String("interface", f.Interface))
	}
}
