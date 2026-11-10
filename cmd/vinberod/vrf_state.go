package main

import (
	"github.com/takehaya/vinbero/pkg/netresource"
	"github.com/takehaya/vinbero/pkg/vrf"
)

// vrfStateStore keeps the VRF objects' state in the resource manager's state
// file, next to the device and bridge records. The conversion lives here so
// pkg/netresource, the mechanics layer, does not depend on pkg/vrf.
type vrfStateStore struct {
	res *netresource.ResourceManager
}

func (s vrfStateStore) SaveVRFState(st vrf.State) error {
	objs := netresource.ManagedVrfObjects{NextVrfID: st.NextID, Entries: make([]netresource.ManagedVrfObject, 0, len(st.VRFs))}
	for _, p := range st.VRFs {
		e := netresource.ManagedVrfObject{Name: p.Name, VrfID: p.ID, Config: p.Config}
		for _, ac := range p.RuntimeACs {
			e.RuntimeACs = append(e.RuntimeACs, netresource.ManagedAC{Interface: ac.Interface, VLAN: ac.VLAN})
		}
		objs.Entries = append(objs.Entries, e)
	}
	return s.res.SaveVrfObjects(objs)
}

// load returns the saved state, the zero State on a file written before the
// VRF objects were recorded.
func (s vrfStateStore) load() vrf.State {
	objs := s.res.VrfObjects()
	if objs == nil {
		return vrf.State{}
	}
	st := vrf.State{NextID: objs.NextVrfID, VRFs: make([]vrf.PersistedVRF, 0, len(objs.Entries))}
	for _, e := range objs.Entries {
		p := vrf.PersistedVRF{Name: e.Name, ID: e.VrfID, Config: e.Config}
		for _, ac := range e.RuntimeACs {
			p.RuntimeACs = append(p.RuntimeACs, vrf.AC{Interface: ac.Interface, VLAN: ac.VLAN})
		}
		st.VRFs = append(st.VRFs, p)
	}
	return st
}
