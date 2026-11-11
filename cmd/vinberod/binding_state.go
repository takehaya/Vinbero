package main

import (
	"fmt"
	"slices"
	"sort"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/netresource"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// bindingStateStore keeps the VRF bindings made over the API in the resource
// manager's state file, next to the VRF objects. The conversion lives here
// so pkg/netresource does not depend on pkg/vrfbgp.
type bindingStateStore struct {
	res *netresource.ResourceManager
}

func (s bindingStateStore) SaveBindings(bindings []vrfbgp.Binding) error {
	out := make([]netresource.ManagedVrfBinding, 0, len(bindings))
	for _, b := range bindings {
		out = append(out, bindingToRecord(b))
	}
	return s.res.SaveRuntimeVrfBindings(out)
}

// drop records bindings, the saved ones minus some the boot dropped, and
// keeps that record in memory if the write fails (DropRuntimeVrfBindings).
func (s bindingStateStore) drop(bindings []vrfbgp.Binding) error {
	out := make([]netresource.ManagedVrfBinding, 0, len(bindings))
	for _, b := range bindings {
		out = append(out, bindingToRecord(b))
	}
	return s.res.DropRuntimeVrfBindings(out)
}

func bindingToRecord(b vrfbgp.Binding) netresource.ManagedVrfBinding {
	r := netresource.ManagedVrfBinding{
		VRFName:        b.VRFName,
		RD:             b.RD,
		ImportRTs:      slices.Clone(b.ImportRTs),
		ExportRTs:      slices.Clone(b.ExportRTs),
		Redistribute:   slices.Clone(b.Redistribute),
		MaxPrefixes:    b.MaxPrefixes,
		DefaultLocator: b.DefaultLocator,
	}
	if b.Families != nil {
		r.Families = make(map[string]netresource.ManagedFamilyPolicy, len(b.Families))
		for fam, fp := range b.Families {
			rts := make([]netresource.ManagedRouteTarget, 0, len(fp.RouteTargets))
			for _, rt := range fp.RouteTargets {
				rts = append(rts, netresource.ManagedRouteTarget{RT: rt.RT, Direction: rt.Direction.String()})
			}
			r.Families[string(fam)] = netresource.ManagedFamilyPolicy{RouteTargets: rts}
		}
	}
	if b.MupGTP4SourcePrefix.IsValid() {
		r.MupGTP4SourcePrefix = b.MupGTP4SourcePrefix.String()
	}
	return r
}

func recordToBinding(r netresource.ManagedVrfBinding) (vrfbgp.Binding, error) {
	if r.VRFName == "" {
		return vrfbgp.Binding{}, vrfbgp.ErrEmptyVRFName
	}
	mupSrc, err := vrfbgp.ParseMUPGTP4SourcePrefix(r.MupGTP4SourcePrefix, r.RD)
	if err != nil {
		return vrfbgp.Binding{}, err
	}
	b := vrfbgp.Binding{
		VRFName:             r.VRFName,
		RD:                  r.RD,
		ImportRTs:           slices.Clone(r.ImportRTs),
		ExportRTs:           slices.Clone(r.ExportRTs),
		Redistribute:        slices.Clone(r.Redistribute),
		MaxPrefixes:         r.MaxPrefixes,
		DefaultLocator:      r.DefaultLocator,
		MupGTP4SourcePrefix: mupSrc,
	}
	if r.Families != nil {
		b.Families = make(map[bgp.Family]vrfbgp.FamilyPolicy, len(r.Families))
		for fam, fp := range r.Families {
			rts := make([]vrfbgp.RouteTarget, 0, len(fp.RouteTargets))
			for _, rt := range fp.RouteTargets {
				// The saved direction is always spelled out: an empty one
				// is not what this daemon writes.
				if rt.Direction == "" {
					return vrfbgp.Binding{}, fmt.Errorf("family %q rt %q: direction is missing", fam, rt.RT)
				}
				dir, err := vrfbgp.ParseDirection(rt.Direction)
				if err != nil {
					return vrfbgp.Binding{}, fmt.Errorf("family %q rt %q: %w", fam, rt.RT, err)
				}
				rts = append(rts, vrfbgp.RouteTarget{RT: rt.RT, Direction: dir})
			}
			b.Families[bgp.Family(fam)] = vrfbgp.FamilyPolicy{RouteTargets: rts}
		}
	}
	return b, nil
}

// savedBindings decodes the bindings the state file holds. A record that
// does not decode stops the start, like a state file that does not parse.
func savedBindings(res *netresource.ResourceManager) ([]vrfbgp.Binding, error) {
	records := res.RuntimeVrfBindings()
	out := make([]vrfbgp.Binding, 0, len(records))
	for i, r := range records {
		b, err := recordToBinding(r)
		if err != nil {
			return nil, fmt.Errorf("runtime_vrf_bindings[%d] (vrf %q): %w", i, r.VRFName, err)
		}
		out = append(out, b)
	}
	return out, nil
}

// savedBindingVRFs names the VRFs the state file's bindings refer to.
func savedBindingVRFs(res *netresource.ResourceManager) []string {
	records := res.RuntimeVrfBindings()
	names := make([]string, 0, len(records))
	for _, r := range records {
		names = append(names, r.VRFName)
	}
	return names
}

// restoreBindings brings the bindings made over the API back and starts
// saving them. The config file wins: a saved binding of a VRF the config
// binds is dropped, from memory and from the state file, so it does not come
// back once the config stops binding that VRF. A failed write of that drop
// is a warning, like the other boot-time saves; the dropped bindings are gone
// from the record in memory all the same, so the next successful write of
// the state file, whatever it saves, removes them from disk. The bindings
// are restored whether BGP is enabled or not, as VrfBgpService runs either
// way; the config's own are bound later, with BGP.
func restoreBindings(mgr *vrfbgp.Manager, saved []vrfbgp.Binding, configNames []string, store bindingStateStore, lg *zap.Logger) error {
	kept := make([]vrfbgp.Binding, 0, len(saved))
	dropped := 0
	for _, b := range saved {
		if slices.Contains(configNames, b.VRFName) {
			lg.Warn("the config file binds this VRF; the binding saved from the API is not restored and is removed from the state file",
				zap.String("vrf", b.VRFName))
			dropped++
			continue
		}
		kept = append(kept, b)
	}
	if err := mgr.Restore(kept); err != nil {
		return fmt.Errorf("%w (repair the state file, settings.state_path, and restart)", err)
	}
	mgr.SetConfigDeclared(configNames)
	mgr.SetStore(store)
	if dropped > 0 {
		restored := mgr.List()
		sort.Slice(restored, func(i, j int) bool { return restored[i].VRFName < restored[j].VRFName })
		if err := store.drop(restored); err != nil {
			lg.Warn("the dropped bindings stay in the state file until the next successful write of it; one comes back if the config stops binding its VRF before that",
				zap.Error(err))
		}
	}
	if len(kept) > 0 {
		lg.Info("VRF bindings restored from the state file", zap.Int("bindings", len(kept)))
	}
	return nil
}
