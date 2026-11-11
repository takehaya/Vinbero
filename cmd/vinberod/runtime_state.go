package main

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/evpn"
	"github.com/takehaya/vinbero/pkg/netresource"
	"github.com/takehaya/vinbero/pkg/vinbero"
	"github.com/takehaya/vinbero/pkg/vrf"
)

func denyActionName(a uint8) string {
	if a == vrf.DenyActionPass {
		return "pass"
	}
	return "drop"
}

// vrfPolicyStore returns what saves the policy VrfSetPolicy sets. Nothing is
// saved when the config file owns the policy (config.VRFsConfig.PolicyDeclared):
// the change then holds until the next start, which applies the config's.
func vrfPolicyStore(res *netresource.ResourceManager, cfg config.VRFsConfig) func(vrf.Policy) error {
	return func(p vrf.Policy) error {
		if cfg.PolicyDeclared() {
			return nil
		}
		return res.SaveRuntimeVrfPolicy(netresource.ManagedVrfPolicy{DefaultDeny: p.DefaultDeny, DenyAction: denyActionName(p.DenyAction)})
	}
}

// restoreVRFPolicy puts back the policy set over the API, after loadVRFs set
// the config's and before restoreVRFs programs the data plane, so the policy
// is in force from the first packet after the attach. When the config owns
// the policy the saved one is not restored and is removed from the state
// file. A saved deny action this version does not know stops the start.
func restoreVRFPolicy(cfg config.VRFsConfig, mgr *vrf.Manager, res *netresource.ResourceManager, lg *zap.Logger) error {
	saved := res.RuntimeVrfPolicy()
	if saved == nil {
		return nil
	}
	if cfg.PolicyDeclared() {
		lg.Warn("the config file sets vrfs.default_deny or vrfs.deny_action; the VRF policy set over the API is not restored and is removed from the state file")
		if err := res.DropRuntimeVrfPolicy(); err != nil {
			lg.Warn("the dropped VRF policy stays in the state file until the next successful write of it", zap.Error(err))
		}
		return nil
	}
	var action uint8
	switch saved.DenyAction {
	case "drop":
		action = vrf.DenyActionDrop
	case "pass":
		action = vrf.DenyActionPass
	default:
		return fmt.Errorf("runtime_vrf_policy: deny_action %q: want \"drop\" or \"pass\" (repair the state file, settings.state_path, and restart)", saved.DenyAction)
	}
	mgr.SetPolicy(vrf.Policy{DefaultDeny: saved.DefaultDeny, DenyAction: action})
	lg.Info("VRF policy restored from the state file",
		zap.Bool("default_deny", saved.DefaultDeny), zap.String("deny_action", saved.DenyAction))
	if saved.DefaultDeny {
		lg.Warn("VRF default-deny enabled: unmapped ACs are dropped at XDP ingress; map every forwarding interface (underlay/control included) to a VRF or host-bound BGP/NDP is black-holed")
	}
	return nil
}

// resumeSegments does for the Ethernet Segments restored from the state file
// what EsCreate does after it writes one: with BGP, a locally attached
// segment's DF is elected again, and with EVPN auto-advertise one with an RD
// has its RT4 advertised. It runs once the BGP session is started, as the RT4
// push is not retried. reElect and enable may be nil.
func resumeSegments(recs []netresource.ManagedEthernetSegment, reElect func([bpf.ESILen]byte), enable func([bpf.ESILen]byte, string) error, lg *zap.Logger) {
	for _, r := range recs {
		if !r.LocalAttached {
			continue
		}
		esi, _, err := vinbero.SegmentEntry(r)
		if err != nil {
			continue // InitResourceManager refused such a record
		}
		if err := evpn.ValidateESI(esi); err != nil {
			lg.Warn("Ethernet Segment restored from the state file has an ESI that BGP peers would reject; it is not elected at start and not advertised (delete it with vbctl es delete and create it again with a valid ESI)",
				zap.String("esi", r.ESI), zap.Error(err))
			continue
		}
		if reElect != nil {
			reElect(esi)
		}
		if enable != nil && r.RD != "" {
			if err := enable(esi, r.RD); err != nil {
				lg.Warn("enable EVPN RT4 auto-advertise for an Ethernet Segment restored from the state file",
					zap.String("esi", r.ESI), zap.Error(err))
			}
		}
	}
}
