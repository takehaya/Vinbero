package headend

import (
	"fmt"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"strings"
)

const MUPGateOwner bpf.OwnerTag = "builtin:v1:mup-gate"

// gateID names one gate's references: a gate is an entry of one VRF, the
// VRF of the uplinks it fronts, so the same endpoint in two VRFs is two
// gates.
func gateID(af Family, vrfID uint32, prefix string) string {
	return fmt.Sprintf("%d/%d/%s", af, vrfID, prefix)
}

// KeepGateReferences protects a recovered uplink before repairing its gate.
// Unlike a new session's SetGateReferences, an error retains the reference:
// persistent forwarding already exists and must not lose its dependency when
// startup prunes unreferenced gates. Release with SetGateReferences(..., 0).
func (r *Reconciler) KeepGateReferences(af Family, vrfID uint32, prefix string, mode uint8, owner bpf.OwnerTag, refs int) error {
	if (af != AFv4 && af != AFv6) || refs <= 0 || owner == "" {
		return fmt.Errorf("invalid recovered gate reference")
	}
	if (af == AFv4 && mode != uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_M_GTP4_D_TEID)) || (af == AFv6 && mode != uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_M_GTP6_D_TEID)) {
		return fmt.Errorf("invalid MUP gate mode")
	}
	key, err := canonicalPrefix(af, prefix)
	if err != nil {
		return err
	}
	r.gateMu.Lock()
	defer r.gateMu.Unlock()
	if r.gateRefs == nil {
		r.gateRefs = map[string]map[bpf.OwnerTag]int{}
	}
	id := gateID(af, vrfID, key)
	if r.gateRefs[id] == nil {
		r.gateRefs[id] = map[bpf.OwnerTag]int{}
	}
	r.gateRefs[id][owner] = refs
	return r.writeGate(af, ID{VRF: vrfID, Prefix: key}, mode)
}

// writeGate puts the shared gate entry, taking over one the built-in MUP
// applier wrote under its own owner before gates were shared.
func (r *Reconciler) writeGate(af Family, key ID, mode uint8) error {
	current, found, err := getOwner(r.maps, af, key)
	if err != nil {
		return err
	}
	if found && current != MUPGateOwner && strings.HasPrefix(string(current), "bgp:") && strings.HasSuffix(string(current), ":mup-gate") {
		if err := r.remove(af, key, current); err != nil {
			return err
		}
	}
	return r.put(af, key, &bpf.HeadendEntry{Mode: mode}, MUPGateOwner)
}

// SetGateReferences shares a physical endpoint gate of one VRF across
// service owners. Drop the final reference only after the corresponding
// uplink delete succeeds.
func (r *Reconciler) SetGateReferences(af Family, vrfID uint32, prefix string, mode uint8, owner bpf.OwnerTag, refs int) error {
	if (af == AFv4 && mode != uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_M_GTP4_D_TEID)) || (af == AFv6 && mode != uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_M_GTP6_D_TEID)) {
		return fmt.Errorf("invalid MUP gate mode")
	}
	if refs < 0 || owner == "" {
		return fmt.Errorf("invalid gate references")
	}
	key, err := canonicalPrefix(af, prefix)
	if err != nil {
		return err
	}
	r.gateMu.Lock()
	defer r.gateMu.Unlock()
	id := gateID(af, vrfID, key)
	if r.gateRefs == nil {
		r.gateRefs = map[string]map[bpf.OwnerTag]int{}
	}
	held := r.gateRefs[id]
	if held == nil {
		held = map[bpf.OwnerTag]int{}
	}
	total := refs
	for other, n := range held {
		if other != owner {
			total += n
		}
	}
	if total > 0 {
		if err := r.writeGate(af, ID{VRF: vrfID, Prefix: key}, mode); err != nil {
			return err
		}
	} else {
		if err := r.remove(af, ID{VRF: vrfID, Prefix: key}, MUPGateOwner); err != nil {
			return err
		}
	}
	if refs == 0 {
		delete(held, owner)
	} else {
		held[owner] = refs
	}
	if len(held) == 0 {
		delete(r.gateRefs, id)
	} else {
		r.gateRefs[id] = held
	}
	return nil
}

// PruneUnreferencedMUPGates runs after persistent uplink inventories have seeded
// their references. gateMu also protects gates held by a live built-in apply.
func (r *Reconciler) PruneUnreferencedMUPGates() error {
	r.gateMu.Lock()
	defer r.gateMu.Unlock()
	for _, af := range []Family{AFv4, AFv6} {
		entries, err := OwnedEntries(r.maps, MUPGateOwner, af)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if len(r.gateRefs[gateID(af, e.VRF, e.TriggerPrefix)]) == 0 {
				if err = r.remove(af, e.ID(), MUPGateOwner); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
