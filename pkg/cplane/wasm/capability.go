package wasm

import (
	"fmt"
	"sort"
	"strings"
)

// A capability is a name for one thing a plugin is allowed to do. A plugin
// declares the ones it needs at registration, and the host links only
// those host functions: a capability that was not granted is not a call
// that fails, it is a function the module cannot import at all.
//
// That is the difference between a permission check and a capability. A
// check can be forgotten at one call site; an unlinked function cannot be
// reached from anywhere, and a module that tries is refused before it
// runs, with a message naming what it asked for.
type Capability string

const (
	// CapHeadend lets a plugin declare headend encap entries: which
	// traffic is steered into which SID list.
	CapHeadend Capability = "headend"
	// CapAdvertise lets a plugin originate BGP routes.
	CapAdvertise Capability = "advertise"
	// CapLocalSID lets a plugin allocate SIDs from a locator and point
	// them at its own data-plane slot.
	CapLocalSID Capability = "local_sid"
)

// Capabilities is a granted set.
type Capabilities map[Capability]struct{}

// ParseCapabilities validates operator-supplied names into a set.
func ParseCapabilities(names []string) (Capabilities, error) {
	out := make(Capabilities, len(names))
	for _, n := range names {
		c := Capability(strings.TrimSpace(n))
		if !c.valid() {
			return nil, fmt.Errorf("%w: unknown capability %q (want %s)",
				ErrAdmission, n, strings.Join(capabilityNames(), ", "))
		}
		out[c] = struct{}{}
	}
	return out, nil
}

// Has reports whether the set grants c.
func (c Capabilities) Has(cap Capability) bool {
	_, ok := c[cap]
	return ok
}

// Names renders the set for logs and errors, in a stable order.
func (c Capabilities) Names() []string {
	out := make([]string, 0, len(c))
	for cap := range c {
		out = append(out, string(cap))
	}
	sort.Strings(out)
	return out
}

// valid reports whether a capability is one the host defines.
func (c Capability) valid() bool {
	switch c {
	case CapHeadend, CapAdvertise, CapLocalSID:
		return true
	default:
		return false
	}
}

// capabilityNames lists every capability, for error messages.
func capabilityNames() []string {
	return []string{string(CapAdvertise), string(CapHeadend), string(CapLocalSID)}
}

// alwaysLinked are the host functions every plugin gets.
//
// Both are diagnostics rather than authority: a module has no stdout and
// no filesystem, so without log a plugin author cannot see why their
// plugin did nothing, and without a clock no liveness logic can be
// written. Neither changes any state, so gating them would cost
// debuggability and buy nothing.
func alwaysLinked() map[string]struct{} {
	return map[string]struct{}{
		HostLog:          {},
		HostNowMonotonic: {},
	}
}

// grantsAnyWrite reports whether the set allows declaring anything at all.
//
// The apply functions are shared by every kind of declaration, so they are
// linked when any write capability is granted and the kind is checked
// again where the transaction is opened. Linking is the coarse gate;
// without the second check a plugin granted only advertise could open a
// headend transaction through the same door.
func (c Capabilities) grantsAnyWrite() bool {
	return c.Has(CapHeadend) || c.Has(CapAdvertise) || c.Has(CapLocalSID)
}

// checkImports refuses a module that imports a host function its granted
// capabilities do not cover.
//
// wazero would refuse an unresolved import on its own, but with a message
// about a missing import rather than about a capability. An operator
// reading "module imports vinbero.apply_begin but was granted no
// capability that provides it" knows what to change; one reading "module
// vinbero: function not exported" has to work it out.
func (c Capabilities) checkImports(imported []string) error {
	always := alwaysLinked()
	var ungranted []string
	for _, name := range imported {
		if _, ok := always[name]; ok {
			continue
		}
		if isApplyFunction(name) {
			if c.grantsAnyWrite() {
				continue
			}
			ungranted = append(ungranted, name)
			continue
		}
		// Anything else is not a host function this version defines; the
		// admission rules refuse it separately, with a message about the
		// import rather than about capabilities.
		ungranted = append(ungranted, name)
	}
	if len(ungranted) == 0 {
		return nil
	}
	sort.Strings(ungranted)
	granted := c.Names()
	if len(granted) == 0 {
		granted = []string{"none"}
	}
	return fmt.Errorf("%w: module imports %s but was granted only %s",
		ErrAdmission, strings.Join(ungranted, ", "), strings.Join(granted, ", "))
}

// isApplyFunction reports whether a host function is part of the shared
// desired-set transaction surface.
func isApplyFunction(name string) bool {
	switch name {
	case HostApplyBegin, HostApplyPut, HostApplyCommit, HostApplyAbort:
		return true
	default:
		return false
	}
}
