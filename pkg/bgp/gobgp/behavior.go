package gobgp

import (
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// BuiltinEndpointBehaviors are the SRv6 endpoint behavior codepoints
// Vinbero's own appliers implement, and which a plugin therefore cannot
// claim: an operator may add a behavior, not take End.DT4 away from the
// built-in path.
//
// The list is derived from what Vinbero advertises and consumes on the
// receive side -- the L3VPN service SIDs and the EVPN ones -- and lives
// beside the encode helpers so a new advertised behavior is added here in
// the same edit rather than silently staying claimable.
func BuiltinEndpointBehaviors() []uint16 {
	return []uint16{
		uint16(gobgppkt.END_DT4),
		uint16(gobgppkt.END_DT6),
		uint16(gobgppkt.END_DT2U),
		uint16(gobgppkt.END_DT2M),
	}
}
