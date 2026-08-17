package gobgp

import (
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// BuiltinEndpointBehaviors are the SRv6 endpoint behavior codepoints a
// plugin may not claim.
//
// It is every behavior with a standardized codepoint, not just the ones
// Vinbero advertises. The receive path is behavior-agnostic: applyVPN and
// its siblings install a headend entry from whatever service SID the route
// carries, without consulting the codepoint at all. So a peer advertising
// End.DT46 or End.DX4 is handled correctly today even though Vinbero never
// originates one, and letting a plugin claim those codepoints would divert
// real L3VPN routes away from the built-in applier -- which is exactly the
// thing this list exists to prevent.
//
// The rule an operator sees is simple: standardized behaviors belong to
// Vinbero, and a plugin's own behavior uses a codepoint outside the
// assigned space. That also keeps this list from needing an edit every
// time the receive path learns to read another standard behavior.
func BuiltinEndpointBehaviors() []uint16 {
	behaviors := []gobgppkt.SRBehavior{
		gobgppkt.END,
		gobgppkt.END_WITH_PSP,
		gobgppkt.END_WITH_USP,
		gobgppkt.END_WITH_PSP_USP,
		gobgppkt.ENDX,
		gobgppkt.ENDX_WITH_PSP,
		gobgppkt.ENDX_WITH_USP,
		gobgppkt.ENDX_WITH_PSP_USP,
		gobgppkt.ENDT,
		gobgppkt.ENDT_WITH_PSP,
		gobgppkt.ENDT_WITH_USP,
		gobgppkt.ENDT_WITH_PSP_USP,
		gobgppkt.END_B6_ENCAPS,
		gobgppkt.END_BM,
		gobgppkt.END_DX6,
		gobgppkt.END_DX4,
		gobgppkt.END_DT6,
		gobgppkt.END_DT4,
		gobgppkt.END_DT46,
		gobgppkt.END_DX2,
		gobgppkt.END_DX2V,
		gobgppkt.END_DT2U,
		gobgppkt.END_DT2M,
		gobgppkt.END_B6_ENCAPS_Red,
		gobgppkt.END_WITH_USD,
		gobgppkt.END_WITH_PSP_USD,
		gobgppkt.END_WITH_USP_USD,
		gobgppkt.END_WITH_PSP_USP_USD,
		gobgppkt.ENDX_WITH_USD,
		gobgppkt.ENDX_WITH_PSP_USD,
		gobgppkt.ENDX_WITH_USP_USD,
		gobgppkt.ENDX_WITH_PSP_USP_USD,
		gobgppkt.ENDT_WITH_USD,
		gobgppkt.ENDT_WITH_PSP_USD,
		gobgppkt.ENDT_WITH_USP_USD,
		gobgppkt.ENDT_WITH_PSP_USP_USD,
		gobgppkt.ENDM_GTP6D,
		gobgppkt.ENDM_GTP6DI,
		gobgppkt.ENDM_GTP6E,
		gobgppkt.ENDM_GTP4E,
	}
	out := make([]uint16, 0, len(behaviors))
	for _, b := range behaviors {
		out = append(out, uint16(b))
	}
	return out
}
