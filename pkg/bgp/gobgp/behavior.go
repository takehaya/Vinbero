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
// assigned space. New RFC assignments must be added here even when the
// pinned GoBGP version has no constant for them.
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
	// RFC assignments absent from the pinned GoBGP enum. Keep explicit values
	// so draft-only assignments and unassigned gaps remain claimable.
	return append(out,
		0x0028, 0x0029, // RFC 9433: End.MAP, End.Limit
		0x004B,                 // RFC 9524: End.Replicate
		0x004C, 0x004D, 0x004E, // RFC 10018: End.DTMC4/6/46
		0x0054,                 // RFC 9491: End.NSH
		0x009E, 0x009F, 0x00A0, // RFC 9801: End.DX1 and its CSID flavors
		0x7FFF, // RFC 8986: SID defined in RFC 8754
		// RFC 9800, section 12.1, Table 1 (NEXT-CSID and REPLACE-CSID).
		0x002B, 0x002C, 0x002D, 0x002E, 0x002F, 0x0030, 0x0031, 0x0032,
		0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, 0x003A, 0x003B,
		0x0055, 0x0056, 0x0057, 0x0058, 0x0059, 0x005A, 0x005B, 0x005C,
		0x005D, 0x005E, 0x005F, 0x0060, 0x0061,
		0x0065, 0x0066, 0x0067, 0x0068, 0x0069, 0x006A, 0x006B, 0x006C,
		0x006D, 0x006E, 0x006F, 0x0070,
		0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077, 0x0078, 0x0079,
		0x007A, 0x007B, 0x007C,
		0x007F, 0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086,
		0x0087, 0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D,
	)
}
