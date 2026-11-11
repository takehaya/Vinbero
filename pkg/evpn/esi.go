package evpn

import "fmt"

// ESI types of RFC 7432 section 5.
const (
	ESITypeArbitrary byte = 0
	ESITypeLACP      byte = 1
	ESITypeMSTP      byte = 2
	ESITypeMAC       byte = 3
	ESITypeRouterID  byte = 4
	ESITypeAS        byte = 5
)

// esiLayouts describes the value octets of each type. reserved is true when
// the last octet must be zero; a receiving GoBGP rejects an UPDATE whose
// value there is nonzero for types 1, 2, 4 and 5
// (EthernetSegmentIdentifier.DecodeFromBytes) and resets the session.
var esiLayouts = [...]struct {
	name     string
	layout   string
	reserved bool
}{
	ESITypeArbitrary: {"arbitrary", "type, 9 octets of any value", false},
	ESITypeLACP:      {"LACP-based", "type, 6-octet system MAC, 2-octet port key, 1 reserved octet that must be 0x00", true},
	ESITypeMSTP:      {"bridge-protocol-based", "type, 6-octet bridge MAC, 2-octet priority, 1 reserved octet that must be 0x00", true},
	ESITypeMAC:       {"MAC-based", "type, 6-octet system MAC, 3-octet local discriminator", false},
	ESITypeRouterID:  {"router-ID-based", "type, 4-octet router ID, 4-octet local discriminator, 1 reserved octet that must be 0x00", true},
	ESITypeAS:        {"AS-based", "type, 4-octet AS number, 4-octet local discriminator, 1 reserved octet that must be 0x00", true},
}

// ValidateESI reports why esi cannot be advertised. It accepts the types of
// RFC 7432 section 5 (0 to 5) and, for the types that reserve their last
// octet, requires it to be zero: the check every receiving GoBGP applies.
// The value is never changed; the error names the octet and the layout of
// the type.
func ValidateESI(esi [ESILen]byte) error {
	t := esi[0]
	if int(t) >= len(esiLayouts) {
		return fmt.Errorf("ESI type 0x%02x is not defined: the types are 0 (arbitrary), 1 (LACP), 2 (bridge protocol), 3 (MAC), 4 (router ID) and 5 (AS)", t)
	}
	l := esiLayouts[t]
	if l.reserved && esi[ESILen-1] != 0 {
		return fmt.Errorf("ESI type %d (%s): octet %d is 0x%02x but must be 0x00 (layout: %s)",
			t, l.name, ESILen, esi[ESILen-1], l.layout)
	}
	return nil
}
