package bpf

import "testing"

// ParseESI is syntax only so an ESI stored earlier can still be looked up or
// deleted; ParseValidESI is what the entry points that advertise or create use.
func TestParseValidESI(t *testing.T) {
	const badType1 = "01:aa:bb:cc:00:00:01:00:05:01" // type 1, last octet 0x01
	if _, err := ParseESI(badType1); err != nil {
		t.Fatalf("ParseESI is syntax only: %v", err)
	}
	if _, err := ParseValidESI(badType1); err == nil {
		t.Error("ParseValidESI accepted a type 1 ESI with a nonzero last octet")
	}
	if _, err := ParseValidESI("07:00:00:00:00:00:00:00:00:00"); err == nil {
		t.Error("ParseValidESI accepted an undefined type")
	}
	if _, err := ParseValidESI("01:aa:bb"); err == nil {
		t.Error("ParseValidESI accepted a short ESI")
	}
	if esi, err := ParseValidESI(""); err != nil || esi != ([ESILen]byte{}) {
		t.Errorf("the empty string is the single-homed ESI: %v %v", esi, err)
	}
	if _, err := ParseValidESI("01:aa:bb:cc:00:00:01:00:05:00"); err != nil {
		t.Errorf("valid type 1 rejected: %v", err)
	}
}
