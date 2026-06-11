package bpf

import "testing"

// buildMupUplink{V4,V6}Key must reject an empty / unspecified endpoint so a
// remote-controlled F-TEID entry can never be keyed on "" or "::" (which would
// match an unintended endpoint). The endpoint is part of the LPM key, so a
// zero endpoint is never a valid session.
func TestBuildMupUplinkKey_RejectsEmptyEndpoint(t *testing.T) {
	if _, err := buildMupUplinkV4Key(0, "", 0x100, 32); err == nil {
		t.Error("buildMupUplinkV4Key empty endpoint: want error, got nil")
	}
	if _, err := buildMupUplinkV6Key(0, "", 0x100, 32); err == nil {
		t.Error("buildMupUplinkV6Key empty endpoint: want error, got nil")
	}
	if _, err := buildMupUplinkV6Key(0, "::", 0x100, 32); err == nil {
		t.Error("buildMupUplinkV6Key unspecified endpoint (::): want error, got nil")
	}

	// A real endpoint succeeds for both families.
	if _, err := buildMupUplinkV4Key(0, "192.0.2.1", 0x100, 32); err != nil {
		t.Errorf("buildMupUplinkV4Key valid endpoint: unexpected error %v", err)
	}
	if _, err := buildMupUplinkV6Key(0, "2001:db8::1", 0x100, 32); err != nil {
		t.Errorf("buildMupUplinkV6Key valid endpoint: unexpected error %v", err)
	}

	// teidPrefixBits > 32 is rejected (a TEID is 32 bits).
	if _, err := buildMupUplinkV6Key(0, "2001:db8::1", 0x100, 33); err == nil {
		t.Error("buildMupUplinkV6Key teidPrefixBits 33: want error, got nil")
	}
}
