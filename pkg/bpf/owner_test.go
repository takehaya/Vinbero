package bpf

import (
	"strings"
	"testing"
)

func TestOwnerBGPVPNFormat(t *testing.T) {
	got := OwnerBGPVPN(65000, "65000:100")
	want := OwnerTag("bgp:v1:asn=65000:rd=65000:100")
	if got != want {
		t.Errorf("OwnerBGPVPN(65000, %q) = %q, want %q", "65000:100", got, want)
	}
}

func TestOwnerBGPUnicastFormat(t *testing.T) {
	got := OwnerBGPUnicast(64512)
	want := OwnerTag("bgp:v1:asn=64512:unicast")
	if got != want {
		t.Errorf("OwnerBGPUnicast(64512) = %q, want %q", got, want)
	}
}

func TestParseOwnerTag(t *testing.T) {
	tests := []struct {
		name        string
		tag         OwnerTag
		wantKind    string
		wantVersion string
		wantErr     bool
	}{
		{name: "rpc-v1", tag: OwnerRPC, wantKind: "rpc", wantVersion: "v1"},
		{name: "builtin-v1", tag: OwnerBuiltin, wantKind: "builtin", wantVersion: "v1"},
		{name: "bgp-vpn", tag: OwnerBGPVPN(65000, "65000:100"), wantKind: "bgp", wantVersion: "v1"},
		{name: "bgp-unicast", tag: OwnerBGPUnicast(65000), wantKind: "bgp", wantVersion: "v1"},
		// Plugin tags are entry owners now that a control-plane plugin can
		// write the main maps; both tag forms parse. See plugin_owner.go.
		{name: "plugin-slot", tag: "plugin:v1:endpoint:32", wantKind: "plugin", wantVersion: "v1"},
		{name: "plugin-bundle", tag: OwnerPluginBundle("acl-prefix"), wantKind: "plugin", wantVersion: "v1"},
		{name: "empty", tag: "", wantErr: true},
		{name: "no-colon", tag: "garbage", wantErr: true},
		{name: "unknown-kind", tag: "wireguard:v1:peer=1", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kind, version, err := ParseOwnerTag(tc.tag)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseOwnerTag(%q) = %q,%q,nil; want error", tc.tag, kind, version)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseOwnerTag(%q) returned %v", tc.tag, err)
			}
			if kind != tc.wantKind {
				t.Errorf("kind = %q, want %q", kind, tc.wantKind)
			}
			if version != tc.wantVersion {
				t.Errorf("version = %q, want %q", version, tc.wantVersion)
			}
		})
	}
}

func TestOwnerTagWireFitsAuxBuffer(t *testing.T) {
	// Owner tags are persisted into a 64-byte aux_owner.tag buffer with one
	// byte reserved for the null terminator. Surface any pre-defined or
	// derivable tag that grows too long for that wire format before it
	// silently truncates in production.
	cases := []OwnerTag{
		OwnerRPC,
		OwnerBuiltin,
		OwnerBGPVPN(4294967295, strings.Repeat("X", 8)),
		OwnerBGPUnicast(4294967295),
		OwnerBGPVPNGroup(4294967295),
	}
	for _, tag := range cases {
		if l := len(tag); l > auxOwnerTagBytes-1 {
			t.Errorf("owner tag %q is %d bytes, must be <= %d", tag, l, auxOwnerTagBytes-1)
		}
	}
}

func TestCheckEntryOwnerNilMapAllowsAll(t *testing.T) {
	// A nil owners pointer indicates owner tracking is disabled (e.g. test
	// fixtures that load a subset of maps). The check must short-circuit
	// rather than dereference nil, and report "not already owned" so the
	// caller still writes the owner record (which becomes a no-op via
	// the nil entryOwnerMap).
	alreadyOwned, err := checkEntryOwner(nil, "any-key", OwnerRPC)
	if err != nil {
		t.Errorf("nil owners check returned %v, want nil", err)
	}
	if alreadyOwned {
		t.Errorf("nil owners check reported alreadyOwned=true, want false")
	}
}

func TestCheckEntryOwnerEmptyCallerRejected(t *testing.T) {
	// Empty caller would silently collide with the "no recorded owner"
	// sentinel; checkEntryOwner must reject it up front.
	if _, err := checkEntryOwner(nil, "any-key", ""); err != ErrEmptyOwner {
		t.Errorf("empty caller: got %v, want ErrEmptyOwner", err)
	}
}

// TestOwnerBGPVPNGroup covers the one job this owner has: being shared by
// every path that contributes to a prefix's group. An RD- or prefix-scoped
// owner would either reject the second PE's path as a cross-owner write or
// overflow the 64-byte tag buffer (see TestOwnerTagWireFitsAuxBuffer).
func TestOwnerBGPVPNGroup(t *testing.T) {
	const asn = 65000
	if a, b := OwnerBGPVPNGroup(asn), OwnerBGPVPNGroup(asn); a != b {
		t.Fatalf("owner is not stable: %q vs %q", a, b)
	}
	if OwnerBGPVPNGroup(asn) == OwnerBGPVPNGroup(asn+1) {
		t.Error("different ASNs must not share an owner")
	}
	// Must not collide with the per-RD owner used for the trigger entries.
	if OwnerBGPVPNGroup(asn) == OwnerBGPVPN(asn, "65000:1") {
		t.Error("group owner collides with the plain VPN owner")
	}
}
