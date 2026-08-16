package bpf

import (
	"errors"
	"strings"
	"testing"
)

func TestValidatePluginBundleName(t *testing.T) {
	tests := []struct {
		name    string
		bundle  string
		wantErr error
	}{
		{name: "ordinary", bundle: "acl-prefix"},
		{name: "longest that fits", bundle: strings.Repeat("a", MaxPluginBundleName)},
		{name: "empty", bundle: "", wantErr: ErrBundleNameInvalid},
		{name: "colon is reserved", bundle: "acl:prefix", wantErr: ErrBundleNameInvalid},
		// A bundle name is also the file name its bundle is persisted
		// under, so anything that could leave the directory is refused.
		{name: "path separator", bundle: "../etc/passwd", wantErr: ErrBundleNameInvalid},
		{name: "leading dot", bundle: ".hidden", wantErr: ErrBundleNameInvalid},
		{name: "space", bundle: "acl prefix", wantErr: ErrBundleNameInvalid},
		{name: "dots inside are fine", bundle: "acl.v2_prefix-1"},
		{name: "one byte too long", bundle: strings.Repeat("a", MaxPluginBundleName+1), wantErr: ErrBundleNameTooLong},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePluginBundleName(tt.bundle)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("ValidatePluginBundleName(%q) = %v, want nil", tt.bundle, err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ValidatePluginBundleName(%q) = %v, want %v", tt.bundle, err, tt.wantErr)
			}
		})
	}
}

// A bundle name of the maximum length must survive the fixed-width owner
// buffer unchanged; one byte more must not be accepted in the first place.
func TestBundleTagSurvivesOwnerBuffer(t *testing.T) {
	name := strings.Repeat("b", MaxPluginBundleName)
	tag := AuxOwnerBundleTag(name)
	if len(tag) > auxOwnerTagBytes-1 {
		t.Fatalf("tag is %d bytes, does not fit %d-byte buffer with terminator", len(tag), auxOwnerTagBytes)
	}
	encoded := encodeOwnerTag(tag)
	got, ok := decodeOwnerTag(encoded[:])
	if !ok || got != tag {
		t.Fatalf("round trip gave (%q, %v), want (%q, true)", got, ok, tag)
	}
}

func TestParsePluginOwnerTagBundleForm(t *testing.T) {
	owner, ok, err := ParsePluginOwnerTag(AuxOwnerBundleTag("acl-prefix"))
	if err != nil || !ok {
		t.Fatalf("parse = (%v, %v), want ok", err, ok)
	}
	if !owner.IsBundle() || owner.Bundle != "acl-prefix" {
		t.Fatalf("owner = %+v, want bundle acl-prefix", owner)
	}
}

func TestParsePluginOwnerTagSlotForms(t *testing.T) {
	tests := []struct {
		name    string
		tag     string
		mapType string
		slot    uint32
	}{
		{name: "versioned", tag: AuxOwnerPluginTag("endpoint", 32), mapType: "endpoint", slot: 32},
		{name: "legacy unversioned", tag: "plugin:headend_v4:16", mapType: "headend_v4", slot: 16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, ok, err := ParsePluginOwnerTag(tt.tag)
			if err != nil || !ok {
				t.Fatalf("parse(%q) = (%v, %v), want ok", tt.tag, err, ok)
			}
			if owner.IsBundle() {
				t.Fatalf("owner = %+v, want the slot form", owner)
			}
			if owner.MapType != tt.mapType || owner.Slot != tt.slot {
				t.Fatalf("owner = %+v, want {%s %d}", owner, tt.mapType, tt.slot)
			}
		})
	}
}

// A tag belonging to another owner kind is reported as not-a-plugin rather
// than as an error, so a sweep over a mixed owner map can skip it.
func TestParsePluginOwnerTagIgnoresOtherKinds(t *testing.T) {
	for _, tag := range []string{AuxOwnerBuiltin, string(OwnerRPC), string(OwnerBGPVPN(65000, "1:1"))} {
		owner, ok, err := ParsePluginOwnerTag(tag)
		if err != nil {
			t.Fatalf("parse(%q) errored: %v", tag, err)
		}
		if ok {
			t.Fatalf("parse(%q) claimed the tag as a plugin owner: %+v", tag, owner)
		}
	}
}

func TestParsePluginOwnerTagRejectsEmptyBundleName(t *testing.T) {
	if _, _, err := ParsePluginOwnerTag("plugin:v1:bundle="); err == nil {
		t.Fatal("an empty bundle name must not parse")
	}
}

// Both tag forms canonicalize to the same owner once the resolver knows
// which bundle holds the slot.
func TestCanonicalPluginOwnerUnifiesBothForms(t *testing.T) {
	resolve := func(mapType string, slot uint32) (string, bool) {
		if mapType == "endpoint" && slot == 32 {
			return "acl-prefix", true
		}
		return "", false
	}
	fromBundle, ok, err := CanonicalPluginOwner(AuxOwnerBundleTag("acl-prefix"), resolve)
	if err != nil || !ok {
		t.Fatalf("bundle form: (%v, %v), want ok", err, ok)
	}
	fromSlot, ok, err := CanonicalPluginOwner(AuxOwnerPluginTag("endpoint", 32), resolve)
	if err != nil || !ok {
		t.Fatalf("slot form: (%v, %v), want ok", err, ok)
	}
	if fromBundle != fromSlot {
		t.Fatalf("forms disagree: bundle=%q slot=%q", fromBundle, fromSlot)
	}
}

// A slot nobody currently holds is unresolved, not attributed to whoever
// takes the slot next: the entry is a leftover to sweep.
func TestCanonicalPluginOwnerLeavesUnclaimedSlotUnresolved(t *testing.T) {
	resolve := func(string, uint32) (string, bool) { return "", false }
	got, ok, err := CanonicalPluginOwner(AuxOwnerPluginTag("endpoint", 32), resolve)
	if err != nil {
		t.Fatalf("canonicalize errored: %v", err)
	}
	if ok {
		t.Fatalf("unclaimed slot resolved to %q, want unresolved", got)
	}
}

func TestCanonicalPluginOwnerNilResolver(t *testing.T) {
	// A bundle tag needs no resolver.
	if _, ok, err := CanonicalPluginOwner(AuxOwnerBundleTag("acl-prefix"), nil); err != nil || !ok {
		t.Fatalf("bundle form with nil resolver: (%v, %v), want ok", err, ok)
	}
	// A slot tag cannot be resolved without one.
	if _, ok, err := CanonicalPluginOwner(AuxOwnerPluginTag("endpoint", 32), nil); err != nil || ok {
		t.Fatalf("slot form with nil resolver: (%v, %v), want unresolved", err, ok)
	}
}

func TestSamePluginOwner(t *testing.T) {
	resolve := func(mapType string, slot uint32) (string, bool) {
		switch {
		case mapType == "endpoint" && slot == 32:
			return "acl-prefix", true
		case mapType == "endpoint" && slot == 33:
			return "counter", true
		}
		return "", false
	}
	tests := []struct {
		name string
		a, b string
		want bool
	}{
		{name: "same plugin across forms", a: AuxOwnerBundleTag("acl-prefix"), b: AuxOwnerPluginTag("endpoint", 32), want: true},
		{name: "different plugins", a: AuxOwnerPluginTag("endpoint", 32), b: AuxOwnerPluginTag("endpoint", 33)},
		{name: "unclaimed slot matches nothing", a: AuxOwnerBundleTag("acl-prefix"), b: AuxOwnerPluginTag("endpoint", 99)},
		{name: "non-plugin tags are never equal here", a: AuxOwnerBuiltin, b: AuxOwnerBuiltin},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SamePluginOwner(tt.a, tt.b, resolve); got != tt.want {
				t.Fatalf("SamePluginOwner(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// The entry-owner namespace must accept a plugin tag, so a main-map entry
// written on behalf of a plugin passes the same parse as any other owner.
func TestParseOwnerTagAcceptsPluginBundle(t *testing.T) {
	kind, version, err := ParseOwnerTag(OwnerPluginBundle("acl-prefix"))
	if err != nil {
		t.Fatalf("ParseOwnerTag: %v", err)
	}
	if kind != OwnerKindPlugin {
		t.Fatalf("kind = %q, want %q", kind, OwnerKindPlugin)
	}
	if version != OwnerTagVersion {
		t.Fatalf("version = %q, want %q", version, OwnerTagVersion)
	}
}
