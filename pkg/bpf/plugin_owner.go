package bpf

import (
	"errors"
	"fmt"
	"strings"
)

// Plugin state (aux indices, owned map entries, and the main-map entries a
// control-plane plugin writes) is attributed to its plugin with an owner
// tag. Two shapes exist:
//
//   - slot form, "plugin:v1:<mapType>:<slot>" (AuxOwnerPluginTag) -- the
//     original, keyed by the PROG_ARRAY slot a data-plane plugin occupies.
//   - bundle form, "plugin:v1:bundle=<name>" (AuxOwnerBundleTag) -- keyed by
//     the name a plugin was registered under, so one identity covers a
//     plugin's data-plane and control-plane halves and any slot it holds.
//
// Both remain readable. A slot is a finite, reusable resource, so a slot tag
// alone cannot say which plugin wrote an entry once the slot has been handed
// to a different plugin; the bundle form exists to make that attribution
// stable. Callers that compare owners must run both shapes through
// CanonicalPluginOwner with a resolver that knows the current slot-to-bundle
// mapping, rather than comparing raw strings.

// pluginBundlePrefix marks the bundle-keyed owner form inside a plugin tag.
const pluginBundlePrefix = "bundle="

// MaxPluginBundleName is the longest bundle name that survives persistence.
// Owner tags are stored in a fixed 64-byte buffer whose last byte is the
// null terminator, so the name must fit in what remains after the
// "plugin:<version>:bundle=" prefix. A longer name would be truncated on
// write and silently compare unequal on read, taking the ownership check
// down with it.
var MaxPluginBundleName = auxOwnerTagBytes - 1 - len(AuxOwnerKindPlugin+":"+AuxOwnerVersion+":"+pluginBundlePrefix)

// ErrBundleNameTooLong is returned when a bundle name would not survive the
// fixed-width owner buffer.
var ErrBundleNameTooLong = errors.New("plugin bundle name too long for owner tag")

// ErrBundleNameInvalid is returned for a bundle name that is empty or holds
// a character the tag format reserves.
var ErrBundleNameInvalid = errors.New("invalid plugin bundle name")

// ValidatePluginBundleName checks that name can be rendered into an owner
// tag and read back unchanged, and that it is safe to use as a file name.
//
// The alphabet is an allowlist rather than a list of rejections. A bundle
// name is both a field inside a colon-separated owner tag and the name of
// the file a bundle is persisted under, so anything outside this set is
// either ambiguous in the tag or an escape from the directory: a name of
// "../../etc/cron.d/x" would otherwise write wherever it liked. A leading
// dot is refused for the same reason.
func ValidatePluginBundleName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty", ErrBundleNameInvalid)
	}
	if len(name) > MaxPluginBundleName {
		return fmt.Errorf("%w: %q is %d bytes, limit %d", ErrBundleNameTooLong, name, len(name), MaxPluginBundleName)
	}
	if name[0] == '.' {
		return fmt.Errorf("%w: %q starts with a dot", ErrBundleNameInvalid, name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("%w: %q may use only letters, digits, '-', '_' and '.'",
				ErrBundleNameInvalid, name)
		}
	}
	return nil
}

// AuxOwnerBundleTag renders the bundle-keyed plugin owner tag. The caller
// should have run ValidatePluginBundleName first; an invalid name is
// rendered as-is here so this stays a pure formatter, and the tag simply
// fails to round-trip.
func AuxOwnerBundleTag(bundle string) string {
	return fmt.Sprintf("%s:%s:%s%s", AuxOwnerKindPlugin, AuxOwnerVersion, pluginBundlePrefix, bundle)
}

// OwnerPluginBundle is the entry-owner form of AuxOwnerBundleTag, for the
// main maps (sid_function, headend v4 / v6) a control-plane plugin writes.
// Entry owners and aux owners share a byte representation, so the two
// namespaces render a plugin identity identically.
func OwnerPluginBundle(bundle string) OwnerTag {
	return OwnerTag(AuxOwnerBundleTag(bundle))
}

// PluginOwner is a parsed plugin owner tag. Exactly one of the two forms is
// populated: Bundle for the bundle-keyed form, or MapType and Slot for the
// slot-keyed one.
type PluginOwner struct {
	Bundle  string
	MapType string
	Slot    uint32
}

// IsBundle reports whether the tag was written in the bundle-keyed form.
func (p PluginOwner) IsBundle() bool { return p.Bundle != "" }

// ParsePluginOwnerTag splits a plugin owner tag of either form. Tags of
// another kind (builtin, rpc, bgp) return ok=false rather than an error, so
// a caller sweeping a mixed owner map can skip them without special-casing
// every other kind.
func ParsePluginOwnerTag(tag string) (owner PluginOwner, ok bool, err error) {
	if !strings.HasPrefix(tag, AuxOwnerKindPlugin+":") {
		return PluginOwner{}, false, nil
	}
	parts := strings.Split(tag, ":")
	// Bundle form: plugin:<version>:bundle=<name> -> 3 segments, the last
	// carrying the marker. Checked before the slot form because the legacy
	// slot form has the same segment count.
	if len(parts) == 3 && strings.HasPrefix(parts[1], "v") && strings.HasPrefix(parts[2], pluginBundlePrefix) {
		name := strings.TrimPrefix(parts[2], pluginBundlePrefix)
		if name == "" {
			return PluginOwner{}, false, fmt.Errorf("malformed plugin owner tag %q (empty bundle name)", tag)
		}
		return PluginOwner{Bundle: name}, true, nil
	}
	kind, mapType, slot, perr := ParseAuxOwnerTag(tag)
	if perr != nil {
		return PluginOwner{}, false, perr
	}
	if kind != AuxOwnerKindPlugin {
		return PluginOwner{}, false, nil
	}
	return PluginOwner{MapType: mapType, Slot: slot}, true, nil
}

// BundleResolver reports which bundle currently holds a plugin slot. The
// plugin registry implements it; ok=false means the slot is unclaimed, so a
// slot-keyed tag found there is a leftover from a plugin that has since
// unregistered.
type BundleResolver func(mapType string, slot uint32) (bundle string, ok bool)

// CanonicalPluginOwner maps either tag form onto the bundle-keyed form, so
// entries written before the bundle form existed compare equal to entries
// written after it. A slot-keyed tag whose slot resolve returns ok=false is
// reported as unresolved (ok=false): the slot has no current owner, so the
// entry is a leftover to sweep rather than state belonging to whoever holds
// the slot next. Passing a nil resolver leaves every slot unresolved.
//
// Tags of another kind return ok=false with a nil error, matching
// ParsePluginOwnerTag.
func CanonicalPluginOwner(tag string, resolve BundleResolver) (canonical OwnerTag, ok bool, err error) {
	owner, isPlugin, err := ParsePluginOwnerTag(tag)
	if err != nil || !isPlugin {
		return "", false, err
	}
	if owner.IsBundle() {
		return OwnerPluginBundle(owner.Bundle), true, nil
	}
	if resolve == nil {
		return "", false, nil
	}
	bundle, found := resolve(owner.MapType, owner.Slot)
	if !found {
		return "", false, nil
	}
	return OwnerPluginBundle(bundle), true, nil
}

// SamePluginOwner reports whether two owner tags name the same plugin, with
// either tag written in either form. Non-plugin tags are never equal here;
// compare those directly.
func SamePluginOwner(a, b string, resolve BundleResolver) bool {
	ca, aok, err := CanonicalPluginOwner(a, resolve)
	if err != nil || !aok {
		return false
	}
	cb, bok, err := CanonicalPluginOwner(b, resolve)
	if err != nil || !bok {
		return false
	}
	return ca == cb
}
