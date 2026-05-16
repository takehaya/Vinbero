package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// expectedMapValueTypes pins BTF value-type names for shared maps a plugin
// may declare. If the plugin's declaration uses a different struct type name
// (e.g. an outdated SDK copy), the replacement at load time would silently
// reinterpret memory. Catch that at validation time instead.
//
// Only maps exposed via GetSharedReadOnlyMaps / GetSharedReadWriteMaps are
// listed. Maps absent from the plugin ELF are fine; plugins only replace what
// they declare.
var expectedMapValueTypes = map[string]string{
	"sid_function_map":      "sid_function_entry",
	"sid_aux_map":           "sid_aux_entry",
	"headend_v4_map":        "headend_entry",
	"headend_v6_map":        "headend_entry",
	"headend_l2_map":        "headend_entry",
	"fdb_map":               "fdb_entry",
	"bd_peer_map":           "headend_entry",
	"bd_peer_reverse_map":   "bd_peer_reverse_val",
	"dx2v_map":              "dx2v_entry",
	"scratch_map":           "scratch_buf",
	"tailcall_ctx_map":      "tailcall_ctx",
}

// validatePluginMapTypes checks that every shared map declared by the plugin
// ELF carries a BTF value type whose name matches the vinbero-side struct.
// Stripped ELFs (no BTF) are allowed through — validation falls back to the
// asm-level checks in ValidatePluginProgram.
func validatePluginMapTypes(spec *ebpf.CollectionSpec) error {
	for name, expected := range expectedMapValueTypes {
		ms, ok := spec.Maps[name]
		if !ok {
			continue
		}
		if ms.Value == nil {
			continue
		}
		got := mapValueTypeName(ms.Value)
		if got == "" {
			continue
		}
		if got != expected {
			return fmt.Errorf(
				"plugin map %q declares value type %q but vinbero expects %q; "+
					"update your SDK headers (sdk/c/include/vinbero/) or remove "+
					"the map declaration to use the vinbero-provided map",
				name, got, expected,
			)
		}
	}
	return nil
}

// mapValueTypeName returns the struct/union name of a BTF type, unwrapping
// typedefs. Returns "" for anonymous or non-composite types (which we
// cannot meaningfully compare against a name-based expectation).
//
// The depth bound guards against malformed BTF with a cyclic typedef chain;
// real type chains are a handful of layers deep at most.
func mapValueTypeName(t btf.Type) string {
	for range 32 {
		switch v := t.(type) {
		case *btf.Typedef:
			t = v.Type
		case *btf.Const:
			t = v.Type
		case *btf.Volatile:
			t = v.Type
		case *btf.Struct:
			return v.Name
		case *btf.Union:
			return v.Name
		default:
			return ""
		}
	}
	return ""
}
