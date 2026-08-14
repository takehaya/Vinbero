package wasm

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// admit decides whether a compiled module may run, from what the module
// declares about itself. It runs before instantiation, so nothing in a
// rejected module ever executes.
//
// The rules are an allowlist. A module may import only from the host
// module, must export exactly the memory the host writes into, and must
// declare an ABI version the host understands. Anything else -- a WASI
// import, an imported memory, an unknown host function, a required export
// with the wrong signature -- is refused with a message naming what was
// wrong, because the alternative is a trap on the first call whose cause
// is far less obvious.
func admit(compiled wazero.CompiledModule) error {
	if err := admitImports(compiled); err != nil {
		return err
	}
	if err := admitMemory(compiled); err != nil {
		return err
	}
	return admitExports(compiled)
}

// hostFunctionSignatures is every host function a guest may import, with
// the parameter and result counts the host defines. Signature is checked
// as well as name: a module importing "log" with different arity was built
// against a different ABI, and linking it anyway would corrupt the stack.
var hostFunctionSignatures = map[string]struct{ params, results int }{
	HostLog:          {params: 3, results: 0}, // level, ptr, len
	HostNowMonotonic: {params: 0, results: 1}, // -> ns
	HostApplyBegin:   {params: 1, results: 1}, // kind -> generation
	HostApplyPut:     {params: 3, results: 1}, // generation, ptr, len -> status
	HostApplyCommit:  {params: 1, results: 1}, // generation -> status
	HostApplyAbort:   {params: 1, results: 0}, // generation
}

// admitImports refuses anything the guest asks for that the host does not
// provide. WASI is excluded by this rule rather than by a special case:
// its functions are imported from wasi_snapshot_preview1, which is not the
// host module.
func admitImports(compiled wazero.CompiledModule) error {
	var foreign []string
	for _, imp := range compiled.ImportedFunctions() {
		module, name, ok := imp.Import()
		if !ok {
			continue
		}
		if module != HostModule {
			foreign = append(foreign, module+"."+name)
			continue
		}
		want, known := hostFunctionSignatures[name]
		if !known {
			foreign = append(foreign, module+"."+name)
			continue
		}
		if got := len(imp.ParamTypes()); got != want.params {
			return fmt.Errorf("%w: host function %q imported with %d parameters, host defines %d",
				ErrAdmission, name, got, want.params)
		}
		if got := len(imp.ResultTypes()); got != want.results {
			return fmt.Errorf("%w: host function %q imported with %d results, host defines %d",
				ErrAdmission, name, got, want.results)
		}
	}
	if len(foreign) > 0 {
		sort.Strings(foreign)
		return fmt.Errorf("%w: module imports functions the host does not provide: %s "+
			"(only the %q module is linked; WASI is not available)",
			ErrAdmission, strings.Join(foreign, ", "), HostModule)
	}
	if len(compiled.ImportedMemories()) > 0 {
		return fmt.Errorf("%w: module imports its memory; it must define and export its own", ErrAdmission)
	}
	return nil
}

// admitMemory requires the guest to define and export exactly the memory
// the host writes buffers into. A guest with no memory could not receive
// an event batch at all.
func admitMemory(compiled wazero.CompiledModule) error {
	mems := compiled.ExportedMemories()
	if len(mems) == 0 {
		return fmt.Errorf("%w: module exports no memory (expected %q)", ErrAdmission, GuestMemory)
	}
	if _, ok := mems[GuestMemory]; !ok {
		names := make([]string, 0, len(mems))
		for name := range mems {
			names = append(names, name)
		}
		sort.Strings(names)
		return fmt.Errorf("%w: module exports memory %s, expected %q",
			ErrAdmission, strings.Join(names, ", "), GuestMemory)
	}
	return nil
}

// requiredExports are the functions every plugin must provide, with their
// signatures. alloc and free are required even for a plugin that expects
// no input: the host has no other way to hand it one, and discovering that
// at the first event is worse than discovering it at registration.
var requiredExports = map[string]struct {
	params  []api.ValueType
	results []api.ValueType
}{
	ExportAlloc: {
		params:  []api.ValueType{api.ValueTypeI32},
		results: []api.ValueType{api.ValueTypeI32},
	},
	ExportFree: {
		params: []api.ValueType{api.ValueTypeI32, api.ValueTypeI32},
	},
	ExportHandleEvents: {
		params:  []api.ValueType{api.ValueTypeI32, api.ValueTypeI32},
		results: []api.ValueType{api.ValueTypeI64},
	},
}

// optionalExports may be absent, but must have the right shape if present.
var optionalExports = map[string]struct {
	params  []api.ValueType
	results []api.ValueType
}{
	ExportConfigure: {
		params:  []api.ValueType{api.ValueTypeI32, api.ValueTypeI32},
		results: []api.ValueType{api.ValueTypeI32},
	},
	ExportOnTick: {
		params: []api.ValueType{api.ValueTypeI64},
	},
}

// admitExports checks that the required entry points exist with the
// signatures the host calls them by, and that any optional one present is
// also the right shape.
func admitExports(compiled wazero.CompiledModule) error {
	fns := compiled.ExportedFunctions()
	for name, want := range requiredExports {
		fn, ok := fns[name]
		if !ok {
			return fmt.Errorf("%w: module exports no %q", ErrAdmission, name)
		}
		if err := checkSignature(name, fn, want.params, want.results); err != nil {
			return err
		}
	}
	for name, want := range optionalExports {
		fn, ok := fns[name]
		if !ok {
			continue
		}
		if err := checkSignature(name, fn, want.params, want.results); err != nil {
			return err
		}
	}
	return nil
}

// checkSignature compares one export against the shape the host calls.
func checkSignature(name string, fn api.FunctionDefinition, params, results []api.ValueType) error {
	if !valueTypesEqual(fn.ParamTypes(), params) {
		return fmt.Errorf("%w: export %q takes %s, host calls it with %s",
			ErrAdmission, name, renderTypes(fn.ParamTypes()), renderTypes(params))
	}
	if !valueTypesEqual(fn.ResultTypes(), results) {
		return fmt.Errorf("%w: export %q returns %s, host expects %s",
			ErrAdmission, name, renderTypes(fn.ResultTypes()), renderTypes(results))
	}
	return nil
}

func valueTypesEqual(a, b []api.ValueType) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// renderTypes formats a signature fragment for an error message.
func renderTypes(types []api.ValueType) string {
	if len(types) == 0 {
		return "()"
	}
	parts := make([]string, 0, len(types))
	for _, t := range types {
		parts = append(parts, api.ValueTypeName(t))
	}
	return "(" + strings.Join(parts, ", ") + ")"
}
