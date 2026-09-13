package wasm

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// admit decides whether a compiled module may run, from what the module
// declares about itself. It runs before instantiation, so nothing in a
// rejected module ever executes.
//
// The rules are an allowlist. A module may import only from vinbero and
// WASI preview 1, must export the memory the host writes into, and must
// declare an ABI version the host understands. Anything else -- a foreign
// import, an imported memory, an unknown host function, a required export
// with the wrong signature -- is refused with a message naming what was
// wrong, because the alternative is a trap on the first call whose cause
// is far less obvious.
func admit(compiled wazero.CompiledModule, caps Capabilities, wasi api.Module) error {
	if err := admitImports(compiled, wasi); err != nil {
		return err
	}
	if err := admitCapabilities(compiled, caps); err != nil {
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
// The types are compared, not just the counts. wazero would refuse a
// mismatched import at link time anyway, but the error it raises then is
// not an ErrAdmission, so a module the caller can fix would be reported as
// a host failure instead of a bad module.
var hostFunctionSignatures = map[string]struct{ params, results []api.ValueType }{
	HostLog: { // level, ptr, len
		params: []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
	},
	HostNowMonotonic: { // -> ns
		results: []api.ValueType{api.ValueTypeI64},
	},
	HostApplyBegin: { // kind -> generation
		params:  []api.ValueType{api.ValueTypeI32},
		results: []api.ValueType{api.ValueTypeI64},
	},
	HostApplyPut: { // generation, ptr, len -> status
		params:  []api.ValueType{api.ValueTypeI64, api.ValueTypeI32, api.ValueTypeI32},
		results: []api.ValueType{api.ValueTypeI32},
	},
	HostApplyCommit: { // generation -> status
		params:  []api.ValueType{api.ValueTypeI64},
		results: []api.ValueType{api.ValueTypeI32},
	},
	HostApplyAbort: { // generation
		params: []api.ValueType{api.ValueTypeI64},
	},
}

// admitImports refuses anything the guest asks for that the host does not
// provide. WASI signatures come from the linked implementation so admission
// cannot drift from wazero. Resource access is restricted by ModuleConfig.
func admitImports(compiled wazero.CompiledModule, wasi api.Module) error {
	var foreign []string
	for _, imp := range compiled.ImportedFunctions() {
		module, name, ok := imp.Import()
		if !ok {
			continue
		}
		if module == wasi_snapshot_preview1.ModuleName {
			fn, known := wasi.ExportedFunctionDefinitions()[name]
			if !known {
				foreign = append(foreign, module+"."+name)
				continue
			}
			if !valueTypesEqual(imp.ParamTypes(), fn.ParamTypes()) || !valueTypesEqual(imp.ResultTypes(), fn.ResultTypes()) {
				return fmt.Errorf("%w: WASI function %q imported with wrong signature", ErrAdmission, name)
			}
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
		if !valueTypesEqual(imp.ParamTypes(), want.params) {
			return fmt.Errorf("%w: host function %q imported as taking %s, host defines %s",
				ErrAdmission, name, renderTypes(imp.ParamTypes()), renderTypes(want.params))
		}
		if !valueTypesEqual(imp.ResultTypes(), want.results) {
			return fmt.Errorf("%w: host function %q imported as returning %s, host defines %s",
				ErrAdmission, name, renderTypes(imp.ResultTypes()), renderTypes(want.results))
		}
	}
	if len(foreign) > 0 {
		sort.Strings(foreign)
		return fmt.Errorf("%w: module imports functions the host does not provide: %s "+
			"(only %q and %q are linked)",
			ErrAdmission, strings.Join(foreign, ", "), HostModule, wasi_snapshot_preview1.ModuleName)
	}
	if len(compiled.ImportedMemories()) > 0 {
		return fmt.Errorf("%w: module imports its memory; it must define and export its own", ErrAdmission)
	}
	return nil
}

// admitCapabilities refuses a module that imports a host function its
// granted capabilities do not cover.
//
// The link step would refuse it too, by simply not providing the function,
// but the error an operator sees then is about a missing import rather
// than about a capability they forgot to grant.
func admitCapabilities(compiled wazero.CompiledModule, caps Capabilities) error {
	var imported []string
	for _, imp := range compiled.ImportedFunctions() {
		module, name, ok := imp.Import()
		if !ok || module != HostModule {
			continue
		}
		imported = append(imported, name)
	}
	return caps.checkImports(imported)
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
	ExportABIVersion: {
		results: []api.ValueType{api.ValueTypeI32},
	},
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
	// The host calls the reactor initializer with no arguments. Without an
	// entry here a module exporting it under a different shape passes
	// admission and then fails at instantiation, which reports a caller's
	// bad module as an internal error.
	ExportInitialize: {},
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
