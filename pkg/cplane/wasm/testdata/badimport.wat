;; Imports a host function under the right name and the right number of
;; parameters, but the wrong types: apply_begin takes an i32 kind and
;; returns an i64 generation. Admission has to compare the types, or this
;; reaches wazero's linker and is reported as a host failure rather than
;; as the bad module it is.
(module
  (import "vinbero" "apply_begin" (func $begin (param i64) (result i64)))
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "free") (param i32 i32))
  (func (export "handle_events") (param i32 i32) (result i64) (i64.const 0))
  (func (export "vinbero_abi_version") (result i32) (i32.const 1))
)
