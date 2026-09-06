;; Imports a host function that does not exist in this ABI version.
(module
  (import "vinbero" "delete_everything" (func $x (param i32)))
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 0))
  (func (export "free") (param i32 i32))
  (func (export "handle_events") (param i32 i32) (result i64) (i64.const 0))
  ;; The ABI this module was built against; the host refuses a mismatch.
  (func (export "vinbero_abi_version") (result i32) (i32.const 1))
)
