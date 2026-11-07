;; Reads the registration's grants through vinbero.grants on demand.
(module
  (import "vinbero" "grants" (func $grants (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "vinbero_abi_version") (result i32) (i32.const 1))
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "free") (param i32 i32))
  (func (export "handle_events") (param i32 i32) (result i64) (i64.const 0))
  (func (export "read_grants") (param $ptr i32) (param $cap i32) (result i32)
    (call $grants (local.get $ptr) (local.get $cap)))
)
