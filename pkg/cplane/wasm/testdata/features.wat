;; Reads the host feature bitmap through vinbero.input_features on demand.
(module
  (import "vinbero" "input_features" (func $features (result i64)))
  (memory (export "memory") 1)
  (func (export "vinbero_abi_version") (result i32) (i32.const 1))
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "free") (param i32 i32))
  (func (export "handle_events") (param i32 i32) (result i64) (i64.const 0))
  (func (export "read_features") (result i64) (call $features))
)
