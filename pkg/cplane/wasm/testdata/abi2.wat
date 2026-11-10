;; Declares ABI version 2, the current one, which carries
;; the VRF of a headend entry.
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "free") (param i32 i32))
  (func (export "handle_events") (param i32 i32) (result i64) (i64.const 0))
  (func (export "vinbero_abi_version") (result i32) (i32.const 2)))
