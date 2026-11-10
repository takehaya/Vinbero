;; Declares ABI version 1, the oldest this host admits. Version 2 only adds
;; the VRF of a headend entry, so a version 1 module is still registered.
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "free") (param i32 i32))
  (func (export "handle_events") (param i32 i32) (result i64) (i64.const 0))
  (func (export "vinbero_abi_version") (result i32) (i32.const 1)))
