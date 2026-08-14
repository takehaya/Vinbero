;; Missing alloc, so the host could never hand it a buffer.
(module
  (memory (export "memory") 1)
  (func (export "free") (param i32 i32))
  (func (export "handle_events") (param i32 i32) (result i64) (i64.const 0)))
