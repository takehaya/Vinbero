;; Exports no memory, so the host has nowhere to put an event batch.
(module
  (func (export "alloc") (param i32) (result i32) (i32.const 0))
  (func (export "free") (param i32 i32))
  (func (export "handle_events") (param i32 i32) (result i64) (i64.const 0)))
