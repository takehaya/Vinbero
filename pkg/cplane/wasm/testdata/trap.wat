;; Traps inside handle_events (unreachable), the WebAssembly equivalent of
;; a panic. The host must report it without taking the daemon down.
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "free") (param i32 i32))
  (func (export "handle_events") (param i32 i32) (result i64)
    (unreachable)))
