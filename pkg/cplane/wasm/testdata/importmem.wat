;; Imports its memory instead of defining one. Refused: the guest must own
;; the region the host writes into.
(module
  (import "env" "memory" (memory 1))
  (func (export "alloc") (param i32) (result i32) (i32.const 0))
  (func (export "free") (param i32 i32))
  (func (export "handle_events") (param i32 i32) (result i64) (i64.const 0)))
