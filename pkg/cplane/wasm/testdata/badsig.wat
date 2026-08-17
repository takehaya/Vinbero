;; handle_events returns i32 where the ABI says i64. Linking it anyway
;; would misread the returned (ptr, len) pair.
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 0))
  (func (export "free") (param i32 i32))
  (func (export "handle_events") (param i32 i32) (result i32) (i32.const 0)))
