;; Loops forever in the WebAssembly start section, which the spec has the
;; runtime run during instantiation. WithStartFunctions() does not cover
;; it -- that only clears the exported _start -- so this is guest code the
;; host executes before it has called anything, and the call budget has to
;; apply to instantiation itself or registration never returns.
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "free") (param i32 i32))
  (func (export "handle_events") (param i32 i32) (result i64) (i64.const 0))
  (func (export "vinbero_abi_version") (result i32) (i32.const 1))
  (func $spin (loop $forever (br $forever)))
  (start $spin)
)
