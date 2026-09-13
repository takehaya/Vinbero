;; Loops forever in handle_events, to exercise the call budget. wazero has
;; no fuel metering, so the only way out is cancelling the context, which
;; closes the module -- the timeout costs the instance, not just the call.
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "free") (param i32 i32))
  (func (export "handle_events") (param i32 i32) (result i64)
    (loop $forever (br $forever))
    (i64.const 0))
  ;; The ABI this module was built against; the host refuses a mismatch.
  (func (export "vinbero_abi_version") (result i32) (i32.const 1))
)
