;; Exports the reactor initializer with arguments the host does not pass.
;; Admission must refuse it: the host calls _initialize with none, so a
;; module accepted here would fail at instantiation and be reported as an
;; internal error instead of a bad module.
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "free") (param i32 i32))
  (func (export "handle_events") (param i32 i32) (result i64) (i64.const 0))
  (func (export "vinbero_abi_version") (result i32) (i32.const 1))
  (func (export "_initialize") (param i32))
)
