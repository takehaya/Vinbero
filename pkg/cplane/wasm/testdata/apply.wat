;; Drives the desired-set transaction host functions, so a test can assert
;; the begin / put / commit sequence reaches the capability layer.
(module
  (import "vinbero" "apply_begin" (func $begin (param i32) (result i64)))
  (import "vinbero" "apply_put" (func $put (param i64 i32 i32) (result i32)))
  (import "vinbero" "apply_commit" (func $commit (param i64) (result i32)))
  (import "vinbero" "apply_abort" (func $abort (param i64)))

  (memory (export "memory") 1)
  (global $bump (mut i32) (i32.const 1024))

  (func (export "alloc") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $size)))
    (local.get $ptr))
  (func (export "free") (param i32 i32))

  ;; Declares the batch it was handed as a one-chunk desired set.
  (func (export "handle_events") (param $ptr i32) (param $len i32) (result i64)
    (local $gen i64)
    (local.set $gen (call $begin (i32.const 0)))
    (if (i64.eqz (local.get $gen)) (then (return (i64.const 0))))
    (if (i32.ne (call $put (local.get $gen) (local.get $ptr) (local.get $len)) (i32.const 0))
      (then
        (call $abort (local.get $gen))
        (return (i64.const 0))))
    (drop (call $commit (local.get $gen)))
    (i64.const 0))

  ;; Opens a transaction and walks away, for the abort-on-drop test.
  (func (export "begin_only") (result i64) (call $begin (i32.const 0)))
  ;; The ABI this module was built against; the host refuses a mismatch.
  (func (export "vinbero_abi_version") (result i32) (i32.const 1))
)
