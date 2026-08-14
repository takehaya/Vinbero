;; A plugin that declares its desired set from the periodic callback rather
;; than from an event, so a test can tell whether the tick is driven at all
;; -- the declaration reaching the data plane with no event delivered is
;; the observable fact.
(module
  (import "vinbero" "apply_begin" (func $begin (param i32) (result i64)))
  (import "vinbero" "apply_put" (func $put (param i64 i32 i32) (result i32)))
  (import "vinbero" "apply_commit" (func $commit (param i64) (result i32)))
  (import "vinbero" "apply_abort" (func $abort (param i64)))

  (memory (export "memory") 1)
  (global $bump (mut i32) (i32.const 1024))

  ;; A pre-encoded PluginApplyChunk with one headend entry, as in
  ;; declare.wat: 10.99.0.0/24 via fd00:2::100.
  (data (i32.const 16)
    "\0a\1b\0a\0c\31\30\2e\39\39\2e\30\2e\30\2f\32\34\12\0b\66\64\30\30\3a\32\3a\3a\31\30\30")

  (func (export "alloc") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $size)))
    (local.get $ptr))

  (func (export "free") (param i32 i32))

  ;; Events are ignored; only the tick declares.
  (func (export "handle_events") (param i32 i32) (result i64) (i64.const 0))

  (func (export "on_tick") (param $now i64)
    (local $gen i64)
    (local.set $gen (call $begin (i32.const 1)))
    (if (i64.eqz (local.get $gen)) (then (return)))
    (if (i32.ne (call $put (local.get $gen) (i32.const 16) (i32.const 29)) (i32.const 0))
      (then
        (call $abort (local.get $gen))
        (return)))
    (drop (call $commit (local.get $gen))))

  ;; The ABI this module was built against; the host refuses a mismatch.
  (func (export "vinbero_abi_version") (result i32) (i32.const 1)))
