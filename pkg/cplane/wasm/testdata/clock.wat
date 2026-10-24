;; Trap if on_tick and now_monotonic use different clock epochs.
(module
  (import "vinbero" "now_monotonic" (func $now (result i64)))
  (memory (export "memory") 1)
  (func (export "vinbero_abi_version") (result i32) (i32.const 1))
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "free") (param i32 i32))
  (func (export "handle_events") (param i32 i32) (result i64) (i64.const 0))
  (func (export "on_tick") (param $tick i64)
    (local $delta i64)
    (local.set $delta (i64.sub (local.get $tick) (call $now)))
    (if (i32.or
      (i64.gt_s (local.get $delta) (i64.const 1000000000))
      (i64.lt_s (local.get $delta) (i64.const -1000000000)))
      (then unreachable)))
)
