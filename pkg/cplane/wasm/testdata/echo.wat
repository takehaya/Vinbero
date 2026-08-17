;; Minimal conforming plugin.
;;
;; It implements the whole required ABI with a bump allocator: alloc hands
;; out ever-increasing offsets, free is a no-op, and handle_events copies
;; the batch it was given into a fresh region and returns it as its status.
;; That round trip is what lets a test assert the host really moved bytes
;; both ways rather than just calling a function.
(module
  (import "vinbero" "log" (func $log (param i32 i32 i32)))
  (import "vinbero" "now_monotonic" (func $now (result i64)))

  (memory (export "memory") 1)
  (global $bump (mut i32) (i32.const 1024))
  (global $config_len (mut i32) (i32.const 0))

  (func (export "alloc") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $size)))
    (local.get $ptr))

  (func (export "free") (param i32 i32))

  ;; Records how many config bytes arrived, then accepts.
  (func (export "configure") (param $ptr i32) (param $len i32) (result i32)
    (global.set $config_len (local.get $len))
    (i32.const 0))

  ;; Copies the batch into a new region and returns (ptr << 32) | len.
  (func (export "handle_events") (param $ptr i32) (param $len i32) (result i64)
    (local $out i32)
    (local $i i32)
    (if (i32.eqz (local.get $len)) (then (return (i64.const 0))))
    (local.set $out (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $len)))
    (local.set $i (i32.const 0))
    (block $done
      (loop $copy
        (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
        (i32.store8
          (i32.add (local.get $out) (local.get $i))
          (i32.load8_u (i32.add (local.get $ptr) (local.get $i))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $copy)))
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $out)) (i64.const 32))
      (i64.extend_i32_u (local.get $len))))

  (func (export "on_tick") (param $now i64))

  ;; Exercises the log and clock host functions on demand.
  (func (export "emit_log") (param $ptr i32) (param $len i32)
    (call $log (i32.const 1) (local.get $ptr) (local.get $len)))
  (func (export "read_clock") (result i64) (call $now))
  (func (export "config_len") (result i32) (global.get $config_len)))
