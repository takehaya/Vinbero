;; A plugin that declares a fixed desired set on every event batch.
;;
;; The set it declares is a pre-encoded PluginApplyChunk carrying one
;; headend entry (10.99.0.0/24 via fd00:2::100), embedded as a data
;; segment. Encoding protobuf in WebAssembly text by hand would test the
;; fixture rather than the host, and what the manager tests care about is
;; the begin / put / commit sequence reaching the capability layer with
;; bytes the host can decode.
(module
  (import "vinbero" "apply_begin" (func $begin (param i32) (result i64)))
  (import "vinbero" "apply_put" (func $put (param i64 i32 i32) (result i32)))
  (import "vinbero" "apply_commit" (func $commit (param i64) (result i32)))
  (import "vinbero" "apply_abort" (func $abort (param i64)))

  (memory (export "memory") 1)
  (global $bump (mut i32) (i32.const 1024))

  ;; The serialized chunk lives at offset 16, out of the allocator's way.
  (data (i32.const 16)
    "\0a\1b\0a\0c\31\30\2e\39\39\2e\30\2e\30\2f\32\34\12\0b\66\64\30\30\3a\32\3a\3a\31\30\30")

  (func (export "alloc") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $size)))
    (local.get $ptr))

  (func (export "free") (param i32 i32))

  (func (export "handle_events") (param $ptr i32) (param $len i32) (result i64)
    (local $gen i64)
    ;; kind 1 is PLUGIN_APPLY_KIND_HEADEND_V4.
    (local.set $gen (call $begin (i32.const 1)))
    (if (i64.eqz (local.get $gen)) (then (return (i64.const 0))))
    (if (i32.ne (call $put (local.get $gen) (i32.const 16) (i32.const 29)) (i32.const 0))
      (then
        (call $abort (local.get $gen))
        (return (i64.const 0))))
    (drop (call $commit (local.get $gen)))
    (i64.const 0))
  ;; The ABI this module was built against; the host refuses a mismatch.
  (func (export "vinbero_abi_version") (result i32) (i32.const 1))
)
