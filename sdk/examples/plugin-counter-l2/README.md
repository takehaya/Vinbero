# plugin-counter-l2

L2 headend plugin の最小例 (Vinbero SDK v3+)。`headend_l2_progs` のプラグインスロット
(16-31 の範囲、慣例的に 16) に register され、BD forwarding が「remote peer に encap
する」と決定した直後 / no-BD entry の encap 経路の直前に呼ばれる。

## 何をするか

- `tctx->headend.bd_id` をキーに per-CPU counter map を加算する
- 続けて `bpf_tail_call(ctx, &headend_l2_progs, SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2)`
  で built-in `do_h_encaps_l2` (slot 3) に dispatch を戻し、通常の encap path を継続

## 使い方

```bash
# Build
make

# Register (slot 16 = HEADEND_PLUGIN_BASE)
vinbero plugin register --type headend_l2 --index 16 \
    --prog plugin.o --program plugin_counter_l2

# Wire HL2 entry to use slot 16 instead of the built-in (= sid create flow
# is not applicable for headend_l2; instead, the dispatcher in vinbero
# selects the plugin slot when sid_function_entry.action is set).
# NOTE: hooking by slot for L2 headend is automatic once registered —
# any traffic that reaches the no-BD path or remote-peer encap will run
# through the plugin chain. (Future: per-HL2-entry plugin slot selection.)

# Observe
bpftool map dump pinned /sys/fs/bpf/plugin_counter_l2_map
```

## SDK helper の例

このサンプルは `bd_id` だけ参照しているが、`vinbero/headend_l2_helpers.h` には
以下も用意されている (実装は `plugin-custom-sh` 例を参照):

- `vinbero_l2_vlan_id(ctx)` — packet header から VLAN ID
- `vinbero_l2_frame_len(ctx)` — pre-encap の inner L2 frame 長
- `vinbero_l2_lookup_esi(ifindex, vlan_id, out_esi)` — 自 AC の source ESI
- `vinbero_l2_dst_peer_esi(ctx, bd_id, out_esi)` — dst peer の ESI (FDB → bd_peer_l2_ext_map)
- `vinbero_l2_is_df_for_esi(bd_id, esi)` — 自 PE が DF か

## 仕様メモ

- plugin は **post-BD-forwarding (HOOK BETA)** に位置する。BUM / dst==LOCAL
  経路には呼ばれない。
- aux (PluginAux) は Phase 2 では未対応。per-instance config を持ちたければ
  plugin-owned map を使う (このサンプルが counter を持っているのと同じ要領)。
- `tctx->headend` は L3 plugin と同じ union variant。`tctx->l3_offset` は L2
  では使用しない (dispatcher が 0 を書く)。
