# plugin-custom-sh

EVPN multi-homing reference: TX-side custom Split-Horizon filter. Headend L2 plugin
(`headend_l2` slot, Vinbero SDK v3+) が src AC の ESI と dst peer の ESI を比較し、
両方が同じ非ゼロ ESI のとき frame を drop する。Built-in の RFC 7432 §8.3 SH
(`NON_DF_DROP` 経路、RX 側) に加えて TX 側で stricter rule を適用するのが用途。

## SDK helper の使い方

`vinbero/headend_l2_helpers.h` の helper を 2 段引きで使用:

```c
__u8 src_esi[ESI_LEN], dst_esi[ESI_LEN];
vinbero_l2_lookup_esi(ifindex, vlan_id, src_esi);   // local AC の ESI
vinbero_l2_dst_peer_esi(ctx, bd_id, dst_esi);       // dst peer の ESI (FDB → bd_peer_l2_ext_map)
```

両方が non-zero でかつ一致 → drop。それ以外は
`bpf_tail_call(ctx, &headend_l2_progs, SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2)`
で built-in encap に戻す。

## ビルド + 登録

```bash
make
vinbero plugin register --type headend_l2 --index 17 \
    --prog plugin.o --program plugin_custom_sh
```

## 観測

Plugin-owned map は bpffs に pin されないので、`bpftool map show` で ID を
取得して dump する:

```bash
# Plugin が drop した frame の per-BD カウント (PERCPU_HASH)
MAP_ID=$(sudo bpftool map show \
    | awk '/name plugin_custom_sh_drops/ { sub(":","",$1); print $1; exit }')
sudo bpftool map dump id "$MAP_ID"

# Vinbero の組込み NON_DF_DROP カウンタとの比較
vinbero stats show
```

## 制約

- HOOK BETA (post-BD-forwarding) のみ。`dst==LOCAL` / BUM 経路には呼ばれない (HOOK ALPHA = Phase 3+ 待ち)。
- `vinbero_l2_dst_peer_esi` は inner Eth + FDB の存在を前提とする。FDB miss
  ケース (= 学習前のフロー) では dst_esi が all-zero で返り、フィルタは pass する。
- DF election ロジックを上書きしたい場合は本サンプル対象外 (Phase 3 HOOK ALPHA + control plane plugin が必要)。

## 関連設計

- `docs/plan/plugin-sdk-l2-headend.md` §5.7 Multihoming-aware plugin patterns
- `sdk/c/include/vinbero/headend_l2_helpers.h` (5 つの SDK helper)
