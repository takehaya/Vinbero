# Vinbero Plugin SDK

Vinberoのtail callベースのプラガブルアーキテクチャを利用して、カスタムXDPプログラムをプラグインとして登録する方法を説明します。

プラグイン作者向けの公開APIは `sdk/c/include/vinbero/` に集約されています。新規プラグインは `#include <vinbero/plugin.h>` だけで書き始められます。

## アーキテクチャと PROG_ARRAY スロット

Vinbero は XDP メインから各処理ステージの PROG_ARRAY へ `bpf_tail_call` でディスパッチします。プラグインは組み込みと予約を避けた範囲の空きスロットに登録します。

| PROG_ARRAY | ディスパッチ元 | 組み込み | RFC予約 | プラグイン |
|---|---|---|---|---|
| `sid_endpoint_progs` | localsid + nosrh | 0-21 | 22-31 | **32-63** |
| `headend_v4_progs`   | headend IPv4    | 0-7  | 8-15  | **16-31** |
| `headend_v6_progs`   | headend IPv6    | 0-7  | 8-15  | **16-31** |

## SDK ヘッダ

| ヘッダ | 内容 |
|---|---|
| `<vinbero/plugin.h>` | 主エントリ。`VINBERO_PLUGIN(name)`、`tailcall_ctx_read()`、`tailcall_epilogue()` |
| `<vinbero/maps.h>`   | 共有eBPFマップ宣言 (`sid_function_map`, `fdb_map`, `stats_map`, ...) |
| `<vinbero/types.h>`  | `sid_function_entry`、`headend_entry`、`sid_aux_entry` の公開型 |
| `<vinbero/helpers.h>` | verifier対策マクロ (`TAILCALL_BOUND_L3OFF`, `CALL_WITH_CONST_L3`, `TAILCALL_PARSE_SRH`, `TAILCALL_AUX_LOOKUP`) |

`<vinbero/plugin.h>` は他の必要ヘッダを間接 include するので、普通は `<vinbero/plugin.h>` と `<vinbero/maps.h>` だけで十分です。

## プラグインを書く

### 最小サンプル: パケットカウンタ

`VINBERO_PLUGIN(name)` マクロが `SEC("xdp")` ラッパーを生成します。本体は `return XDP_PASS;` のように普通の int を返せば、ラッパーが `tailcall_epilogue` を経由して最終 return します。

```c
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <vinbero/plugin.h>
#include <vinbero/maps.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} packet_counter_map SEC(".maps");

VINBERO_PLUGIN(packet_counter)
{
    if (tctx->l3_offset > 22)
        return XDP_DROP;

    __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&packet_counter_map, &key);
    if (counter)
        __sync_fetch_and_add(counter, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

`tctx` はディスパッチャが渡すコンテキスト、`ctx` は `struct xdp_md *`。どちらも本体引数として受け取れます。

### コンテキスト (`struct tailcall_ctx`)

```c
struct tailcall_ctx {
    __u16 l3_offset;        // Ethからの距離 (14=タグなし, 18=VLAN, 22=QinQ)
    __u8  dispatch_type;    // DISPATCH_LOCALSID / DISPATCH_NOSRH / DISPATCH_HEADEND
    __u8  inner_proto;      // DISPATCH_NOSRH時: nexthdr (IPIP/IPV6/ETHERNET)
    union {
        struct sid_function_entry sid_entry;  // Endpoint時
        struct headend_entry headend;         // Headend時
    };
};
```

主な用途:

- `l3_offset`: verifier 対策に `TAILCALL_BOUND_L3OFF(tctx, l3_off)` か `if (l3_off > 22)` でバウンドする
- `sid_entry.has_aux` が立っていれば `aux_index` で `sid_aux_map` を再 lookup
- Headend 系なら `headend` に segments/flavor 等が入る

### 戻りの契約

プラグインは以下のいずれかで終わる必要があります:

1. **リーフ**: `tailcall_epilogue(ctx, action)` を経由して return
2. **ディスパッチャへの戻し**: `sid_endpoint_progs` / `headend_v4_progs` / `headend_v6_progs` のいずれかへ `bpf_tail_call`

```c
/* OK — リーフ */
return tailcall_epilogue(ctx, XDP_PASS);

/* OK — 別スロットに委譲してフォールバック */
bpf_tail_call(ctx, &sid_endpoint_progs, next_action);
return tailcall_epilogue(ctx, XDP_DROP);

/* NG — 統計が記録されない */
return XDP_DROP;

/* NG — 自作 PROG_ARRAY へは脱出できない */
bpf_tail_call(ctx, &my_private_progs, 0);
```

`VINBERO_PLUGIN` を使う場合は `return XDP_DROP;` のように素の return で OK — ラッパーが必ず `tailcall_epilogue` を通します。`TAILCALL_PARSE_SRH` など直書きしたい高度なケースでは `SEC("xdp") int name(...)` を自分で書き、手動で `tailcall_epilogue` を呼んでください。

サーバーは登録時に静的検証を行い、上記契約を満たさない ELF と vinbero 管理外の PROG_ARRAY を指す `bpf_tail_call` は拒否します。CLI で事前チェック可能:

```bash
vinbero plugin validate --prog plugin.o --program my_plugin
# exit 0 = OK, 1 = 契約違反, 2 = ファイル/パースエラー
```

### 利用可能な共有マップ

プラグインが同名で宣言するとロード時に vinbero の実マップに差し替えられます。

| マップ名 | 型 | 用途 | アクセス |
|---|---|---|---|
| `sid_function_map` | LPM_TRIE | SID → Endpoint action | 読み取り |
| `sid_aux_map`      | ARRAY    | Endpoint補助データ    | 読み取り |
| `headend_v4_map` / `headend_v6_map` | LPM_TRIE | DA → Headend config | 読み取り |
| `fdb_map`    | HASH         | FDB (BD + MAC → OIF) | 読み取り |
| `stats_map`  | PERCPU_ARRAY | 統計カウンタ          | 読み書き |
| `scratch_map` | PERCPU_ARRAY | 一時バッファ (256B/CPU) | 読み書き |
| `tailcall_ctx_map` | PERCPU_ARRAY | tail callコンテキスト | 読み取り (内部) |

ルーティング状態系 (`sid_function_map`, `headend_*_map`, `fdb_map`) はプラグインから書き換えるとデータプレーンが壊れるので読み取りに留めてください。

### プラグイン固有マップ

ELF 内で `BPF_MAP_TYPE_HASH` / `PERCPU_ARRAY` などを独自に宣言すると、登録時に新規作成されます。`sdk/examples/simple-acl/` の `acl_deny_map` 参照。

### 制約事項

| 項目 | 制約 |
|---|---|
| tail call 深度 | main(0) → プラグイン(1) = 深度 1。残り 32 まで利用可 |
| BPF スタック | 512 バイト/プログラム。大きなデータは `scratch_map` 等の per-CPU マップへ |
| l3_offset | 必ず 22 以下にバウンドしてからパケットアクセス (verifier 要件) |
| l3_offset の定数化 | ヘルパー関数呼び出し時は `CALL_WITH_CONST_L3` か `switch(l3_off)` で定数化 |
| プログラムタイプ | XDP (`SEC("xdp")`) のみ |
| スロット範囲 | Endpoint 32-63、Headend 16-31。それ以外は `ErrReservedSlot` |

## ビルド

```bash
sudo make install-sdk          # /usr/local/include/vinbero/ にヘッダを配置
```

プラグインディレクトリの Makefile は `sdk/c/Makefile.plugin` をテンプレートとして使えます:

```makefile
VINBERO_SDK_ROOT ?= /usr/local/include
include $(VINBERO_SDK_ROOT)/vinbero/Makefile.plugin
```

もしくは `sdk/examples/*/Makefile` をコピーして改造してください。

## 登録

```bash
# 1. ローカル検証 (サーバー不要)
vinbero plugin validate --prog plugin.o --program my_plugin

# 2. サーバーに登録
vinbero -s http://127.0.0.1:8080 \
    plugin register --type endpoint --index 32 \
    --prog plugin.o --program my_plugin

# 3. SID をプラグインスロットに向ける
vinbero -s http://127.0.0.1:8080 \
    sid create --trigger-prefix fc00:2::32/128 --action 32

# 4. 解除
vinbero -s http://127.0.0.1:8080 \
    plugin unregister --type endpoint --index 32
```

## 観測

パケットキャプチャやデバッグには外部ツール [xdp-ninja](https://github.com/takehaya/xdp-ninja) を推奨します。

per-action 統計 (`XDP_PASS` / `XDP_DROP` / `XDP_REDIRECT` / エラー) は `vinbero.yml` で `enable_stats: true` にすると `stats_map` から読めます。

## サンプルプラグイン

- `sdk/examples/plugin-counter/` : per-CPU カウンタ + 三台ルータ E2E デモ (setup / test / teardown スクリプト付き)
- `sdk/examples/simple-acl/` : IPv6 ソースアドレス deny-list。`CALL_WITH_CONST_L3` のヘルパーマクロ使用例 (ビルド確認のみ)
