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
- `sid_entry.aux_index != 0` なら `aux_index` で `sid_aux_map` を再 lookup (0 は "aux なし" sentinel)
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

プラグインが同名で宣言するとロード時に vinbero の実マップに差し替えられます。マップは **アクセス意図** で 2 カテゴリに分かれ、`vbctl plugin list -v` に分類が表示されます:

| カテゴリ | マップ例 | 用途 | プラグインの扱い |
|---|---|---|---|
| **Read-Only** (14 本) | `sid_function_map`, `sid_aux_map`, `headend_v4_map`, `headend_v6_map`, `headend_l2_map`, `fdb_map`, `bd_peer_map`, `bd_peer_reverse_map`, `esi_map`, `bd_peer_l2_ext_map`, `headend_l2_ext_map`, `bd_local_esi_map`, `dx2v_map`, `tailcall_ctx_map` | ルーティング / BD / ESI などの制御状態 | プラグインから書き換えるとデータプレーンが壊れる。必ず読み取りのみ |
| **Read-Write** (8 本) | `scratch_map`, `stats_map`, `slot_stats_endpoint`, `slot_stats_headend_v4`, `slot_stats_headend_v6`, `sid_endpoint_progs`, `headend_v4_progs`, `headend_v6_progs` | 統計 / scratch / PROG_ARRAY | 書き込み可 (ただし `slot_stats_*` は epilogue 経由、PROG_ARRAY は `bpf_tail_call` 専用) |

プラグイン ELF が RO カテゴリのマップに write 命令を含んでいると、将来バージョン (Phase 2) では register 時に reject される予定です。現状は audit ログ (`slog` の `plugin map linkage` イベント) に記録されるのみ。

### プラグイン固有マップ

ELF 内で `BPF_MAP_TYPE_HASH` / `PERCPU_ARRAY` などを独自に宣言すると、登録時に新規作成されます。`sdk/examples/simple-acl/` の `acl_deny_map` 参照。登録時の分類結果 (owned / shared RO / shared RW) は `vbctl plugin list -v` で確認できます。

### プラグイン aux (SID 単位の設定値)

SID ごとに異なる設定値をプラグインへ渡したい場合、`sid_aux_entry.plugin_raw` (196 バイト) に任意の構造体を置けます。共有マップを増やさず、SID と 1:1 で構成を持てるのが利点です。

プラグイン作者は `struct <program>_aux` という名前で構造体を宣言し、`VINBERO_PLUGIN_AUX_TYPE` マクロで BTF に残します:

```c
#include <vinbero/types.h>

struct my_plugin_aux {
    __u32                        limit;
    vinbero_mac_t                match_mac;
    struct vinbero_ipv6_prefix_t source;
};
VINBERO_PLUGIN_AUX_TYPE(my_plugin, my_plugin_aux);

VINBERO_PLUGIN(my_plugin)
{
    TAILCALL_AUX_LOOKUP(tctx, aux);
    if (aux) {
        struct my_plugin_aux *cfg =
            VINBERO_PLUGIN_AUX_CAST(struct my_plugin_aux, aux);
        // cfg->limit, cfg->match_mac, cfg->source.prefix_len / addr
    }
    return XDP_PASS;
}
```

CLI からは aux の払い出し経路が 3 つあり、SID 1 件あたりで **どれか 1 つだけ** 指定できます (3-way mutually exclusive、2 つ以上指定すると `InvalidArgument`):

| フラグ | 挙動 | 用途 |
|---|---|---|
| `--plugin-aux-json '<json>'` | サーバが BTF レイアウトに encode して SID の aux index を自動払い出し。SID 削除で aux も解放 | 一番シンプル。SID と aux を 1:1 で扱う場合 |
| `--plugin-aux-raw <hex>` | 作者自身が encode した 196 バイト以下の byte 列を直接渡す | BTF に `*_aux` 型が無いプラグイン、テスト用途 |
| `--plugin-aux-index <idx>` | 事前に `vbctl plugin aux alloc` で払い出した index を参照。SID 削除で aux は消えない | 複数の SID で同じ aux を共有する / aux を長寿命にしたい |

```bash
# パターン A: SID 内包 (旧来)
vinbero sid create --prefix fc00::100/128 --action 32 \
  --plugin-aux-json '{"limit": 100,
                      "match_mac": "aa:bb:cc:dd:ee:ff",
                      "source": "fc00:1::/64"}'

# パターン B: 独立アロケート (Phase 1d, 新規)
IDX=$(vinbero plugin aux alloc --map-type endpoint --slot 32 \
        --json '{"limit": 200}' | jq -r .index)
vinbero sid create --prefix fc00::200/128 --action 32 \
  --plugin-aux-index "$IDX"
vinbero sid create --prefix fc00::201/128 --action 32 \
  --plugin-aux-index "$IDX"   # 同 aux を別 SID からも参照
```

SDK は次の well-known typedef/struct を提供しており、encoder はこれらを判別して人間が読み書きしやすい文字列フォーマットを受け付けます (`sdk/c/include/vinbero/types.h`):

| 型 | JSON での書き方 | バイナリ |
|---|---|---|
| `vinbero_mac_t` | `"aa:bb:cc:dd:ee:ff"` (`:` / `-` / 連続 hex 可) | `[6]u8` |
| `vinbero_ipv4_t` | `"10.0.0.1"` | `[4]u8` (network order) |
| `vinbero_ipv6_t` | `"fc00::1"` | `[16]u8` (network order) |
| `struct vinbero_ipv4_prefix_t` | `"10.0.0.0/24"` | `{prefix_len u8, _pad[3], addr [4]u8}` |
| `struct vinbero_ipv6_prefix_t` | `"fc00::/48"` | `{prefix_len u8, _pad[7], addr [16]u8}` |
| プレーン整数 | `42` または `"0x2a"` | native endian |
| `__u8[N]` 配列 | `"aabbccdd..."` (hex 短縮) or `[0xaa, 0xbb, ...]` | そのままバイト列 |

BTF に `<program>_aux` 型が無い場合は raw / index 経路だけが使えます。`plugin_aux_raw` / `plugin_aux_json` / `plugin_aux_index` は 3-way mutually exclusive。

### 独立 aux のライフサイクル (`vbctl plugin aux`)

`--plugin-aux-index` で SID から参照される aux は `sid_aux_map` 上で所有者タグ (`plugin:<mapType>:<slot>` 形式) により保護されており、払い出したスロットからしか書き換え / 解放できません。別スロット経由で触ろうとすると `PermissionDenied` が返ります。

```bash
# alloc: スロット 32 の owner タグで aux を 1 件払い出し
IDX=$(vinbero plugin aux alloc --map-type endpoint --slot 32 \
        --json '{"limit":100}' | jq -r .index)

# update: payload 差し替え (owner は alloc 時と一致している必要)
vinbero plugin aux update --map-type endpoint --slot 32 --index "$IDX" \
  --json '{"limit":200}'

# get: raw bytes を hex ダンプ + owner / has_aux_type を表示
vinbero plugin aux get --map-type endpoint --slot 32 --index "$IDX"

# free: 参照している SID が無い (または削除済み) 状態で解放
vinbero plugin aux free --map-type endpoint --slot 32 --index "$IDX"
```

独立 aux は **daemon 再起動で消失**します (`sid_function_map` に紐づかない index は `RecoverAuxIndices` の復元対象外)。`pin_maps: true` で永続化される対象にも含まれていません。恒久化が必要な場合は `--plugin-aux-json` 経由で SID と一体で管理するか、外部コントローラから起動時に再投入してください。詳しくは [`persistence.md`](persistence.md) を参照。

### Go SDK からのタイプ付アクセス (`sdk/go/plugin`)

カスタムコントローラから使う場合、`github.com/takehaya/vinbero/sdk/go/plugin` パッケージの `PluginAux[T]` generic wrapper で RPC をラップできます:

```go
import "github.com/takehaya/vinbero/sdk/go/plugin"

type MyPluginAux struct {
    Limit uint32
    _     [4]byte
    // (C struct と同じ固定長レイアウト・LittleEndian)
}

aux := plugin.NewPluginAux[MyPluginAux](client, "endpoint", 32)
idx, _ := aux.Alloc(ctx, MyPluginAux{Limit: 100})
_    = aux.Update(ctx, idx, MyPluginAux{Limit: 200})
v, _ := aux.Get(ctx, idx)  // binary.Read で復元
_    = aux.Free(ctx, idx)
```

`Alloc` / `Update` は `json.Marshal` → サーバ BTF で C レイアウトに encode、`Get` は raw bytes を `binary.Read(LittleEndian)` で復元します。T は BTF 型と同じ **固定サイズ・LittleEndian・C 互換** のレイアウトである必要があります (`sdk/go/plugin/doc.go` に制約明記)。

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

### 登録済みプラグインの一覧 (`plugin list`)

```bash
vinbero plugin list                       # MAP_TYPE / SLOT / PROGRAM / AUX / REGISTERED
vinbero plugin list --type endpoint       # endpoint PROG_ARRAY のみ
vinbero plugin list -v                    # owned / shared RO / shared RW マップを展開表示
```

verbose 出力例:

```
MAP_TYPE    SLOT  PROGRAM           AUX                 REGISTERED
endpoint    32    plugin_counter    plugin_counter_aux  2026-04-23T10:15:00Z
  shared_ro: [sid_aux_map, tailcall_ctx_map]
  shared_rw: [stats_map, slot_stats_endpoint, scratch_map]
  owned:     [plugin_counter_map]
```

`shared_ro` / `shared_rw` / `owned` はプラグイン ELF が参照したマップの分類で、「プラグイン固有マップ」節の通り `owned` 側は登録時に新規作成された vinbero の管理外マップです。

## 観測

パケットキャプチャやデバッグには外部ツール [xdp-ninja](https://github.com/takehaya/xdp-ninja) を推奨します。

### `stats_map` (vinbero 全体の per-action 集計)

`vinbero.yml` で `enable_stats: true` にすると `stats_map` に per-action 統計 (`RX_PACKETS` / `PASS` / `DROP` / `REDIRECT` / `ABORTED`) が蓄積されます。`vinbero stats show` で参照:

```bash
vinbero stats show
# COUNTER     PACKETS  BYTES
# RX_PACKETS  ...
# PASS        ...
# DROP        ...
# REDIRECT    ...
# ABORTED     ...
```

これは「XDP 入口を抜けた全パケットの per-action 合計」で、**プラグインごとの呼び出し回数ではありません**。NDP / RA / MLD 等の背景 IPv6 パケットも同じ counter に加算されます。プラグイン経由で `XDP_PASS` 等した場合もここに乗ります (plugin ELF の `enable_stats` もロード時に書き換えられます)。

### Per-slot invocation counter (builtin + plugin)

`vinbero stats slot show` で各 tail-call target slot が何回呼ばれたかを確認できます。builtin は enum 名、plugin は `plugin:<program_name>` でラベル付けされます。

```bash
vinbero stats slot show                     # 全 map、packets>0 のみ
vinbero stats slot show --all               # packets=0 も含めて表示
vinbero stats slot show --type endpoint     # endpoint PROG_ARRAY のみ
vinbero stats slot show --plugin-only       # plugin スロットのみ
vinbero stats slot show --top 10            # packets 降順で上位 N 件
vinbero stats slot reset                    # 全リセット
vinbero stats slot reset --type endpoint    # 指定 map のみリセット
```

出力例 (ping -c 3 で plugin slot 32 に到達した場合):

```
MAP       SLOT  NAME                   PACKETS  BYTES
endpoint  1     End                    0        0
endpoint  32    plugin:plugin_counter  3        594
```

内部では 3 本の PERCPU_ARRAY (`slot_stats_endpoint` / `slot_stats_headend_v4` / `slot_stats_headend_v6`) に `tailcall_epilogue` がインクリメントしています。`enable_stats` gate で on/off され、無効時は分岐 1 つで早期 return します。

### プラグイン固有カウンタ

「この plugin 内で deny した回数」「src IP 別の集計」などプラグインロジック固有の計数は、plugin ELF 内で独自の `BPF_MAP_TYPE_PERCPU_ARRAY` / `HASH` を宣言してそこに書きます。`sdk/examples/plugin-counter/plugin.c` の `plugin_counter_map` が最小例で、bpftool から userspace 経由で読めます:

```bash
MAP_ID=$(sudo bpftool map show | awk '/name plugin_counter/ { sub(":","",$1); print $1; exit }')
sudo bpftool map dump id "$MAP_ID"
```

Phase 1c で `PluginList` RPC がプラグイン ELF 内で宣言された owned map 名を返すようになったので、`vbctl plugin list -v` から名前を取って `bpftool map show name <owned>` で直接読めます。Go SDK から owned map の FD を取得する経路 (Map[K,V] generic wrapper 復活) は Phase 2 の課題。

## サンプルプラグイン

- `sdk/examples/plugin-counter/` : per-CPU カウンタ。aux の `increment` 値を JSON で指定して増分を可変にできる三台ルータ E2E デモ
- `sdk/examples/plugin-acl-prefix/` : 外側 IPv6 src の prefix マッチ ACL。`vinbero_ipv6_prefix_t` を aux で渡し、同一プラグインスロットを複数 SID で使い分ける E2E デモ
- `sdk/examples/simple-acl/` : IPv6 ソースアドレス deny-list (ハッシュマップ)。`CALL_WITH_CONST_L3` のヘルパーマクロ使用例 (ビルド確認のみ)
