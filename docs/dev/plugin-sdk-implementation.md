# プラグイン SDK 実装記録 (Phase 0 + 1a + 1b + 1c + 1d + 1e)

Vinbero の XDP プラグイン SDK を段階的に強化した際の実装記録。`docs/plan/plugin-sdk-enhancement.md` で策定したプランに沿って、Phase 0 / 1a / 1b / 1e まで実施したのち、残タスクだった Phase 1c (plugin-visible map の分類と可視化) と Phase 1d (typed PluginAux ライフサイクル) を実装した (PR #23)。

開発者向けの最終的な使い方ドキュメントは [`docs/design/ja/plugin-sdk.md`](../design/ja/plugin-sdk.md) を参照。

---

## Phase 0: xdpcap フックの完全撤去

**目的**: cloudflare/xdpcap 連携用フック (PROG_ARRAY + `RETURN_ACTION` マクロ + config flag) がプラグイン SDK の戻り契約を複雑化させていたので、観測は自作の xdp-ninja に寄せて本体から切り離す。

### 削除したもの

- `src/core/xdpcap.h` (ファイル丸ごと)
- `src/core/xdp_map.h` の `xdpcap_hook` マップ定義
- `src/xdp_main.c` の `RETURN_ACTION(ctx, &xdpcap_hook, action)` → 単なる `return action;` に
- `src/xdp_prog.c` の xdpcap include
- `pkg/config/config.go` の `EnableXdpcap` フィールド
- `pkg/vinbero/vinbero.go` の `enable_xdpcap` constant 設定
- `pkg/bpf/maps.go` の `XdpcapHook` 共有マップ参照
- `vinbero.yml` の `enable_xdpcap` 行

### シンプル化

`TAILCALL_RETURN` マクロを `return tailcall_epilogue(ctx, action)` の 1 行に縮約。23 個のビルトイン tail call ターゲット (End, End.DX2, H.Encaps, GTP 系など) はマクロ経由で自動的に新仕様へ移行。

### 再生成

`make bpf-gen` で `pkg/bpf/bpf_bpfel.go` / `bpf_bpfeb.go` から `XdpcapHook` フィールドが消えた。

### 効果

default OFF 運用 (`enable_xdpcap: false`) だったので機能的な挙動変化はゼロ、代わりに戻り経路が「統計記録のみ」に単純化された。

---

## Phase 1a: プラグイン契約の静的検証

**目的**: プラグインが最終的に vinbero の信頼境界内で終わることを保証する。具体的にはロード時に以下を確認して違反があれば拒否:

1. `SEC("xdp")` であること
2. `tailcall_epilogue` への `BPF_CALL` があるか、vinbero 管理下の PROG_ARRAY (`sid_endpoint_progs` / `headend_v4_progs` / `headend_v6_progs`) への `bpf_tail_call` があるか (どちらか / 両方)
3. `bpf_tail_call` の map 引数は vinbero PROG_ARRAY に限定。自作マップや動的な map pointer は拒否

### 新規

`pkg/bpf/plugin_validate.go`:

```go
func ValidatePluginProgram(spec *ebpf.ProgramSpec) error
func ValidatePluginCollection(spec *ebpf.CollectionSpec, program string) (*ebpf.ProgramSpec, error)

var ValidTailCallMaps = []string{
    "sid_endpoint_progs",
    "headend_v4_progs",
    "headend_v6_progs",
}
```

- `ValidatePluginProgram`: 上記 3 条件をチェック
- `ValidatePluginCollection`: 指定プログラムを spec から取り出し、型を XDP に強制してから `ValidatePluginProgram` を呼ぶ共通ヘルパ

### 仕組み

**epilogue 呼び出し検出** (リーフ検知):
cilium/ebpf の `asm.Instruction.IsFunctionReference()` が BPF_CALL 命令の参照シンボルを返す。`tailcall_epilogue` は `__noinline` な BPF サブプログラムなので、命令列に参照があるかを走査すれば判定できる。

**tail call 検出** (ディスパッチ検知):
`ins.IsBuiltinCall() && ins.Constant == int64(asm.FnTailCall)` で `bpf_tail_call` helper を呼んでいる命令を特定。その直前に R2 をロードしている `LoadMapPtr` 命令を逆向きに探し、`ins.Reference()` で map 名を取得する。

```go
// findTailCallMapName walks backwards to find the most recent instruction
// that wrote R2 (the map argument of bpf_tail_call). Returns the map name
// when R2 was set by a static LoadMapPtr; "" otherwise.
```

map 名が取れなければ "(dynamic)" として扱い、拒否 (保守的な挙動 — 静的に白リスト判定できないものは通さない)。

### 何が保証できて、何ができないか

**Hard guarantee**:
- `bpf_tail_call` の map 引数は (静的 map 参照である限り) 必ず vinbero PROG_ARRAY を指す。自作マップに tail-call することで validator の境界から脱出するパターンは完全に拒否できる

**Soft guarantee (call-site presence のみ)**:
- 「どこかに」epilogue 呼び出し or vinbero PROG_ARRAY への tail call があれば通る
- 一部 exit path で契約を守らず `return XDP_DROP;` と抜けているケースは検知不能 (= 将来の CFG 解析課題)

実用上、単純なミスは拾える shift-left 用途としては十分。完全な per-path 検証は Phase 2 相当として保留。

### サーバー統合

`pkg/server/plugin.go` の `PluginRegister` が `msg.Program` 指定のプログラムに対して `ValidatePluginCollection` を 1 回呼ぶ形に差し替え。旧実装は「ELF 内のどれか 1 つのプログラムに `tailcall_epilogue` 参照があれば OK」という緩い判定で、tail call 先の妥当性は一切見ていなかった。

### 失敗時のエラー例

```
# どちらの契約も満たさない
invalid_argument: plugin program "my_plugin" neither calls tailcall_epilogue
  nor tail-calls into a vinbero PROG_ARRAY; write
  `return tailcall_epilogue(ctx, action);` at every exit, or bpf_tail_call
  into one of (sid_endpoint_progs, headend_v4_progs, headend_v6_progs)

# 自作 PROG_ARRAY への tail call
invalid_argument: plugin program "my_plugin" calls bpf_tail_call with
  unauthorized map(s): [my_private_progs]; plugins may only tail-call
  into vinbero PROG_ARRAYs (sid_endpoint_progs, headend_v4_progs, headend_v6_progs)

# 動的な map pointer
invalid_argument: plugin program "my_plugin" calls bpf_tail_call with
  unauthorized map(s): [(dynamic)]; ...
```

---

## Phase 1b: SDK 骨組み + CLI サブコマンド

**目的**: プラグイン作者が `#include <vinbero/plugin.h>` だけで開発を始められ、CI 上でサーバーを立てずに契約違反を検出できる (shift-left) ようにする。

### C SDK ヘッダ (`sdk/c/include/vinbero/`)

既存 `src/core/*.h` の薄い再 export として、以下 4 ヘッダを公開 API 境界として宣言:

| ヘッダ | 内容 |
|---|---|
| `plugin.h` | エントリ。`tailcall_ctx` / `tailcall_ctx_read()` / `tailcall_epilogue()` / `VINBERO_SDK_VERSION` |
| `maps.h` | `sid_function_map`, `fdb_map`, `stats_map` など共有マップ |
| `types.h` | `sid_function_entry`, `headend_entry`, `sid_aux_entry` などの公開型 |
| `helpers.h` | verifier 対策マクロ (`TAILCALL_BOUND_L3OFF`, `CALL_WITH_CONST_L3`, `TAILCALL_PARSE_SRH`, `TAILCALL_AUX_LOOKUP`) |

プラグイン作者は内部パス (`core/xdp_tailcall.h` など) を知る必要がなくなり、将来 Vinbero が内部ディレクトリを再編しても SDK インタフェースを維持できる。

### CLI (`vinbero plugin …`)

`pkg/cli/cmd_plugin.go` に `validate` サブコマンド追加 (既存 `register`/`unregister` と並列):

```bash
vinbero plugin validate --prog plugin.o --program my_plugin
# exit 0 = OK, 1 = 契約違反, 2 = ファイル/パースエラー
```

サーバー非依存なので CI の pre-commit / pre-push で活用できる。

### サンプルプラグイン

- `sdk/examples/plugin-counter/` : per-CPU カウンタ + 三台ルータ E2E デモ
- `sdk/examples/simple-acl/` : IPv6 ソース deny-list。ハッシュマップ + `CALL_WITH_CONST_L3` デモ (ビルド確認のみ)
- 両者とも `Makefile` は `include ../../c/Makefile.plugin` の 1 行で済む形

### Makefile ターゲット

```makefile
install-sdk   # SDK ヘッダを $(SDK_PREFIX)/include/vinbero/ に install
sdk-build     # sdk/examples/*/ を再帰 make
sdk-test      # サンプルを build → vinbero plugin validate で契約チェック
sdk-clean     # サンプルのビルド成果物を削除
```

---

## Phase 1e: `VINBERO_PLUGIN` マクロによる path coverage の構造保証

**目的**: Phase 1a の validator は call-site 存在チェックしかしていないので、プラグインが一部 exit path で `return XDP_DROP;` と抜けるケースは検知できない。validator 側の CFG 解析 (Phase 2 相当) は実装コストが大きいので、先に **プラグイン側の書き方で path coverage を構造的に保証する** 仕組みを追加する。

### 新規マクロ

`sdk/c/include/vinbero/plugin.h`:

```c
#define VINBERO_PLUGIN(name)                                                  \
    static __always_inline int __vinbero_body_##name(                           \
        struct xdp_md *ctx, struct tailcall_ctx *tctx);                       \
    SEC("xdp")                                                                 \
    int name(struct xdp_md *ctx)                                              \
    {                                                                          \
        struct tailcall_ctx *_tctx = tailcall_ctx_read();                     \
        int _action = _tctx ? __vinbero_body_##name(ctx, _tctx) : XDP_DROP;     \
        return tailcall_epilogue(ctx, _action);                               \
    }                                                                          \
    static __always_inline int __vinbero_body_##name(                           \
        struct xdp_md *ctx, struct tailcall_ctx *tctx)
```

プラグイン作者は:

```c
VINBERO_PLUGIN(my_plugin)
{
    if (err) return XDP_DROP;   /* 本体は int 返し。素の return で OK */
    return XDP_PASS;
}
```

と書ける。SDK 側が生成する `SEC("xdp")` ラッパーの唯一の return は `return tailcall_epilogue(ctx, _action);` なので、本体のどの path で抜けても必ず epilogue を通る。本体は `__always_inline` なので実行時オーバーヘッドはゼロ。

### 追加の安全装置: `warn_unused_result`

`tailcall_epilogue` に `__attribute__((warn_unused_result))` を追加した。`tailcall_epilogue(ctx, XDP_DROP);` (戻り値を捨てて普通の return へ) のように epilogue を呼ぶだけで return しないミスは、コンパイル時に warning として検出される。

```c
static __noinline __attribute__((warn_unused_result))
int tailcall_epilogue(struct xdp_md *ctx, int action);
```

既存の `TAILCALL_RETURN(ctx, action)` マクロは `return tailcall_epilogue(ctx, action)` に展開されるので、in-tree のビルトインでは warning は出ない。

### サンプル書き換え

- `sdk/examples/plugin-counter/plugin.c` を `VINBERO_PLUGIN(plugin_counter)` 版にリライト
- `sdk/examples/simple-acl/plugin.c` を `VINBERO_PLUGIN(simple_acl)` 版にリライト

どちらも行数が減り、path coverage が構造的に保証されるようになった。

### 保証レベルのまとめ

| 書式 | path coverage | tail call 脱出 |
|---|---|---|
| `VINBERO_PLUGIN(name) { ... }` (推奨) | **構造的に完全** (マクロが単一 return 経路) | validator で hard reject |
| `SEC("xdp") int name(...) { ... }` (直書き) | validator は call-site 存在のみ (将来 CFG 解析) | validator で hard reject |

### 運用方針

- 新規プラグインは `VINBERO_PLUGIN` マクロ書式を推奨
- 既存の直書き書式も受け入れ続ける (`TAILCALL_PARSE_SRH` のような内部で `TAILCALL_RETURN` を使う高度なマクロを活用するプラグイン向け)
- 将来、validator 側の CFG 解析が入れば直書き書式も完全保証される (Phase 2)

---

## 実際の呼び出しフロー

プラグイン登録から通常運用までの流れ:

```
[開発者]           [Vinbero サーバー]              [カーネル XDP]
  │                       │                               │
  │ make plugin           │                               │
  │ (sdk/c/Makefile.plugin│                               │
  │  でビルド)            │                               │
  │                       │                               │
  │ vinbero plugin        │                               │
  │   validate            │   ← shift-left: サーバー不要  │
  │ (ローカル検証 OK)     │                               │
  │                       │                               │
  │ gRPC PluginRegister ──▶ ValidatePluginCollection       │
  │   (ELF, slot=32)      │   (プログラム存在 + 型 XDP +   │
  │                       │    tailcall_epilogue 参照)    │
  │                       │                               │
  │                       │ NewCollectionWithOptions      │
  │                       │   (共有マップ差し替え) ──────▶ BPF ロード
  │                       │                               │
  │                       │ RegisterPlugin("endpoint",    │
  │                       │   32, prog.FD()) ────────────▶ PROG_ARRAY[32]
  │                       │                               │ にプログラム登録
  │ ◀──────── OK ─────────┤                               │
  │                       │                               │
  │ sid create            │                               │
  │   --trigger-prefix    │ sid_function_map にエントリ   │
  │   fc00:2::32/128      │   (action=32) 追加 ──────────▶ SID 登録
  │   --action 32         │                               │
  │                       │                               │
  │ [通常運用]            │                               │
  │                       │                               │  パケット到着
  │                       │                               │    ↓
  │                       │          vinbero_main が tail call ─┐
  │                       │                               │     ↓
  │                       │       sid_endpoint_progs[32] ──▶ プラグイン実行
  │                       │                               │     ↓
  │                       │                               │ tailcall_epilogue
  │                       │                               │  (統計記録)
  │                       │                               │     ↓
  │                       │                               │   XDP_PASS/DROP
```

---

## ドキュメント配置

- [`docs/design/ja/plugin-sdk.md`](../design/ja/plugin-sdk.md) : プラグイン開発者向け完全ガイド (日本語)
- [`docs/dev/plugin-sdk-implementation.md`](plugin-sdk-implementation.md) : 本ファイル、実装記録
- `docs/plan/plugin-sdk-enhancement.md` : プラン全体像 + Phase 1c/1d の将来検討項目 (コミット対象外)
- `sdk/README.md` : SDK ディレクトリ直下の案内 (英語)
- `sdk/examples/*/README.md` : 各サンプルの使い方

---

## Per-slot invocation counter

プラグイン (と builtin) の呼び出し回数を global stats とは独立に観測できるよう、per-slot counter を追加:

- **新マップ 3 本**: `slot_stats_endpoint` (64 entries) / `slot_stats_headend_v4` (32) / `slot_stats_headend_v6` (32)、いずれも `PERCPU_ARRAY` で value は既存 `stats_entry` (packets / bytes)
- **dispatch_type を細分化**: `DISPATCH_HEADEND = 2` を `DISPATCH_HEADEND_V4 = 2` / `DISPATCH_HEADEND_V6 = 3` に分離し、`tailcall_ctx` に `slot` フィールドを追加。dispatcher が書き込み時に slot 番号を保存、`tailcall_epilogue` が per-CPU 読み取り 1 回で対応 map にインクリメント
- **enable_stats で gate**: 無効時は分岐 1 つ (~5ns) で早期 return、既存 `stats_inc` と同じコスト特性
- **既存 SRV6_END / H_ENCAPS_V{4,6} を廃止**: `stats_counter` enum を 8→5 (`RX_PACKETS` / `PASS` / `DROP` / `REDIRECT` / `ABORTED`) に縮小。11 箇所の `STATS_INC(STATS_SRV6_END, 0)` 呼び出しを削除 (H_ENCAPS_V{4,6} は元々未使用)。`ABORTED` は従来 `ERROR` という名前 / 呼び出し側ゼロの dead counter だったのを、XDP_ABORTED 発生時に確実にインクリメントする形に正す
- **CLI**: `vinbero stats slot show [--type X] [--all] [--top N] [--plugin-only]` / `stats slot reset [--type X]`。出力は `MAP / SLOT / NAME / PACKETS / BYTES` のテーブル。builtin は `Srv6LocalAction` / `Srv6HeadendBehavior` enum を逆引き、plugin は `PluginServer.registry` から `plugin:<program>` のラベル
- **Plugin 名の記憶**: `PluginServer` に `registry map[slotKey]string` を追加、register/unregister で読み書き。Collection close の lifecycle は Phase 1c 課題として据え置き

### 破壊的変更

- `vinbero stats show` の出力が 8 カウンタ → 5 カウンタに減少。SRV6_END / H_ENCAPS_V4 / H_ENCAPS_V6 を参照する script は stats slot show 経由に切り替える必要
- `tailcall_ctx` のレイアウトに `slot` (+ `_pad[3]`) が追加。`VINBERO_SDK_VERSION` は 1 のまま据え置き (当面バンプせず、plugin は再コンパイルで追従)
- `tailcall_ctx_write_sid` / `tailcall_ctx_write_headend` のシグネチャ拡張 (dispatcher 側のみ追従、plugin は tailcall_ctx を read のみなので影響なし)

---

## 保留 (次回 PR で再検討)

- **Phase 2 — asm-level RO write enforce**: Phase 1c で共有マップを RO / RW に分類して audit ログを出すところまでは入ったが、RO マップへの write 命令は reject していない。cilium/ebpf の `asm.Instructions` を走査して `BPF_ST*` / `BPF_STX*` のターゲット map を特定し、RO set に含まれていれば load 前に reject する CFG analyzer を入れる。概ね +300〜500 LOC 規模。
- **Phase 2 — BPF pinning / 独立 PluginAux の永続化**: 今回追加した `PluginAuxAlloc` は SID 関数に紐づかない「独立 aux」を生むが、`sid_function_map` を iterate して index 使用状況を復元している `RecoverAuxIndices` の仕組みでは拾えず、daemon 再起動で消失する。`pin_maps.enabled: true` の拡張として owner map 自体も pin する設計が要るが、schema migration の扱いも含めて別 PR 扱い。
- **SDK 配布体験の改善**: 現状 `sudo make install-sdk` は vinbero リポジトリを clone した状態でないと実行できず、完全に外部のプラグイン作者には体験が重い。改善案:
  - **案 A (推奨): SDK tarball のリリース**. goreleaser に `vinbero-sdk-vX.Y.tar.gz` を追加。中身は `sdk/c/include/vinbero/*.h` + 必要な `src/core/*.h` + `Makefile.plugin`。ユーザーは `curl -L .../vinbero-sdk.tar.gz \| sudo tar xz -C /` で完結。既存 `install-sdk` のロジックを再利用して `sdk-archive` ターゲット追加する程度の工数で、リリースごとに SDK バージョンが固定できるのでバージョニングも綺麗
  - **案 B: 単一ヘッダ化**. `quom`/`amalgamate` で公開ヘッダ一式を `vinbero.h` 1 ファイルにマージ。`curl -o vinbero.h ...` 1 発で済むが、デバッグ時の line 番号と元 source の乖離が発生
  - **案 C: Docker image**. `ghcr.io/takehaya/vinbero-plugin-builder` を公開、`docker run --rm -v $PWD:/work ... make` で完結。CI 統合しやすいが image 更新追跡が面倒
  - **案 D: apt/RPM パッケージ**. `apt install vinbero-sdk` は最もユーザーフレンドリだがメンテ負担最大
  - 案 A が ROI 最高。現状は in-tree 開発 (`sdk/examples/*/Makefile` が `VINBERO_SDK_ROOT` を override する方式) で最低限成立しているので今回スコープ外

詳細な背景・代替案の比較は `docs/plan/plugin-sdk-enhancement.md` に ADR として残してある。

### 既に撤去されたもの / 部分復活したもの

- **Go SDK パッケージ (`sdk/go/plugin/`)**: Phase 1b で初期実装したが、リポジトリ内 import ゼロ + CLI と機能完全重複のため YAGNI 判断で削除 (ADR-6)。Phase 1d で `PluginAux[T]` generic wrapper の用例が具体化したため、**`aux.go` + `doc.go` のみ部分復活**。`Map[K, V]` などは引き続き保留。
- **SDK 配下への examples 集約**: サンプルは `sdk/examples/plugin-counter/` (E2E デモ) と `sdk/examples/simple-acl/` (ビルド確認) に集約 (ADR-7)。

---

## Phase 1c: 共有マップの RO/RW 分類 + PluginList

**目的**: プラグインから参照される共有マップを「read-only な制御状態」と「read-write な統計/scratch」に分類して audit ログで可視化し、将来の asm-level enforce (Phase 2) の土台を作る。合わせて登録済プラグインの一覧を RPC / CLI から引けるようにする。

### 共有マップの分類

`MapOperations.GetSharedMaps()` を廃止し、以下の 2 getter に分離した (`pkg/bpf/maps.go`):

- `GetSharedReadOnlyMaps()` (14 本): `sid_function_map`, `sid_aux_map`, `headend_{v4,v6,l2}_map`, `fdb_map`, `bd_peer_map`, `bd_peer_reverse_map`, `esi_map`, `bd_peer_l2_ext_map`, `headend_l2_ext_map`, `bd_local_esi_map`, `dx2v_map`, `tailcall_ctx_map`
- `GetSharedReadWriteMaps()` (8 本): `scratch_map`, `stats_map`, `slot_stats_endpoint/v4/v6`, `sid_endpoint_progs`, `headend_v4_progs`, `headend_v6_progs`

`slot_stats_*` は「プラグインから直接書かない (epilogue 経由)」という運用慣習ではあるが、BPF verifier 視点では write 可能なので RW 側に分類。PROG_ARRAY 3 本はプラグインから `bpf_tail_call` の対象になるため RW 扱い。

`TestSharedMapPartitioning` (`pkg/bpf/maps_test.go`) が「RO と RW が disjoint + 既知マップ全てを網羅」をハードコード辞書で assert する。新マップ追加時に片側に入れ忘れると落ちる。

### プラグイン登録時の分類ログと記録

`PluginServer.PluginRegister` (`pkg/server/plugin.go`) を書き直し、プラグイン ELF が宣言した各 `spec.Maps` を

1. RO にマッチ → `replacements[name] = sharedRO[name]` に入れ、`usedRO` に追加
2. RW にマッチ → 同様に `usedRW` へ
3. どちらにも該当しない → plugin-owned map として ELF 内定義で新規作成、`ownedMaps` へ

と振り分ける。結果は `slog.InfoContext(ctx, "plugin map linkage", …)` で audit ログに構造化出力し、同時に `pluginEntry` に保存する:

```go
type pluginEntry struct {
    program       string
    auxType       *btf.Struct
    ownedMapNames []string
    sharedRWNames []string
    sharedRONames []string
    registeredAt  time.Time
}
```

### `PluginList` RPC + `vbctl plugin list`

`proto/vinbero/v1/plugin.proto` に `PluginList` RPC を追加:

```proto
rpc PluginList(PluginListRequest) returns (PluginListResponse);

message PluginListRequest { string map_type_filter = 1; }
message PluginInfo {
    string map_type = 1;
    uint32 slot = 2;
    string program = 3;
    bool has_aux_type = 4;
    string aux_type_name = 5;
    repeated string owned_map_names = 6;
    repeated string shared_rw_names = 7;
    repeated string shared_ro_names = 8;
    google.protobuf.Timestamp registered_at = 9;
}
message PluginListResponse { repeated PluginInfo plugins = 1; }
```

サーバ側は `PluginServer.SnapshotEntries(mapTypeFilter)` を追加、`map_type / slot` でソートした `[]PluginEntryInfo` を返す。CLI (`pkg/cli/cmd_plugin.go`) は `vbctl plugin list [--type X] [-v]`、verbose 時に owned / shared RO / RW の各リストを展開表示する。

### 非スコープ

- RO マップへの write 命令の asm-level 拒否: Phase 2 送り。現状は audit ログ止まりで、プラグイン作者が誤って write してもロード自体は通る (kernel verifier が read-only bind していない限り)。
- `slot_stats_*` の書き込み許可を「epilogue 経由のみ」に絞る enforce: 同上。

---

## Phase 1d: Typed PluginAux ライフサイクル

**目的**: SID 関数の create / delete サイクルから独立に、プラグイン作者が自分の aux エントリを alloc / update / get / free できるようにする。複数プラグインと builtin が同じ `sid_aux_map` を共有するので、誤って他人の aux を書き換える事故を owner タグで防ぐ。

### Owner 付き indexAllocator

既存の `indexAllocator.Alloc / Free / RecoverUsed` を全削除し、以下の owner 必須 API に置換 (`pkg/bpf/maps.go`):

```go
const AuxOwnerBuiltin = "builtin"
func AuxOwnerPluginTag(mapType string, slot uint32) string {
    return fmt.Sprintf("plugin:%s:%d", mapType, slot)
}
var ErrOwnerMismatch = fmt.Errorf("aux owner mismatch")

type indexAllocator struct {
    mu       sync.Mutex
    freeList []uint32
    maxIndex uint32
    nextNew  uint32
    owners   map[uint32]string  // idx -> owner tag
}

func (a *indexAllocator) AllocOwner(owner string) (uint32, error)
func (a *indexAllocator) FreeOwner(idx uint32, owner string) error
func (a *indexAllocator) OwnerOf(idx uint32) string
func (a *indexAllocator) WithOwnerLocked(idx uint32, owner string, fn func() error) error
func (a *indexAllocator) RecoverWithOwners(owners map[uint32]string)
```

Owner 形式は `builtin` か `plugin:<mapType>:<slot>` の文字列。選択肢として「ownerタグを別 metadata map に格納」する案もあったが、**同一 pool + in-memory metadata** に落ち着いた (sid_aux_map の容量は config で決まるので pool split は避けたい)。

`RecoverAuxIndices` は `sid_function_map` を iterate して `entry.Action >= EndpointPluginBase` なら `plugin:endpoint:<action>`、それ以外は `builtin` として owner を再構築。独立 aux (Phase 1d 新設) はこの経路で拾えないため daemon 再起動で消失する (永続化は Phase 2 の `BPF pinning` 課題)。詳細は [`docs/design/ja/persistence.md`](../design/ja/persistence.md) 参照。

### TOCTOU 対策: `WithOwnerLocked`

初版は `OwnerOf(idx) → SidAuxMap.Put` の 2 step で owner 検証していたが、並走する `FreePluginAux` がチェック成功後・Put 前に idx を再割当できる race があった。`WithOwnerLocked(idx, owner, fn)` に統一し、allocator ロックを握ったまま callback で BPF map op を実行する形にした。`CreateSidFunctionWithAuxIndex` も同じく `expectedOwner` を引数に取りアトミック検証する。

### 単発 aux 操作 API

```go
func (m *MapOperations) AllocPluginAux(owner string) (uint32, error)
func (m *MapOperations) PutPluginAux(idx uint32, raw []byte, owner string) error
func (m *MapOperations) GetPluginAux(idx uint32, owner string) ([]byte, error)
func (m *MapOperations) FreePluginAux(idx uint32, owner string) error
```

Put / Get / Free は全て `WithOwnerLocked` でラップされ、owner mismatch は `ErrOwnerMismatch` を返す (RPC 層で `PermissionDenied` に変換)。

### `validatePluginAuxType`: サイズ事前チェック

`pkg/bpf/plugin_validate.go` に新関数を追加。`VINBERO_PLUGIN_AUX_TYPE(prog, type)` マクロで anchor された `<program>_aux` 構造体を `spec.Types.TypeByName` で探し、`btf.Sizeof` が `SidAuxPluginRawMax (=196)` を超えていたら register 時点で reject する。anchor 無しの plugin は skip (許容)。

### RPC: `PluginAuxAlloc / Update / Get / Free`

`proto/vinbero/v1/plugin.proto` に 4 RPC を追加。Alloc / Update は `oneof payload { string json; bytes raw; }` で payload を受け取る。JSON なら既存 `EncodePluginAux` (BTF 駆動) で byte 列に変換、raw ならそのまま `NewSidAuxPluginRaw` で `sid_aux_entry.plugin_raw` に収まる形に包む。

サーバ実装 (`pkg/server/plugin_aux.go`, 新規) は共通ヘルパ `ownerFor(mapType, slot, idx, requireIdx)` で slot 範囲バリデーション + owner タグ算出 + idx != 0 チェックをまとめて行い、各 RPC はそれを 1 回呼ぶだけ。Owner mismatch は `toRPCError` で `PermissionDenied`、slot 範囲外や payload 不正は `InvalidArgument`、枯渇は `ResourceExhausted`。

### `SidFunction.plugin_aux_index` — 独立 aux を SID に紐づける

`proto/vinbero/v1/vinbero.proto` の `SidFunction` に field 20 として追加。`plugin_aux_raw` (18) / `plugin_aux_json` (19) / `plugin_aux_index` (20) は 3-way mutually exclusive。

`pkg/server/sid_function.go` の `protoToEntry` で:

1. 3 つのうち 2 つ以上指定されたら `InvalidArgument`
2. `plugin_aux_index != 0` なら SID の action が plugin 範囲であることを確認
3. action から map_type / slot を推定し、`CreateSidFunctionWithAuxIndex(triggerPrefix, entry, expectedOwner)` を呼ぶ — owner 検証は `WithOwnerLocked` 内でアトミックに行われる

`DeleteSidFunction` は `entry.AuxIndex != 0` なら owner を read し、builtin なら map ゼロ化 + FreeOwner、plugin owner なら「PluginAuxFree に任せる」で **touch しない** (SID delete で独立 aux を勝手に解放してしまわないため)。

### CLI

`vbctl plugin aux {alloc,update,get,free}` (`pkg/cli/cmd_plugin.go`) を追加。`--json` / `--raw` (hex) どちらかの payload 指定、`--map-type` / `--slot` / `--index` でターゲット指定。`vbctl sid create` には `--plugin-aux-index` フラグ追加、既存 `--plugin-aux-json` / `--plugin-aux-raw` と 3-way 排他。

### Go SDK (`sdk/go/plugin/aux.go`)

ADR-6 で YAGNI として削除されていた `sdk/go/plugin/` パッケージを、`aux.go` + `doc.go` のみ復活。

```go
type PluginAux[T any] struct { ... }

func NewPluginAux[T any](client vinberov1connect.PluginServiceClient,
    mapType string, slot uint32) *PluginAux[T]

func (p *PluginAux[T]) Alloc(ctx context.Context, v T) (uint32, error)
func (p *PluginAux[T]) Update(ctx context.Context, idx uint32, v T) error
func (p *PluginAux[T]) Get(ctx context.Context, idx uint32) (T, error)
func (p *PluginAux[T]) Free(ctx context.Context, idx uint32) error
```

`Alloc / Update` は `json.Marshal(v)` → サーバ側 BTF で C 構造体レイアウトに encode。`Get` は server からの raw bytes を `binary.Read(LittleEndian)` で復元するので、T に「固定サイズ・LittleEndian・C struct 互換」という制約がかかる (`doc.go` に明記)。

### サンプル / E2E

`sdk/examples/plugin-counter/test.sh` に Phase 6 として以下のフローを追加:

1. `vbctl plugin aux alloc --map-type endpoint --slot 32 --json '{"increment":20}'` で idx 払い出し
2. `vbctl sid create --prefix fc00::200/128 --action 32 --plugin-aux-index <idx>` で別 SID を同 idx に束縛
3. `vbctl plugin aux get` で owner タグが `plugin:endpoint:32` に設定されていることを確認
4. `vbctl plugin aux update` で payload を差し替え
5. 別スロット (33) 経由で free しようとして `PermissionDenied` を確認
6. 正しい slot で free → aux クリア

### 新規 / 書き換えテスト

| テスト | 検証内容 |
|---|---|
| `TestIndexAllocatorOwnerRoundTrip` (`pkg/bpf/plugin_aux_alloc_test.go`) | AllocOwner → OwnerOf → FreeOwner |
| `TestIndexAllocatorOwnerMismatch` | cross-owner free が `ErrOwnerMismatch` |
| `TestIndexAllocatorExhaustion` | max_index 超過で error |
| `TestRecoverWithOwners` | builtin / plugin 混在 index から allocator 再構築 |
| `TestValidatePluginAuxType_NilTypes` | BTF types 無しは skip |
| `TestValidatePluginSlot` (`pkg/server/plugin_aux_test.go`) | 各 map_type の plugin slot 範囲境界 |
| `TestEncodePluginAuxPayload_*` | raw / json / mutex / size limit |
| `TestSnapshotEntriesFilterAndSort` (`pkg/server/plugin_test.go`) | map_type filter + ソート順 |

---

## 検証結果

- `make lint` : 0 issues (buf-format / buf-lint / yamllint / golangci-lint / trailing-whitespace / check-executables-have-shebangs / mixed-line-ending)
- `go test ./...` : 全パス (50+ XDP E2E テストケースを含む)
- `make test-runnable` : 両バイナリ起動 OK
- `make sdk-test` : `plugin-counter` / `plugin-acl-prefix` / `simple-acl` 全サンプルが validate 通過
- `sdk/examples/plugin-counter/test.sh` : 既存 embed フロー + Phase 1d の alloc/bind フロー両方で E2E 通過
