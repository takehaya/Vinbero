# プラグイン SDK 実装記録 (Phase 0 + 1a + 1b + 1e)

Vinbero の XDP プラグイン SDK を段階的に強化した際の実装記録。`docs/plan/plugin-sdk-enhancement.md` で策定したプランのうち、今回は Phase 0 / 1a / 1b と、path coverage を構造的に保証する追加ステップ Phase 1e を実施した。

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

## 保留 (次回 PR で再検討)

- **Phase 1c**: プラグイン所有マップの lifecycle 管理。現状 `pkg/server/plugin.go` の `coll.Close()` で FD を閉じるため、プラグイン ELF 内で宣言した `acl_deny_map` などを userspace から書き換える経路がない。`pluginRegistry` で Collection を追跡し `Unregister` 時にクローズする案が有力。
- **Phase 1d**: Plugin Aux API。`sid_aux_entry` の union に `__u8 plugin_raw[200]` variant を追加して、`PluginAux[T]` ジェネリック Go ラッパーから型安全にアクセスできるようにする案。Phase 1c で userspace からプラグイン固有マップを叩く経路が整った時点で、Go SDK パッケージ (`sdk/go/plugin/`) の復元と合わせて検討する。
- **SDK 配布体験の改善**: 現状 `sudo make install-sdk` は vinbero リポジトリを clone した状態でないと実行できず、完全に外部のプラグイン作者には体験が重い。改善案:
  - **案 A (推奨): SDK tarball のリリース**. goreleaser に `vinbero-sdk-vX.Y.tar.gz` を追加。中身は `sdk/c/include/vinbero/*.h` + 必要な `src/core/*.h` + `Makefile.plugin`。ユーザーは `curl -L .../vinbero-sdk.tar.gz \| sudo tar xz -C /` で完結。既存 `install-sdk` のロジックを再利用して `sdk-archive` ターゲット追加する程度の工数で、リリースごとに SDK バージョンが固定できるのでバージョニングも綺麗
  - **案 B: 単一ヘッダ化**. `quom`/`amalgamate` で公開ヘッダ一式を `vinbero.h` 1 ファイルにマージ。`curl -o vinbero.h ...` 1 発で済むが、デバッグ時の line 番号と元 source の乖離が発生
  - **案 C: Docker image**. `ghcr.io/takehaya/vinbero-plugin-builder` を公開、`docker run --rm -v $PWD:/work ... make` で完結。CI 統合しやすいが image 更新追跡が面倒
  - **案 D: apt/RPM パッケージ**. `apt install vinbero-sdk` は最もユーザーフレンドリだがメンテ負担最大
  - 案 A が ROI 最高。現状は in-tree 開発 (`sdk/examples/*/Makefile` が `VINBERO_SDK_ROOT` を override する方式) で最低限成立しているので今回スコープ外

詳細な背景・代替案の比較は `docs/plan/plugin-sdk-enhancement.md` に ADR として残してある。

### 既に撤去されたもの

- **Go SDK パッケージ (`sdk/go/plugin/`)**: Phase 1b で初期実装したが、リポジトリ内 import ゼロ + CLI と機能完全重複のため YAGNI 判断で削除 (ADR-6)。復元条件は Phase 1c 実装時。
- **SDK 配下への examples 集約**: サンプルは `sdk/examples/plugin-counter/` (E2E デモ) と `sdk/examples/simple-acl/` (ビルド確認) に集約 (ADR-7)。

---

## 検証結果

- `make lint` : 0 issues (buf-format / buf-lint / yamllint / golangci-lint / trailing-whitespace / check-executables-have-shebangs / mixed-line-ending)
- `go test ./...` : 全パス (50+ XDP E2E テストケースを含む)
- `make test-runnable` : 両バイナリ起動 OK
- `make sdk-test` : `packet-counter` / `simple-acl` 両サンプルが validate 通過
