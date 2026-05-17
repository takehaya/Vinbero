# Plugin Example (Negative): Read-Only Map Write Violation

このディレクトリは Vinbero Plugin SDK の asm-level RO-write enforcer に対する
**負の例 (negative example)** です。意図的に契約違反となるプラグインを
コンパイルし、`vbctl plugin validate` が確実に reject することを確認するため
だけに存在します。

## 何が違反か

`plugin.c` は vinbero の共有 read-only マップ `sid_function_map` の値を
`bpf_map_lookup_elem()` で取得した後、その `action` フィールドを書き換えます。
プラグインからは `sid_function_map` は **読み取り専用**: コントロールプレーン
の状態をプラグインが上書きすると、vinbero 全体の動作が壊れる可能性があります。

`pkg/bpf/plugin_validate.go::checkROWrites` がこの書き込みを load 前に検出して
reject します。

## ビルドと検証

通常の SDK 例と同じ手順でビルドできます (clang は kernel verifier を呼ばない
ので `.o` 自体は生成されます):

```bash
make -C sdk/examples/plugin-counter-evil
```

その上で `vbctl plugin validate` で reject されることを確認します:

```bash
./out/bin/vinbero plugin validate \
    --prog sdk/examples/plugin-counter-evil/plugin.o \
    --program plugin_counter_evil
# expected: exit code 1, stderr に
#   "plugin program ... has N disallowed map write(s); ..."
```

CI ではルートの `make sdk-test-negative` ターゲットがこの reject を自動検証
します。`make sdk-test` (正の例向け) には含まれません — 含めると CI が
"validate が pass する" を期待して失敗するためです。

## 使ってはいけない

これはあくまで validator のリグレッションテスト用サンプルです。実プラグインの
ひな型としては `sdk/examples/plugin-counter/` を参照してください。
