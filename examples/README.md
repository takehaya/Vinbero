# Vinbero Examples

VinberoのSRv6機能を実際に試せるPlayground環境です。

ここには2系統のサンプルがあります。

- netns example（このディレクトリ直下の `end-*` / `headend-*` / `gtp*-*`）。各 SRv6 機能を単独の Linux network namespace 上で検証する自己完結スクリプト。`test.yaml` の matrix に登録した example を CI で並列実行します。matrix 未登録の example はローカル実行のみです。
- interop ラボ（[`interop-clab/`](interop-clab/)）。Vinbero を FRR など第三者実装と相互運用させる containerlab シナリオ群。

このページは netns example を説明します。interop ラボは [`interop-clab/README.md`](interop-clab/README.md) を参照してください。

## 前提のビルド

netns example は `out/bin/vinberod` と `out/bin/vinbero` を使います。clone 直後は repo ルートで一度ビルドしてください。

```bash
make protobuf-gen && make bpf-gen && make build
```

ビルドしていないと `setup.sh` は通っても `test.sh` が Vinbero failed to start で落ちます。

## クイックスタート

```bash
cd examples/end
sudo ./setup.sh    # 環境構築
sudo ./test.sh     # テスト実行
sudo ./teardown.sh # クリーンアップ
```

各 example は固有のプレフィックスで独自の namespace 空間を持つため（例: `end-host1`、`dx4-router1`）、衝突なく並列実行できます。

## 新しいExampleの追加
1. **ディレクトリを作成**: `examples/<name>/`
2. **必要なファイル**:
   - `README.md`: シナリオの説明
   - `setup.sh`: 環境構築（`common/`の関数を使用）
   - `test.sh`: テスト実行
   - `teardown.sh`: クリーンアップ
   - `vinbero_*.yaml`: Vinbero設定
3. **プレフィックス設定**: 他 example と衝突しない固有のプレフィックスを `TOPO_NS_PREFIX` に設定します。ディレクトリ名から導くか、短い固有文字列を直接指定します。
   ```bash
   EXAMPLE_NAME="$(basename "$SCRIPT_DIR")"
   export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-${EXAMPLE_NAME}-}"
   # または短い固有プレフィックス: export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-dx4-}"
   ```
4. **ワークフローに追加**: `.github/workflows/test.yaml`の`Integration Test`ジョブの`matrix.example`に追加

## 共通機能

各exampleで使える共通ユーティリティ：

- **`common/netns.sh`**: namespace操作（create/delete/srv6有効化/sysctl設定）
- **`common/veth.sh`**: vethペア作成とIP設定（IPv4/IPv6自動判定）
- **`common/test_utils.sh`**: テストヘルパー（ping疎通確認、vinberodデーモン起動/readyチェック、root権限チェック、カラー出力）
- **`common/topologies/three_router.sh`**: 3ルータートポロジーの構築/削除（設定変数でカスタマイズ可能）

## Example一覧

### Endpoint Functions
| ディレクトリ | 機能 | 説明 |
|---|---|---|
| `end/` | End | 基本SRHエンドポイント処理 |
| `end-x/` | End.X | ネクストホップ指定のクロスコネクト |
| `end-t/` | End.T | VRF指定のFIBルックアップ |
| `end-dx4/` | End.DX4 | IPv4デカプセレーション |
| `end-dx6/` | End.DX6 | IPv6デカプセレーション |
| `end-dt4/` | End.DT4 | VRF対応IPv4テーブルルックアップ |
| `end-dt6/` | End.DT6 | VRF対応IPv6テーブルルックアップ |
| `end-dt2/` | End.DT2 | L2VPN（FDB学習 + ブリッジ転送） |
| `end-dt2-p2mp/` | End.DT2 P2MP | マルチサイトL2VPN（BUMフラッディング） |
| `end-dt2m-multihomed/` | End.DT2M | multi-homed L2VPN（DF election + split-horizon） |
| `end-dx2v/` | End.DX2V | VLAN単位のL2クロスコネクト |
| `end-un/` | uN | NEXT-C-SID の shift 転送 (RFC 9800、F3216) |
| `end-ua/` | uA | NEXT-C-SID の shift + adjacency 転送 (RFC 9800、F3216) |
| `end-ut/` | uT | NEXT-C-SID の shift + VRF table 転送 (RFC 9800、F3216) |
| `end-udt4/` | uDT4 | container 最終 uSID の End.DT4 (zero-padded /128 の LPM 優先) |
| `end-un-usd/` | uN + USD | SRH なし container 終端での outer decap |
| `end-replace/` | End(REP) | REPLACE-CSID の container walk (RFC 9800、32bit C-SID) |

### Headend Functions
| ディレクトリ | 機能 | 説明 |
|---|---|---|
| `headend-v4/` | H.Encaps (IPv4) | IPv4パケットのSRv6カプセル化 |
| `headend-v6/` | H.Encaps (IPv6) | IPv6パケットのSRv6カプセル化 |
| `headend-l2/` | H.Encaps.L2 | L2フレームのSRv6カプセル化 |
| `headend-ecmp/` | H.Encaps + ECMP | headend ECMP path group と liveness fast reroute |

### Mobile (GTP-U)
| ディレクトリ | 機能 | 説明 |
|---|---|---|
| `gtp4-encap/` | H.M.GTP4.D + End.M.GTP4.E | GTP-U/IPv4とSRv6の相互変換 |
| `gtp6-encap/` | H.M.GTP6.D + End.M.GTP6.E | GTP-U/IPv6とSRv6の相互変換 |
| `gtp6-drop-in/` | End.M.GTP6.D.Di | GTP-U Drop-Inモード |

### Plugin Extension

プラグインによる拡張は SDK で行います。サンプル (ビルド確認 + E2E デモ) は [`../sdk/examples/`](../sdk/examples/) 参照、プラグインの書き方は [Plugin SDK ドキュメント](../docs/design/ja/plugin-sdk.md) 参照。
