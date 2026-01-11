# Vinbero Examples

VinberoのSRv6機能を実際に試せるPlayground環境です。

GitHub Actionsのmatrix strategyにより、各exampleは独立したジョブとして並列実行されます。
## クイックスタート

```bash
cd examples/end
sudo ./setup.sh    # 環境構築
sudo ./test.sh     # テスト実行
sudo ./teardown.sh # クリーンアップ
```

各exampleはディレクトリ名をプレフィックスとして独自のnamespace空間を持つため（例: `end-host1`, `end-router1`）、衝突なく並列実行できます。

## 新しいExampleの追加
1. **ディレクトリを作成**: `examples/<name>/`
2. **必要なファイル**:
   - `README.md`: シナリオの説明
   - `setup.sh`: 環境構築（`common/`の関数を使用）
   - `test.sh`: テスト実行
   - `teardown.sh`: クリーンアップ
   - `vinbero_*.yaml`: Vinbero設定
3. **プレフィックス設定**:
   ```bash
   EXAMPLE_NAME="$(basename "$SCRIPT_DIR")"
   export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-${EXAMPLE_NAME}-}"
   ```
4. **ワークフローに追加**: `.github/workflows/examples.yaml`のmatrixに追加

## 共通機能

各exampleで使える共通ユーティリティ：

- **`common/netns.sh`**: namespace操作（create/delete/srv6有効化/sysctl設定）
- **`common/veth.sh`**: vethペア作成とIP設定（IPv4/IPv6自動判定）
- **`common/test_utils.sh`**: テストヘルパー（ping疎通確認、root権限チェック、カラー出力）
- **`common/topologies/three_router.sh`**: 3ルータートポロジーの構築/削除（設定変数でカスタマイズ可能）
