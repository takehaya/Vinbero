# src/ ディレクトリ リファクタリング設計書

## 背景

`src/` ディレクトリは現在22ファイルがフラットに配置されている。プロジェクトの成長に伴い、以下の問題が顕在化している:

- **構造化の欠如**: SRv6エンドポイント、ヘッドエンド、GTP-U、L2VPN等の異なる機能群が同一ディレクトリに混在
- **巨大ファイル**: `srv6_endpoint.h` (784行) が基本End、DX/DT系、DT2(FDB)、フレーバー処理を1ファイルに詰め込み
- **xdp_prog.c の肥大化**: メインエントリ、ヘッドエンドディスパッチ、L2 encap実装、BD転送が835行に集約
- **デッドコード**: 未使用の関数・include・ファイルが残存

## 新ディレクトリ構造

```
src/
├── xdp_prog.c                  # メインXDP/TCプログラム
├── core/                        # インフラ・基盤定義
│   ├── xdp_prog.h              # コア型定義、マクロ
│   ├── xdp_map.h               # BPFマップ定義
│   ├── xdp_stats.h             # 統計カウンター
│   ├── xdpcap.h                # パケットキャプチャフック
│   ├── srv6.h                  # SRv6プロトコル定数
│   └── srv6_fib.h              # FIBルックアップヘルパー
├── headend/                     # ヘッドエンド encapsulation
│   ├── srv6_headend.h          # モードバリデータ
│   ├── srv6_headend_utils.h    # セグメントコピー
│   ├── srv6_encaps.h           # H.Encaps コア
│   ├── srv6_encaps_red.h       # H.Encaps.Red
│   ├── srv6_insert.h           # H.Insert / H.Insert.Red
│   └── srv6_encaps_l2.h        # H.Encaps.L2 (xdp_prog.cから抽出)
├── endpoint/                    # SRv6エンドポイント関数
│   ├── srv6_endpoint_core.h    # 共通コンテキスト・ユーティリティ
│   ├── srv6_endpoint_basic.h   # End, End.X, End.T
│   ├── srv6_endpoint_decap.h   # End.DX2/4/6, End.DT4/6/46
│   ├── srv6_endpoint_l2.h      # End.DT2 (FDB学習含む)
│   ├── srv6_endpoint.h         # ファサード (全endpoint headerを再export)
│   ├── srv6_end_b6.h           # End.B6 ポリシーチェイニング
│   └── srv6_decaps.h           # デカプセル化ヘルパー
├── mobile/                      # モバイル連携 (GTP-U/SRv6 interworking)
│   ├── srv6_gtp.h              # GTP-Uプロトコル定義
│   ├── srv6_gtp_decap.h        # H.M.GTP4.D, End.M.GTP6.D/Di
│   └── srv6_gtp_encap.h        # End.M.GTP4.E, End.M.GTP6.E
└── l2vpn/                       # L2VPN / BUM
    ├── bum_meta.h              # BUMメタデータ
    └── tc_bum.h                # TC BUMクローニング
```

## 実施フェーズ

### Phase 0: デッドコード削除

| 対象 | ファイル | 理由 |
|------|----------|------|
| `#include <linux/tcp.h>` | xdp_prog.c | TCP構造体の使用なし |
| `#include <string.h>` | xdp_prog.c | `__builtin_memcpy`のみ使用 |
| `headend_should_encaps()` | srv6_headend.h | 未呼び出し |
| `headend_should_encaps_l2()` | srv6_headend.h | 未呼び出し |
| `srv6_fib_lookup_and_update_nexthop()` | srv6_fib.h | 未呼び出し |
| `xdp_vlan.h` 全体 | - | 全関数未使用 |
| `xdp_utils.h` 全体 | - | `struct vlan_hdr`をxdp_prog.hに統合後削除 |

### Phase 1: ディレクトリ分離・include更新

- 5つのサブディレクトリを作成
- `git mv` で既存ファイルを移動
- 全ファイルの `#include` パスを `src/` ルートからの相対パスに統一
  - 例: `#include "xdp_prog.h"` → `#include "core/xdp_prog.h"`

### Phase 2: srv6_endpoint.h の分割

784行の巨大ファイルを機能別に4分割:
- `srv6_endpoint_core.h`: 共通インフラ (endpoint_ctx, init, fib_redirect, strip_srh, flavors)
- `srv6_endpoint_basic.h`: 基本エンドポイント (End, End.X, End.T)
- `srv6_endpoint_decap.h`: デカプセル系 (End.DX2/4/6, End.DT4/6/46)
- `srv6_endpoint_l2.h`: L2ブリッジング (End.DT2, FDB学習)

元の `srv6_endpoint.h` はファサードとして残し、4ファイルを再exportする。

### Phase 3: L2 encap関数のxdp_prog.cからの抽出

`do_h_encaps_l2()`, `do_h_encaps_l2_red*()` を `headend/srv6_encaps_l2.h` に抽出。
これにより前方宣言が不要になり、xdp_prog.cは~570行に削減される。

### Phase 4: DO_L3_PROCESS マクロの関数化

40行の巨大マクロ `DO_L3_PROCESS` を `__noinline` 関数 `process_l3()` に置換。
マクロは `goto out` と暗黙的な変数キャプチャで可読性が極めて悪い。
`__noinline` でBPFサブプログラム境界を作り、ポインタ再導出を関数内で完結させる。

## スコープ外

- 命名規則の統一: 現在のprocess_*/do_*/endpoint_*は一貫した意味論があり変更不要
- v4/v6ラッパーの統合: BPFバリファイアの制約上、薄いラッパーは適切
- srv6_gtp_decap.hの分割: mobile/ディレクトリ分離で十分整理される
- CHECK_BOUND/ADVANCE_PTRマクロ: 短く標準的なBPFパターン、可読性に問題なし
