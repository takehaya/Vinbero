# End.X / End.T / SRv6 Flavors (PSP, USP, USD) 実装設計

## Context

Vinberoは現在、End, End.DX2/DX4/DX6, End.DT2/DT4/DT6/DT46 をサポートしているが、End.X, End.T はスタブのみ（XDP_PASS返却）で未実装。SRv6フレーバー（PSP/USP/USD）はproto定義とBPFマップにフィールドが存在するが、エンドポイント処理で使われていない。

RFC 8986に準拠したこれらの機能を実装し、Phase 1のSRv6機能を完成させる。

## Phase 1: End.T（最小変更）

**概要**: End と同じだが、FIBルックアップを特定のVRF（ルーティングテーブル）で行う。

### BPF変更 — `src/srv6_endpoint.h`

1. `endpoint_fib_redirect()` をリファクタリングして `ifindex` パラメータを受け取るようにする:

```c
// 既存の endpoint_fib_redirect を修正: ifindex パラメータ追加
static __always_inline int endpoint_fib_redirect(struct endpoint_ctx *ectx, __u32 fib_ifindex)
```

2. `process_end()` の呼び出しを `endpoint_fib_redirect(&ectx, ectx.ctx->ingress_ifindex)` に更新

3. `process_end_t()` のスタブを実装に置き換え:
```c
__u32 fib_ifindex = entry->vrf_ifindex ? entry->vrf_ifindex : ctx->ingress_ifindex;
return endpoint_fib_redirect(&ectx, fib_ifindex);
```

### テスト変更 — `pkg/bpf/`

- `xdp_test_helpers_test.go`: `actionEndT` 定数追加
- `xdp_test.go`: `TestXDPProgEndT` 追加（SL=0/1/2テスト、DA更新検証）
  - `createSidFunctionWithVRF()` を再利用（既存ヘルパー）

### CLI/API変更: なし（`--vrf-name` フラグは既存）

---

## Phase 2: End.X（FIBルックアップの新パターン）

**概要**: End と同じDA更新だが、更新されたDAではなく `entry->nexthop` のIPv6アドレスでFIBルックアップして転送先を解決する。

### BPF変更 — `src/srv6_fib.h`

nexthop指定のFIBルックアップヘルパーを追加:

```c
static __always_inline int srv6_fib_lookup_and_update_nexthop(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,  // saddr のソースとして使用
    struct ethhdr *eth,
    __u32 *out_ifindex,
    __u8 *nexthop,         // 16バイト nexthop IPv6アドレス（DAの代わりに使用）
    __u32 ifindex)
```

- `fib_params.ipv6_src` は `ip6h->saddr` から
- `fib_params.ipv6_dst` は `nexthop` から（`ip6h->daddr` ではない）
- `bpf_fib_lookup` 成功時にeth MACを更新、ifindex返却

### BPF変更 — `src/srv6_endpoint.h`

1. `endpoint_fib_redirect_nexthop()` ヘルパー追加:

```c
static __always_inline int endpoint_fib_redirect_nexthop(struct endpoint_ctx *ectx)
```

- `ectx->entry->nexthop` を使って `srv6_fib_lookup_and_update_nexthop()` を呼ぶ
- 成功時 `bpf_redirect`、失敗時 XDP_PASS/XDP_DROP

2. `process_end_x()` のスタブを実装に置き換え:
```c
if (endpoint_update_da(&ectx) != 0) return XDP_DROP;
return endpoint_fib_redirect_nexthop(&ectx);
```

### テスト変更 — `pkg/bpf/`

- `xdp_test_helpers_test.go`:
  - `actionEndX` 定数追加
  - `createSidFunctionWithNexthop(prefix, action, nexthop [16]byte)` ヘルパー追加
- `xdp_test.go`: `TestXDPProgEndX` 追加（SL=0/1/2テスト、DA更新検証）
  - FIBルックアップはテスト環境では失敗するのでXDP_PASS期待（Endと同じ）

### CLI/API変更: なし（`--nexthop` フラグは既存）

---

## Phase 3: SRv6フレーバー（PSP / USP / USD）

### 3a: フレーバー基盤

#### BPF側 — `src/srv6.h`

既存の `srv6_local_flavor` enum（PSP=2, USP=3, USD=4）をそのまま使用。
BPF側では `entry->flavor == SRV6_LOCAL_FLAVOR_PSP` のようにenum値の直接比較で判定。

#### Proto/Go側

proto enum値をそのまま `uint8(sidFunc.Flavor)` でBPFマップに書き込み。変換不要。

#### CLI — `pkg/cli/cmd_sid.go`

- `--flavor` フラグ追加（`StringFlag`、例: "PSP", "USP", "USD"）
- `resolve.go` に `resolveFlavor()` 追加
- list表示にFLAVOR列追加

### 3b: PSP（Penultimate Segment Pop）

**動作**: SL=1のパケット処理で `new_sl` が0になった時、DAを更新した後にSRHを除去してから転送。End, End.X, End.T に適用。

#### SRH除去ヘルパー — `src/srv6_endpoint.h`

`endpoint_strip_srh()` を追加。`srv6_decap()` と同じパターンを応用:

```
Before: [Eth(14)][IPv6(40)][SRH(8+N*16)][Upper Layer]
After:  [Eth(14)][IPv6(40)][Upper Layer]  (SRH除去、IPv6ヘッダは保持)
```

実装手順:
1. Eth + IPv6ヘッダをスタックに保存（計54バイト、BPFスタック512B制限内）
2. SRHのnexthdr値を保存
3. `bpf_xdp_adjust_head(ctx, ETH_HLEN + sizeof(ipv6hdr) + srh_len)` でEth+IPv6+SRHを除去
4. `bpf_xdp_adjust_head(ctx, -(ETH_HLEN + sizeof(ipv6hdr)))` でEth+IPv6ヘッダ分を再確保
5. 保存したEth + IPv6ヘッダを書き戻し
6. `ip6h->nexthdr = saved_nexthdr` に更新
7. `ip6h->payload_len -= srh_len` に更新

#### エンドポイント統合

End/End.X/End.T の `endpoint_update_da()` の後に:
```c
if (ectx.new_sl == 0 && (entry->flavor & SRV6_FLAVOR_PSP)) {
    if (endpoint_strip_srh(&ectx) != 0) return XDP_DROP;
}
// FIBルックアップ（既存のendpoint_fib_redirect等）
```

`endpoint_fib_redirect()` は `ctx->data` からポインタを再取得するため、SRH除去後も正常動作する。

#### テスト

`TestXDPProgEndPSP`:
- SL=1 + PSP: SRH除去を検証（出力パケットのIPv6 nexthdr != 43）
- SL=2 + PSP: 通常のEnd動作（PSPはnew_sl==0の時のみ）
- SL=0 + PSP: 上位レイヤーにパス（SL=0は通常処理）

### 3c: USP（Ultimate Segment Pop）

**動作**: SL=0で到着したパケットに対し、通常のXDP_PASSの代わりにSRHを除去してFIBルックアップ。

#### BPF変更 — `src/srv6_endpoint.h`

`endpoint_handle_usp()` ヘルパー:
1. `endpoint_strip_srh()` でSRH除去
2. `endpoint_fib_redirect()` で更新済みDAに基づきFIBルックアップ

End/End.X/End.T の SL=0 パス:
```c
if (ret == -1) { // SL=0
    if (entry->flavor & SRV6_FLAVOR_USP) {
        return endpoint_handle_usp(/* ... */);
    }
    return XDP_PASS;
}
```

注意: USPではDAの更新は行わない（SL=0なのでSegment Listからのコピーなし）。現在のDAでFIBルックアップする。

#### テスト

`TestXDPProgEndUSP`:
- SL=0 + USP: SRH除去を検証
- SL=1 + USP: 通常のEnd動作（USPはSL=0の時のみ）

### 3d: USD（Ultimate Segment Decapsulation）

**動作**: SL=0で到着したパケットに対し、内部パケットをデカプセレーション（End.DX4/DX6相当だが自動プロトコル検出）。

#### BPF変更 — `src/srv6_endpoint.h`

End/End.X/End.T の SL=0 パス:
```c
if (ret == -1) { // SL=0
    if (entry->flavor & SRV6_FLAVOR_USD) {
        __u8 inner_proto = srh->nexthdr;
        if (inner_proto == IPPROTO_IPIP)
            return process_end_dx4(ctx, ip6h, srh, entry);
        if (inner_proto == IPPROTO_IPV6)
            return process_end_dx6(ctx, ip6h, srh, entry);
        return XDP_DROP;
    }
    if (entry->flavor & SRV6_FLAVOR_USP) {
        return endpoint_handle_usp(/* ... */);
    }
    return XDP_PASS;
}
```

既存の `process_end_dx4/dx6` を再利用（SL=0チェックは通過する）。

#### テスト

`TestXDPProgEndUSD`:
- SL=0 + USD + inner IPv4: デカプセレーション検証
- SL=0 + USD + inner IPv6: デカプセレーション検証
- SL=1 + USD: 通常のEnd動作

---

## 対象ファイル一覧

| ファイル | 変更内容 |
|---------|---------|
| `src/srv6_endpoint.h` | End.X/End.T実装、PSP SRH除去、USP/USDハンドラ、フレーバー統合 |
| `src/srv6_fib.h` | nexthop指定FIBルックアップヘルパー追加 |
| `src/srv6.h` | フレーバービットマスク定義追加 |
| `pkg/bpf/xdp_test.go` | End.X/End.T/PSP/USP/USDテスト追加 |
| `pkg/bpf/xdp_test_helpers_test.go` | actionEndX/EndT定数、createSidFunctionWithNexthop/WithFlavor |
| `pkg/server/sid_function.go` | flavorToBitmask変換関数 |
| `pkg/cli/cmd_sid.go` | `--flavor` フラグ追加 |
| `pkg/cli/resolve.go` | `resolveFlavor()` 追加 |
| `docs/loadmap.md` | End.X, End.T, PSP, USP, USD を Supported に更新 |

## 実装順序

```
Phase 1: End.T → Phase 2: End.X → Phase 3a: フレーバー基盤 + PSP → Phase 3b: USP → Phase 3c: USD
```

各フェーズは独立してコンパイル・テスト可能。Phase 1と2は並行開発も可。

## 検証手順

1. `make bpf-gen` でBPFコード再生成
2. `go test -exec sudo -run TestXDPProgEndT github.com/takehaya/vinbero/pkg/bpf`
3. `go test -exec sudo -run TestXDPProgEndX github.com/takehaya/vinbero/pkg/bpf`
4. `go test -exec sudo -run TestXDPProgEndPSP github.com/takehaya/vinbero/pkg/bpf`
5. `go test -exec sudo -run TestXDPProgEndUSP github.com/takehaya/vinbero/pkg/bpf`
6. `go test -exec sudo -run TestXDPProgEndUSD github.com/takehaya/vinbero/pkg/bpf`
7. `make test` で全テスト通過確認
8. `make lint` でリント通過確認
