
# TC BPF BUM転送 + P2MP + Remote MAC Learning 設計ドキュメント

## 概要

L2VPN (H.Encaps.L2 + End.DT2) において、BUM (Broadcast/Unknown unicast/Multicast) フレームを
対向PEへSRv6転送するためのTC BPFプログラム。P2MP (複数リモートPE) に対応し、
End.DT2 での data-plane MAC learning によりリモートMACを自動学習する。

## 背景

XDPは1パケットに対して1アクションしか返せない（clone不可）。
BUMフレームは「ローカルflood + リモートPEへのSRv6転送」の両方が必要だが、XDP単独では実現できない。

## アーキテクチャ

### P2MP トポロジ

```
                      ┌─── PE2 ←→ host2
host1 ←→ PE1 ←→ P ──┤     End.DT2 + H.Encaps.L2
              End     └─── PE3 ←→ host3
    H.Encaps.L2            End.DT2 + H.Encaps.L2
    + TC ingress
```

BD=100 に PE1, PE2, PE3 が参加。各 PE に Vinbero (XDP + TC) が動作。

### XDP→TC メタデータ連携

`bpf_xdp_adjust_meta` で `__u64` (8バイト) のメタデータを書き込む。

```
__u64 meta layout:
  [63:32] marker (0x564E4255 = "VNBU")
  [15:0]  vlan_id (XDPが解析済み)
  [31:16] reserved
```

### 処理フロー

```
H.Encaps.L2 パス (customer port ingress):
  XDP:
    src MAC → ローカル学習 (fdb_map: is_remote=0)
    dst MAC →
      ├─ BUM (multicast bit) → meta + XDP_PASS → TC flood
      ├─ FDB hit, local (is_remote=0) → XDP_PASS (bridge)
      ├─ FDB hit, remote (is_remote=1) → bd_peer_map → SRv6 encap → redirect
      └─ FDB miss → meta + XDP_PASS → TC flood (unknown unicast)

  TC ingress (vinbero_tc_ingress):
    ├─ meta なし → TC_ACT_OK
    └─ meta あり → headend_l2_map → bd_id
        → bd_peer_map[(bd_id, 0..7)] ループ
        → 各 PE に encap → clone → restore
        → TC_ACT_OK (オリジナルは bridge flood)

End.DT2 パス (SRv6 decap):
  XDP:
    outer IPv6 src を保存
    SRv6 decap → inner L2 frame
    inner src MAC → remote MAC learning:
      bd_peer_map iterate → outer src と一致する peer_index を特定
      fdb_map に (is_remote=1, peer_index, bd_id) を書き込み
    inner dst MAC → fdb_map lookup → local redirect or XDP_PASS
```

## BPF Map

| マップ | キー | 値 | 用途 |
|--------|------|-----|------|
| `headend_l2_map` | (ifindex, vlan_id) | headend_entry | Port+VLAN → L2 encap設定 |
| `fdb_map` | (bd_id, MAC) | fdb_entry | MAC → ローカル/リモート判定 |
| `bd_peer_map` | (bd_id, index) | headend_entry | BD内のリモートPE flood list |

### fdb_entry (12B)

```c
struct fdb_entry {
    __u32 oif;           // local: ifindex, remote: 0
    __u8 is_remote;      // 0=local, 1=remote
    __u8 _pad;
    __u16 peer_index;    // bd_peer_map の index (remote時)
    __u16 bd_id;         // BD ID (remote時)
    __u8 _pad2[2];
};
```

### bd_peer_key

```c
struct bd_peer_key {
    __u16 bd_id;
    __u16 index;   // 0..MAX_BUM_NEXTHOPS-1 (max 8)
};
```

## ファイル構成

| ファイル | 役割 |
|---------|------|
| `src/bum_meta.h` | XDP↔TC共有: marker定数, `xdp_write_bum_meta()`, `tc_read_bum_meta()` |
| `src/tc_bum.h` | TC: `tc_do_bum_encaps_and_clone()`, `tc_do_bum_flood()`, TC FIB lookup |
| `src/xdp_prog.c` | XDP: BUM/FDB miss meta書き込み, remote FDB hit encap, TC entry point `vinbero_tc_ingress` |
| `src/xdp_prog.h` | fdb_entry 拡張, bd_peer_key 定義 |
| `src/xdp_map.h` | bd_peer_map 定義 |
| `src/srv6_endpoint.h` | End.DT2: remote MAC learning (`find_peer_index_by_src`) |
| `pkg/bpf/maps.go` | BdPeer CRUD operations |
| `pkg/server/bd_peer.go` | BdPeerService Connect RPC ハンドラ |

## API

### BdPeerService

```
POST /vinbero.v1.BdPeerService/BdPeerCreate
  { "peers": [{ "bd_id": 100, "src_addr": "fc00:1::1", "segments": ["fc00:2::1", "fc00:3::3"] }] }

POST /vinbero.v1.BdPeerService/BdPeerDelete
  { "bd_ids": [100] }

POST /vinbero.v1.BdPeerService/BdPeerList
  { "bd_id": 100 }
```

## 技術詳細

### P2MP encap → clone → restore ループ
TC が `bd_peer_map` を `#pragma unroll` で最大 8 回ループ。各イテレーションで:
1. `bpf_skb_adjust_room(+N)` で SRv6 ヘッダ分拡張
2. Outer Eth + IPv6 + SRH 書き込み
3. `bpf_fib_lookup` で next-hop MAC 解決
4. `bpf_clone_redirect` で encap 済み clone 送出
5. `bpf_skb_adjust_room(-N)` で元フレームに復元

### Remote MAC Learning
End.DT2 decap 時に `bd_peer_map` を iterate (MAX=8) して outer IPv6 src と一致する PE を特定。
inner src MAC を `fdb_map` に `is_remote=1` で書き込み。以後の unicast は `bd_peer_map` 経由で直接 encap。

### Graceful Degradation
- `bpf_xdp_adjust_meta` 失敗 → ローカル flood のみ (リモート転送欠落)
- `bd_peer_map` 空 → TC で flood ループがスキップ (BUM はローカルのみ)
- `find_peer_index_by_src` で PE 見つからない → MAC 未学習 (FDB miss でフォールバック)

## 将来の拡張

- **DF (Designated Forwarder) フィルタリング**: EVPN multi-homing での BUM 出し分け
- **EVPN コントロールプレーン連携**: BGP Type-2/Type-3 route による MAC/PE 配布
