# BUM Traffic Forwarding — 実装解説

## 概要

L2VPN（H.Encaps.L2 + End.DT2）において、BUM（Broadcast / Unknown unicast / Multicast）フレームを
リモートPEへSRv6転送する機能。XDPにはパケットクローン機能がないため、TC BPFの`bpf_clone_redirect`による
**clone-to-self パターン**で実現している。

## 背景と制約

### なぜTCが必要か

XDPは1パケットに対して1アクション（DROP / PASS / REDIRECT）しか返せない。
BUMフレームは「ローカルflood」と「リモートPEへのSRv6転送（複数PE分）」の両方が必要だが、XDP単独では不可能。

### bd_id による動作の分岐

| bd_id | 動作 | 用途 |
|-------|------|------|
| 0 | 直接 H.Encaps.L2（全トラフィックをSRv6 encap） | P2P L2VPN（Bridge Domain不使用） |
| >0 | MAC学習 + FDB判定 + BUM flood | P2MP L2VPN（Bridge Domain使用） |

bd_id=0は従来のH.Encaps.L2（#7以前）と同じ動作を維持。BD機能はbd_id>0のときのみ有効。

## アーキテクチャ

### トポロジ例

```
                      ┌─── PE2 (router3) ←→ host2
host1 ←→ PE1 (router1) ←→ P (router2) ──┤
              H.Encaps.L2        End      └─── PE3 ←→ host3
              + TC ingress                     End.DT2 + H.Encaps.L2
```

BD=100 に PE1, PE2, PE3 が参加。各PEにVinbero（XDP + TC）が動作。

### 全体フロー（forward path: host1 → host2）

```
host1: ARP broadcast (VLAN 100) 送信
  │
  ▼
PE1 XDP (vinbero_main):
  │ headend_l2_map (ifindex, vlan_id=100) → bd_id=100
  │ process_bd_forwarding:
  │   ├── src MAC学習 → fdb_map に (bd_id=100, srcMAC) = local
  │   ├── dst MAC = broadcast (0x01 bit) → BUM
  │   └── xdp_write_bum_meta(vlan_id=100) → XDP_PASS
  │
  │ ★ カーネルが xdp_buff → skb 変換
  │ ★ VLAN tag がパケットデータから skb->vlan_tci に移動
  ▼
PE1 TC ingress (vinbero_tc_ingress):
  │ tc_read_bum_meta → vlan_id=100
  │ tc_dispatch_bum_clones (Mode 1):
  │   ├── bd_peer_map[(100, 0)] → PE2 の encap 情報
  │   │   cb[] = {MAGIC, bd_id=100, pe_index=0, vlan_id=100}
  │   │   bpf_clone_redirect(self, INGRESS) → clone を自分の TC に再投入
  │   │
  │   └── 元パケット → TC_ACT_OK → bridge → ローカル flood
  │
  ▼ (clone が TC ingress に再投入)
PE1 TC ingress (再入):
  │ cb[0] == MAGIC → tc_do_single_pe_encap (Mode 2):
  │   ├── cb[3] から vlan_id=100 を取得
  │   ├── bpf_skb_vlan_pop (HW VLAN 除去)
  │   ├── bpf_skb_change_head(outer_headers + 4) — VLAN tag 分の余裕確保
  │   ├── Outer Eth + IPv6 + SRH 書き込み
  │   ├── bpf_fib_lookup → next-hop MAC 解決
  │   ├── VLAN materialization: inner frame に VLAN tag を手動復元
  │   └── bpf_redirect(uplink) → SRv6 パケット送出
  ▼
P (router2): End (SRH transit) → 次の segment へ転送
  ▼
PE2 (router3) XDP: End.DT2 (decap)
  │ outer IPv6 src を保存
  │ SRv6 decap → inner L2 frame (VLAN 100 付き)
  │ Remote MAC learning: inner src MAC を fdb_map に remote エントリとして記録
  │ dst MAC → FDB miss → bpf_redirect(bridge_ifindex) → bridge flood
  ▼
host2: VLAN 100 の ARP を受信
```

## clone-to-self パターン

### なぜ2段階か

`bpf_clone_redirect`は**パケットのコピーを送り出す**だけで、コピーの中身を個別に変更できない。
ループ内でヘッダを書いてからcloneすると、元パケットも変わってしまい次のPE用に壊れる。

```
✗ ダメな案:
  for each PE:
    encap(skb)          → 元パケットが変わる
    clone_redirect()    → encap済みコピーを送出
    restore(skb)        → bpf_skb_adjust_room が L2 frame で ENOTSUPP

✓ 実装:
  Mode 1: for each PE: clone_redirect(self) → コピーを自分に戻す
  Mode 2: 戻ってきた個別のcloneを encap → redirect
  元パケットは無傷
```

### Mode 1: Dispatch（tc_dispatch_bum_clones）

```c
for (int i = 0; i < MAX_BUM_NEXTHOPS; i++) {
    peer = bpf_map_lookup_elem(&bd_peer_map, {bd_id, i});
    if (!peer) continue;  // 削除で穴が開いている可能性

    skb->cb[0] = MAGIC;     // clone 識別マーカー
    skb->cb[1] = bd_id;     // Bridge Domain ID
    skb->cb[2] = i;         // PE index
    skb->cb[3] = vlan_id;   // VLAN ID（materialization 用）

    bpf_clone_redirect(skb, skb->ifindex, BPF_F_INGRESS);
}
skb->cb[0] = 0;  // 元パケットが Mode 2 に入らないようクリア
return TC_ACT_OK; // 元パケットは bridge へ（ローカル flood）
```

### Mode 2: Encap（tc_do_single_pe_encap）

```c
// cb[] から情報を取得
vlan_id = skb->cb[3];

// bd_peer_map から SRv6 encap 情報を取得
entry = bpf_map_lookup_elem(&bd_peer_map, {cb_bd_id, cb_pe_index});

// HW VLAN を除去（パケットデータにはVLANなし）
bpf_skb_vlan_pop(skb);

// SRv6 ヘッダ + VLAN tag 分のスペース確保
bpf_skb_change_head(skb, outer_headers_len + vlan_extra);

// Outer Eth + IPv6 + SRH を書き込み
// FIB lookup で next-hop MAC を解決
// VLAN materialization（後述）
// bpf_redirect で送出
```

## VLAN Materialization

### 問題

generic XDP（veth pair）では、カーネルが xdp_buff → skb 変換時に **VLANタグをパケットデータから
`skb->vlan_tci` に強制的に移動**する。`ethtool -K rxvlan off` でも回避不可能
（rxvlan はNICドライバレベルのoffload制御であり、generic XDPの内部変換パスには影響しない）。

```
XDP が見るパケット:  [dst][src][0x8100][VLAN 100][payload]  ← tag あり
                                    ↓
                カーネル xdp_buff → skb 変換（generic XDP）
                                    ↓
TC が見るパケット:   [dst][src][payload]         ← tag なし
                     skb->vlan_tci = 100        ← メタデータに移動
```

TC encap 時に inner frame が untagged のままだと、decap 後に host2 が untagged フレームを受信し、
return path の headend_l2_map（vlan_id=100）にマッチしない。

### 解決策

Mode 1（dispatch）で元パケットに VLAN を挿入すると bridge パスに影響するため、
**Mode 2（個別 clone の encap 時）** で VLAN tag を手動復元する。

```
bpf_skb_change_head(N + 4) 後のパケット:
  [outer headers (N bytes)][4-byte gap][dst MAC][src MAC][ethertype][payload]

① bpf_skb_load_bytes: dst+src MAC (12B) を gap の後ろからロード
② bpf_skb_store_bytes: 12B を 4 バイト左にシフト
③ bpf_skb_store_bytes: 空いた 4B に 0x8100 + TCI を書き込み

結果:
  [outer headers (N bytes)][dst MAC][src MAC][0x8100][TCI][ethertype][payload]
                                             ^^^^^^^^^^^^^^^^
                                             復元された VLAN tag
```

### untagged フレームの場合

`vlan_id == 0` なら `needs_vlan = false`。追加バイトなし、materialization スキップ。正常動作。

## XDP → TC データ受け渡し

2つの受け渡し経路がある:

| 経路 | 方法 | 内容 |
|------|------|------|
| XDP → TC Mode 1 | `bpf_xdp_adjust_meta` で `__u64` 書き込み | marker (上位32bit) + vlan_id (下位16bit) |
| TC Mode 1 → Mode 2 | `skb->cb[]`（5個の `__u32` スロット） | cb[0]=MAGIC, cb[1]=bd_id, cb[2]=pe_index, cb[3]=vlan_id |

`data_meta` は XDP が書き込み、skb 変換後も TC から `skb->data_meta` で読める。
`cb[]` は TC プログラム間でのみ使える汎用レジスタ。

## End.DT2 Remote MAC Learning

### O(1) peer 解決

`bd_peer_reverse_map`（ユーザ空間で `bd_peer_map` と同時に管理）により、
outer IPv6 src → peer_index を O(1) で解決。

```c
// キー: (bd_id, outer_src_addr) → 値: peer_index
struct bd_peer_reverse_key rk = { .bd_id = bd_id };
memcpy(rk.src_addr, outer_src, 16);
rv = bpf_map_lookup_elem(&bd_peer_reverse_map, &rk);
// rv->index が peer_index
```

### 学習フロー

End.DT2 decap 後:
1. inner src MAC がマルチキャストでないことを確認
2. `find_peer_index_by_src(bd_id, outer_src)` で peer_index を解決
3. `fdb_map` に `{is_remote=1, peer_index, bd_id}` で書き込み
4. 以後の unicast は XDP 側で直接 `bd_peer_map[bd_id, peer_index]` → H.Encaps.L2

### src MAC 学習の保護

`process_bd_forwarding` での local src MAC 学習は `is_remote` をチェックし、
remote エントリ（End.DT2 で学習済み）を上書きしない。

## BPF Map 一覧

| マップ | タイプ | キー | 値 | 用途 |
|--------|--------|------|-----|------|
| `headend_l2_map` | Hash | (ifindex, vlan_id) | headend_entry | Port+VLAN → L2 encap 設定 |
| `fdb_map` | Hash | (bd_id, MAC) | fdb_entry (12B) | MAC → local/remote 判定 |
| `bd_peer_map` | Hash | (bd_id, index) | headend_entry | BD 内のリモート PE flood list |
| `bd_peer_reverse_map` | Hash | (bd_id, src_addr) | peer_index | outer src → peer_index の O(1) 逆引き |

## ファイル構成

| ファイル | 役割 |
|---------|------|
| `src/bum_meta.h` | XDP↔TC 共有: BUM_META_MARKER 定数, `xdp_write_bum_meta()`, `tc_read_bum_meta()` |
| `src/tc_bum.h` | TC: Mode 1 `tc_dispatch_bum_clones()`, Mode 2 `tc_do_single_pe_encap()`, TC FIB lookup |
| `src/xdp_prog.c` | XDP: `process_bd_forwarding()`, TC entry `vinbero_tc_ingress` |
| `src/xdp_prog.h` | fdb_entry 拡張, bd_peer_key, bd_peer_reverse_key/val, BD_PEER_INDEX_INVALID |
| `src/xdp_map.h` | bd_peer_map, bd_peer_reverse_map 定義 |
| `src/srv6_endpoint.h` | End.DT2: `find_peer_index_by_src()`, remote MAC learning, bridge redirect |
| `pkg/bpf/maps.go` | BdPeer CRUD, FindFreeBdPeerIndex |
| `pkg/bpf/tc.go` | LoadTCProgram (TCX attach) |
| `pkg/server/bd_peer.go` | BdPeerService Connect RPC |

## API

### BdPeerService

```
POST /vinbero.v1.BdPeerService/BdPeerCreate
  { "peers": [{ "bd_id": 100, "src_addr": "fc00:1::1", "segments": ["fc00:2::1", "fc00:3::3"] }] }

POST /vinbero.v1.BdPeerService/BdPeerDelete
  { "bd_ids": [100] }

POST /vinbero.v1.BdPeerService/BdPeerList
  { "bd_id": 100 }   // 0 = 全BD
```

### SidFunction (End.DT2 拡張)

```json
{
  "trigger_prefix": "fc00:3::3/128",
  "action": "SRV6_LOCAL_ACTION_END_DT2",
  "bd_id": 100,
  "bridge_name": "br100"   // FDB miss 時の bridge redirect 先
}
```

### HeadendL2 (bd_id 拡張)

```json
{
  "vlan_id": 100,
  "interface_name": "eth0",
  "src_addr": "fc00:1::1",
  "segments": ["fc00:2::1", "fc00:3::3"],
  "bd_id": 100   // 0 = 直接 H.Encaps.L2（BD不使用）
}
```

## Graceful Degradation

| 障害 | 影響 | フォールバック |
|------|------|--------------|
| `bpf_xdp_adjust_meta` 失敗 | リモート BUM 転送欠落 | ローカル flood のみ |
| `bd_peer_map` 空 | TC flood ループがスキップ | ローカル flood のみ |
| `find_peer_index_by_src` 未解決 | remote MAC 未学習 | FDB miss → bridge flood |
| FIB lookup 失敗 | encap 済み clone が送出不可 | TC_ACT_SHOT（clone 破棄） |

## 技術メモ

- `bpf_skb_adjust_room` は `skb->protocol` が IP/IPv6 のみ対応。L2 frame（VLAN 0x8100, ARP 0x0806）は `ENOTSUPP`。`bpf_skb_change_head` で回避。
- `bpf_skb_store_bytes` 後はパケットポインタが verifier 的に無効化される。FIB lookup（直接ポインタアクセス）を先に実行し、VLAN materialization（store_bytes）を最後に実行。
- `BPF_PROG_TEST_RUN` for TC: `skb->data_meta` injection は kernel が `EINVAL` を返す（`convert___skb_to_skb` の制約）。
- TC の `skb->vlan_tci` は読み取り専用。書き込みは `bpf_skb_vlan_push/pop` を使う必要がある。
- Close() 順序: XDP を先にデタッチ（入口を塞ぐ）→ TC をデタッチ。逆にすると BUM meta を持つパケットがデタッチ済み TC に到達する。
