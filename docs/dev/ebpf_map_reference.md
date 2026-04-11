# eBPF Map リファレンス

Vinberoで使用される全eBPFマップの定義、ルックアップタイミング、フィールド使用状況をまとめたリファレンスドキュメント。

## 1. マップ一覧

### 1.1 データプレーンマップ

| Map名 | タイプ | Key | Value | Max Entries | フラグ | 定義場所 |
|--------|--------|-----|-------|-------------|--------|----------|
| `sid_function_map` | LPM_TRIE | `lpm_key_v6` (20B) | `sid_function_entry` (12B) | 1024 | NO_PREALLOC | `src/core/xdp_map.h:14` |
| `sid_aux_map` | ARRAY | `__u32` (index) | `sid_aux_entry` (200B union) | 512 | - | `src/core/xdp_map.h:22` |
| `headend_v4_map` | LPM_TRIE | `lpm_key_v4` (8B) | `headend_entry` (196B) | 1024 | NO_PREALLOC | `src/core/xdp_map.h:33` |
| `headend_v6_map` | LPM_TRIE | `lpm_key_v6` (20B) | `headend_entry` (196B) | 1024 | NO_PREALLOC | `src/core/xdp_map.h:44` |
| `headend_l2_map` | HASH | `headend_l2_key` (8B) | `headend_entry` (196B) | 1024 | - | `src/core/xdp_map.h:53` |
| `fdb_map` | HASH | `fdb_key` (8B) | `fdb_entry` (20B) | 8192 | - | `src/core/xdp_map.h:63` |
| `bd_peer_map` | HASH | `bd_peer_key` (4B) | `headend_entry` (196B) | 1024 | - | `src/core/xdp_map.h:78` |
| `bd_peer_reverse_map` | HASH | `bd_peer_reverse_key` (20B) | `bd_peer_reverse_val` (2B) | 1024 | - | `src/core/xdp_map.h:88` |

### 1.2 補助マップ

| Map名 | タイプ | Key | Value | Max Entries | 用途 |
|--------|--------|-----|-------|-------------|------|
| `scratch_map` | PERCPU_ARRAY | `__u32` (key=0固定) | `scratch_buf` (224B) | 1 | End.M.GTP6.Dのヘッダ一時保存。BPFスタック512B制限の回避用 |
| `stats_map` | PERCPU_ARRAY | `__u32` (0-7) | `stats_entry` (16B) | 8 | パケット統計カウンタ（`enable_stats`で有効化） |
| `xdpcap_hook` | PROG_ARRAY | `int` | `int` | 5 | Cloudflare xdpcapパケットキャプチャフック |

## 2. Key/Value構造体

### sid_function_map + sid_aux_map

`sid_function_map`はgeneric（共通）フィールドのみを持ち、アクション固有データは`sid_aux_map`に分離。

```c
// Key: IPv6 LPMキー (20 bytes)
struct lpm_key_v6 {
    __u32 prefixlen;          // 0-128
    __u8 addr[16];            // IPv6アドレス
};

// Value: SIDファンクション設定 - generic (12 bytes)
struct sid_function_entry {
    __u8 action;              // srv6_local_action enum (End, End.X, End.DT4, etc.)
    __u8 flavor;              // srv6_local_flavor enum (PSP, USP, USD)
    __u8 has_aux;             // 1: sid_aux_map[aux_index]に追加データあり
    __u8 _pad;
    __u32 vrf_ifindex;        // VRFインターフェースインデックス (End.T/DT4/DT6/DT46)
    __u32 aux_index;          // sid_aux_mapへのインデックス
};

// Auxiliary: アクション固有データ (200 bytes, union)
// sid_aux_map (ARRAY) の value。action フィールドで識別。
// Max size = headend_entry (196B) for End.B6 policy variant.
struct sid_aux_entry {
    union {
        struct { __u8 nexthop[16]; } nexthop;                    // End.X, End.DX2 (16B)
        struct { __u16 bd_id; __u16 _pad; __u32 bridge_ifindex; } l2;  // End.DT2 (8B)
        struct { __u8 args_offset; __u8 gtp_v4_src_addr[4]; } gtp4e;   // GTP4.E (8B)
        struct { __u8 args_offset; } gtp6d;                            // GTP6.D (8B)
        struct { __u8 args_offset; __u8 _pad[7];
                 __u8 src_addr[16]; __u8 dst_addr[16]; } gtp6e;        // GTP6.E (40B)
        struct headend_entry b6_policy;                                // End.B6* (196B)
    };
};
```

### headend_v4_map / headend_v6_map / headend_l2_map / bd_peer_map

```c
// headend_v4_map Key: IPv4 LPMキー (8 bytes)
struct lpm_key_v4 {
    __u32 prefixlen;          // 0-32
    __u8 addr[4];             // IPv4アドレス
};

// headend_l2_map Key: ポート+VLAN (8 bytes)
struct headend_l2_key {
    __u32 ifindex;            // 入力ポートifindex
    __u16 vlan_id;            // VLAN ID (0=タグなし)
    __u8 _pad[2];
};

// bd_peer_map Key: BD + ピアインデックス (4 bytes)
struct bd_peer_key {
    __u16 bd_id;
    __u16 index;              // 0..MAX_BUM_NEXTHOPS-1 (最大8)
};

// 共通Value: ヘッドエンド設定 (196 bytes)
struct headend_entry {
    __u8 mode;                // srv6_headend_behavior enum
    __u8 num_segments;        // セグメント数 (1-10)
    __u8 _pad[2];
    __u8 src_addr[16];        // 外側IPv6ソースアドレス
    __u8 dst_addr[16];        // 予約
    __u8 segments[10][16];    // SIDリスト (最大10セグメント)
    __u16 bd_id;              // ブリッジドメインID (H.Encaps.L2)
    __u8 args_offset;         // Args バイトオフセット (RFC 9433)
    __u8 _pad_gtp;
};
```

### fdb_map

```c
// Key: BD + MACアドレス (8 bytes)
struct fdb_key {
    __u16 bd_id;
    __u8 mac[6];
};

// Value: 転送エントリ (20 bytes)
struct fdb_entry {
    __u32 oif;                // ローカル: 出力ifindex, リモート: 0
    __u8 is_remote;           // 0=ローカル, 1=リモート
    __u8 is_static;           // 1=静的(aging対象外), 0=動的(BPF学習)
    __u16 peer_index;         // bd_peer_mapインデックス (is_remote=1時)
    __u16 bd_id;              // BD ID (is_remote=1時)
    __u8 _pad[2];
    __u64 last_seen;          // bpf_ktime_get_ns() タイムスタンプ (0=静的)
};
```

### bd_peer_reverse_map

```c
// Key: BD + リモートPEソースアドレス (20 bytes)
struct bd_peer_reverse_key {
    __u16 bd_id;
    __u8 src_addr[16];        // 外側IPv6ソースアドレス
    __u8 _pad[2];
};

// Value: ピアインデックス (2 bytes)
struct bd_peer_reverse_val {
    __u16 index;
};
```

## 3. パケット処理フローとLookupタイミング

```
vinbero_main() [src/xdp_prog.c:387]  SEC("xdp_vinbero_main")
 |
 +-- STATS_INC(STATS_RX_PACKETS)
 +-- Ethernetヘッダパース (h_proto判定)
 |
 +-- [ETH_P_8021Q / ETH_P_8021AD] ── VLANパケット処理
 |    |
 |    +-- try_l2_headend(ctx, ifindex, vlan_id, ...)
 |    |    |
 |    |    +-- [1] headend_l2_map LOOKUP ── Key: {ifindex, vlan_id}
 |    |    |   Miss → L3処理へフォールスルー
 |    |    |   Hit (bd_id != 0) → BD転送処理
 |    |    |   Hit (bd_id == 0) → H.Encaps.L2処理
 |    |    |
 |    |    +-- process_bd_forwarding()
 |    |         |
 |    |         +-- [2] fdb_map LOOKUP ── Key: {bd_id, src_mac} ← MAC学習
 |    |         |   既存エントリと比較、変更時bpf_map_update_elem
 |    |         |
 |    |         +-- [3] fdb_map LOOKUP ── Key: {bd_id, dst_mac} ← 転送先決定
 |    |         |   Miss → BUMフラッド (TC clone-to-selfへ)
 |    |         |   Hit (is_remote=0) → ローカル転送 (bpf_redirect)
 |    |         |   Hit (is_remote=1) ↓
 |    |         |
 |    |         +-- [4] bd_peer_map LOOKUP ── Key: {bd_id, peer_index}
 |    |              Hit → SRv6 encap → リモートPEへ転送
 |    |
 |    +-- process_l3() (VLANタグ除去後)
 |
 +-- [ETH_P_IP / ETH_P_IPV6 / other] ── 非VLANパケット
 |    |
 |    +-- try_l2_headend(ctx, ifindex, vlan_id=0, ...) ← タグなしBD処理
 |    +-- process_l3()
 |
 +-- process_l3() [src/xdp_prog.c:356]
      |
      +-- [IPv6 + nexthdr==IPPROTO_ROUTING] ── SRH付きパケット
      |    |
      |    +-- process_srv6_localsid() [src/xdp_prog.c:197]
      |         |
      |         +-- SRH Type 4 検証
      |         +-- [5] sid_function_map LOOKUP ── Key: {prefixlen=128, daddr} (12B generic)
      |         |   Miss → XDP_PASS (カーネルへ)
      |         +-- [5.1] [has_aux] sid_aux_map LOOKUP ── Key: aux_index (40B union)
      |         |   Hit → entry->action でディスパッチ:
      |         |
      |         +-- End           → endpoint_common_processing (flavor)
      |         +-- End.X         → endpoint_common_processing + FIB nexthop redirect
      |         +-- End.T         → endpoint_common_processing + VRF FIB redirect
      |         +-- End.DX2       → SRH decap + L2 redirect (nexthop=OIF)
      |         +-- End.DX4       → SRH decap + IPv4 FIB redirect
      |         +-- End.DX6       → SRH decap + IPv6 FIB redirect
      |         +-- End.DT4       → SRH decap + VRF IPv4 FIB redirect
      |         +-- End.DT6       → SRH decap + VRF IPv6 FIB redirect
      |         +-- End.DT46      → SRH decap + VRF auto-detect FIB redirect
      |         +-- End.DT2       → SRH decap + L2 FDB forwarding
      |         |    +-- [6] bd_peer_reverse_map LOOKUP ── Key: {bd_id, outer_src}
      |         |    +-- [7] fdb_map LOOKUP (learn + forward)
      |         |
      |         +-- End.B6        → aux->b6_policy + SRH insert
      |         +-- End.B6.Encaps → aux->b6_policy + SRH encaps
      |         +-- End.M.GTP4.E  → GTP-U decap + IPv4 encap
      |         +-- End.M.GTP6.D  → GTP-U encap + IPv6 SRv6 encap
      |         +-- End.M.GTP6.E  → GTP-U encap + IPv6 SRv6 encap
      |
      +-- [IPv6 + nexthdr!=ROUTING + inner=IP/ETH] ── Reduced SRH (no-SRH)
      |    |
      |    +-- process_srv6_decap_nosrh() [src/xdp_prog.c:148]
      |         |
      |         +-- [9] sid_function_map LOOKUP ── Key: {prefixlen=128, daddr}
      |         |   同じマップ、単一セグメントパケット向け
      |         |
      |         +-- End.DX4/DT4   → decap + nosrh_fib_v4 (vrf_ifindex使用)
      |         +-- End.DX6/DT6   → decap + nosrh_fib_v6 (vrf_ifindex使用)
      |         +-- End.DT46      → decap + inner protocol判定
      |         +-- End.DX2       → L2 decap + redirect (nexthop=OIF)
      |         +-- End.DT2       → L2 decap + FDB forwarding
      |              +-- [10] bd_peer_reverse_map, fdb_map LOOKUP
      |
      +-- [IPv6 other] ── ヘッドエンド (IPv6トランジット)
      |    |
      |    +-- process_headend_v6() [src/xdp_prog.c:62]
      |         +-- [11] headend_v6_map LOOKUP ── Key: {prefixlen=128, daddr}
      |         +-- H.Encaps / H.Encaps.Red / H.Insert / H.Insert.Red
      |
      +-- [IPv4] ── ヘッドエンド (IPv4トランジット)
           |
           +-- process_headend_v4() [src/xdp_prog.c:32]
                +-- [12] headend_v4_map LOOKUP ── Key: {prefixlen=32, daddr}
                +-- H.Encaps / H.Encaps.Red / H.M.GTP4.D
```

### TC Ingress (BUMフラッド処理)

```
vinbero_tc_ingress() [src/xdp_prog.c:473]  SEC("tc/vinbero_tc_ingress")
 |
 +-- モード判定 (skb->cb[0])
 |
 +-- [mode=1] tc_dispatch_bum_clones()
 |    +-- [13] headend_l2_map LOOKUP ← BD設定取得
 |    +-- [14] bd_peer_map LOOKUP (index 0..7) ← 全リモートPEへclone
 |
 +-- [mode=2] Single PE encap
      +-- [15] bd_peer_map LOOKUP ← skb->cb[]からpeer情報取得
```

## 4. sid_function_entry フィールド使用マトリクス

各アクションが`sid_function_entry`のどのフィールドを参照するか。

```
Field            | End | X  | T  | DX2 | DX4 | DX6 | DT4 | DT6 | DT46 | DT2 | B6* | GTP4E | GTP6D | GTP6E
-----------------+-----+----+----+-----+-----+-----+-----+-----+------+-----+-----+-------+-------+------
action           |  *  | *  | *  |  *  |  *  |  *  |  *  |  *  |  *   |  *  |  *  |   *   |   *   |   *
flavor           |  *  | *  | *  |     |     |     |     |     |      |     |  *  |       |       |
nexthop          |     | *  |    |  *  |     |     |     |     |      |     |     |       |       |
vrf_ifindex      |     |    | *  |     |     |     |  *  |  *  |  *   |     |     |       |       |
bd_id            |     |    |    |     |     |     |     |     |      |  *  |     |       |       |
bridge_ifindex   |     |    |    |     |     |     |     |     |      |  *  |     |       |       |
args_offset      |     |    |    |     |     |     |     |     |      |     |     |   *   |   *   |   *
gtp_v4_src_addr  |     |    |    |     |     |     |     |     |      |     |     |   *   |       |
src_addr         |     |    |    |     |     |     |     |     |      |     |     |       |       |   *
dst_addr         |     |    |    |     |     |     |     |     |      |     |     |       |       |   *
arg_src_offset   |     |    |    |     |     |     |     |     |      |     |     |       |       |
arg_dst_offset   |     |    |    |     |     |     |     |     |      |     |     |       |       |
```

**凡例**: `*` = 参照あり、空欄 = 未使用、`B6*` = End.B6.Insert/End.B6.Encaps両方

**フィールド参照箇所**:
- `flavor`: `src/endpoint/srv6_endpoint_core.h` (endpoint_common_processing)
- `nexthop`: End.X → `srv6_endpoint_core.h:123`、End.DX2 → `srv6_endpoint_decap.h:111`
- `vrf_ifindex`: End.T → `srv6_endpoint_basic.h:50`、End.DT4/6 → `srv6_endpoint_decap.h:143,155`、nosrh → `xdp_prog.c:118,141`
- `bd_id` / `bridge_ifindex`: End.DT2 → `srv6_endpoint_l2.h:152,159`
- `args_offset`: GTP → `srv6_gtp_encap.h:47`、`srv6_gtp_decap.h:306,445`
- `gtp_v4_src_addr`: `srv6_gtp_encap.h:68`
- `src_addr` / `dst_addr`: GTP6.E → `srv6_gtp_decap.h:510,511`

## 5. headend_entry 使用パターン

`headend_entry`は5つのマップで共有されるvalue型。

| 使用マップ | 用途 | 主要フィールド |
|-----------|------|---------------|
| `headend_v4_map` | IPv4 H.Encaps/H.Encaps.Red/H.M.GTP4.D | mode, num_segments, src_addr, segments |
| `headend_v6_map` | IPv6 H.Encaps/H.Encaps.Red/H.Insert/H.Insert.Red | mode, num_segments, src_addr, segments |
| `sid_aux_map` (b6_policy) | End.B6/End.B6.Encaps ポリシー | mode, num_segments, src_addr, segments |
| `headend_l2_map` | H.Encaps.L2 (ポート+VLAN) | mode, num_segments, src_addr, segments, bd_id |
| `bd_peer_map` | リモートPE SRv6 encap情報 | mode, num_segments, src_addr, segments, bd_id |

`segments[10][16]` (160B) が196B中の大半を占めるが、全ヘッドエンドアクションが必ず使用するため分割の対象外。

## 6. マップ更新元

| 更新元 | マップ | 操作 |
|--------|--------|------|
| **ユーザ空間(Go)のみ** | `sid_function_map` | CRUD via RPC API (genericフィールドのみ) |
| **ユーザ空間(Go)のみ** | `sid_aux_map` | sid_function_mapと連動 (アクション固有データ + End.B6ポリシー) |
| **ユーザ空間(Go)のみ** | `headend_v4_map`, `headend_v6_map` | CRUD via RPC API |
| **ユーザ空間(Go)のみ** | `headend_l2_map` | CRUD via RPC API |
| **ユーザ空間(Go)のみ** | `bd_peer_map`, `bd_peer_reverse_map` | CRUD via RPC API (双方向同期) |
| **カーネル(BPF) + Go** | `fdb_map` | BPF: MAC学習 (src MAC update)、Go: 静的エントリ管理 |
| **カーネル(BPF)のみ** | `stats_map` | per-CPU統計カウンタ increment |
| **なし (読み取り専用)** | `scratch_map` | per-CPUバッファ、初期値のまま使用 |
| **なし** | `xdpcap_hook` | PROG_ARRAY tail callフック |

## 7. Go側 MapOperations 対応表

`pkg/bpf/maps.go` の `MapOperations` 構造体が全マップ操作を提供。

| マップ | Create | Delete | Get | List | 対応ファイル |
|--------|--------|--------|-----|------|-------------|
| `sid_function_map` | `CreateSidFunction` | `DeleteSidFunction` | `GetSidFunction` | `ListSidFunctions` | `maps.go` |
| `sid_aux_map` | (CreateSidFunction内) | (DeleteSidFunction内) | `GetSidAux` | - | `maps.go` (End.B6ポリシーもここに格納) |
| `headend_v4_map` | `CreateHeadendV4` | `DeleteHeadendV4` | `GetHeadendV4` | `ListHeadendV4` | `maps.go:150-207` |
| `headend_v6_map` | `CreateHeadendV6` | `DeleteHeadendV6` | `GetHeadendV6` | `ListHeadendV6` | `maps.go:212-269` |
| `headend_l2_map` | `CreateHeadendL2` | `DeleteHeadendL2` | `GetHeadendL2` | `ListHeadendL2` | `maps.go:313-354` |
| `fdb_map` | `CreateFdb` | `DeleteFdb` | `GetFdb` | `ListFdb` | `maps.go:359-400` |
| `bd_peer_map` | `CreateBdPeer` | `DeleteBdPeer` | `GetBdPeer` | `ListBdPeers` | `maps.go:406-482` |
| `bd_peer_reverse_map` | (CreateBdPeer内) | (DeleteBdPeer内) | - | - | `maps.go:412-442` |

### RPC サービス対応

| サービス | 操作するマップ | ファイル |
|----------|---------------|---------|
| `SidFunctionService` | sid_function_map, sid_aux_map | `pkg/server/sid_function.go` |
| `Headendv4Service` | headend_v4_map | `pkg/server/headendv4.go` |
| `Headendv6Service` | headend_v6_map | `pkg/server/headendv6.go` |
| `HeadendL2Service` | headend_l2_map | `pkg/server/headendl2.go` |
| `BdPeerService` | bd_peer_map, bd_peer_reverse_map | `pkg/server/bd_peer.go` |
| `FdbService` | fdb_map (読み取りのみ) | `pkg/server/fdb.go` |
| `NetworkResourceService` | sid_function_map (参照チェック) | `pkg/server/network_resource.go` |
