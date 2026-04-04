# L2VPN / L3VPN データプレーン設計

## 概要

SRv6でL2VPN/L3VPNを実現するためのデータプレーン設計について記述します。
XDPのhot-pathでパケット転送を行い、カーネルbridgeをslow-path/学習に活用します。

## L3VPN (End.DT4/DT6/DT46)

### 仕組み

Linux VRFの `bpf_fib_lookup(params.ifindex=VRF)` を活用します。
VRFデバイスの作成は `NetworkResourceService/VrfCreate` APIで行います。Vinberoが `netlink` でVRFを作成し、SID登録時に `vrf_name` から ifindex を解決します。

```
VrfCreate API → netlink: VRF作成
SidFunctionCreate API → vrf_name → ifindex解決 → BPF map書き込み

パケット処理:
  SRv6パケット → SID照合 → sid_function_entry.vrf_ifindex
    → デカプセル → bpf_fib_lookup(ifindex=VRF) → redirect
```

## L2VPN (End.DT2 + H.Encaps.L2)

### Bridge Domain (BD)

FDBのスコーピングにBridge Domain IDを使用します。VLANではなくBD IDでFDBをnamespace化することで、VLAN重複時の衝突を防ぎます。

BD自体の詳細な解説は [bridge_domain.md](bridge_domain.md) を参照してください。

### データフロー

```
H.Encaps.L2 送信側（customer port）

  XDP:
    ① headend_l2_map[(ifindex, vlan_id)] → headend_entry（bd_id含む）
    ② src MAC学習: fdb_map[(bd_id, src_MAC)] = {oif=ingress_ifindex}
       read-before-writeにより既存エントリと同じなら書き込みをスキップする
       リモートエントリ（is_remote=1）は上書きしない
    ③ dst MACチェック
       ├─ broadcast/multicast → BUM meta + XDP_PASS → TC clone-to-self flood
       ├─ fdb_map hit, local → XDP_PASS → bridge forwarding
       ├─ fdb_map hit, remote → bd_peer_map → SRv6 encap → redirect
       └─ fdb_map miss → BUM meta + XDP_PASS → TC clone-to-self flood

  bd_id == 0 の場合:
    MAC学習なし。全フレームを直接 H.Encaps.L2 で SRv6 encap する（P2P用）

End.DT2 受信側

  XDP:
    ① SID照合 → sid_function_entry.bd_id, bridge_ifindex
    ② デカプセル → inner L2フレーム
    ③ inner src MACをリモートエントリとして学習する
       bd_peer_reverse_map で outer src → peer_index を O(1) 解決
    ④ fdb_map[(bd_id, dst_MAC)] lookup
       ├─ hit, local → bpf_redirect(oif)（fast-path）
       ├─ hit, remote → XDP_PASS（routing loop防止）
       └─ miss → bpf_redirect(bridge_ifindex) → bridge flood

FDBウォッチャー（補助）
  BridgeCreate API呼び出し時に FDBWatcher に動的登録される
  Netlink RTM_NEWNEIGH → MasterIndex で bridge を特定 → bd_id タグ付きで fdb_map 同期
```

### BUM転送

XDPは1パケットに対して1アクションしか返せないため、パケットクローンができません。
BUMトラフィックはTC BPFのclone-to-selfパターンで対向PEに転送します。

処理の流れは以下の通りです。
1. XDPがBUMフレームを検出し、`bpf_xdp_adjust_meta` で vlan_id をメタデータに書き込んでXDP_PASSする
2. TC Mode 1がメタデータを読み取り、bd_peer_mapの各PEに対してclone_redirectで自分に再投入する
3. TC Mode 2が個別のcloneにSRv6ヘッダを付与し、VLAN tagをinner frameに復元してredirectする

VLAN materializationが必要な理由は、generic XDPがxdp_buff→skb変換時にVLANタグをパケットデータから`skb->vlan_tci`に移動するためです。

### Port VLAN

`headend_l2_map` のキーは `(ifindex, vlan_id)` です。
同じVLANでもポートごとに別のBDに紐付けできます。untaggedは `vlan_id=0` で表現します。

| ケース | キー | 意味 |
|--------|------|------|
| tagged | `(eth1, VLAN=100)` | eth1のVLAN 100をL2VPNにする |
| untagged | `(eth1, VLAN=0)` | eth1のuntaggedトラフィックをL2VPNにする |
| 同一VLANで別BD | `(eth1, 100)` と `(eth2, 100)` | 異なるBDに紐付ける |

### XDP MAC学習

XDPがbridgeより先にフレームを処理するため、H.Encaps.L2処理時にXDP側でsrc MACを `fdb_map` に書き込みます。bridgeに頼らずXDPだけでFDB構築が可能です。FDBウォッチャーはXDP_PASSで落ちたフレームの学習を補助します。

ローカル学習はリモートエントリを上書きしません。End.DT2で学習されたリモートMACが、H.Encaps.L2側のローカル学習で壊されることを防ぎます。

### BPFマップ

| マップ | キー | 値 | 用途 |
|--------|------|-----|------|
| `sid_function_map` | IPv6 prefix（LPM） | action, vrf_ifindex, bd_id, bridge_ifindex | SID → Endpoint function |
| `headend_l2_map` | (ifindex, vlan_id) | segments, src_addr, bd_id | Port+VLAN → L2 encap設定 |
| `fdb_map` | (bd_id, MAC) | oif, is_remote, peer_index, bd_id | BD内のMAC → 出力先判定 |
| `bd_peer_map` | (bd_id, index) | headend_entry | BD内のリモートPE flood list |
| `bd_peer_reverse_map` | (bd_id, src_addr) | peer_index | outer src → peer_indexの逆引き |

## リソース管理

VRFとBridgeは `NetworkResourceService` APIで管理します。Vinberoがnetlinkでリソースを作成し、JSON状態ファイルで永続化します。再起動時にはReconcileで状態を復元します。

BridgeCreate APIを呼ぶと、FDBWatcherへの登録も同時に行われます。Bridge削除時はSIDが参照していないかを確認し、参照がある場合はエラーを返します。

API呼び出しの依存関係と利用シーケンスは [api_sequence.md](api_sequence.md) を参照してください。
