# L2VPN / L3VPN データプレーン設計

## 概要

SRv6でL2VPN/L3VPNを実現するためのデータプレーン設計について記述します。
XDPのhot-pathでパケット転送を行い、カーネルbridgeをslow-path/学習に活用します。

## L3VPN (End.DT4/DT6/DT46)

### 仕組み

Linux VRFの `bpf_fib_lookup(params.ifindex=VRF)` を活用します。
VRFデバイスの作成やルーティングテーブル設定はLinux側で行い、Vinberoは `vrf_ifindex` でFIB lookupするだけです。

```
SRv6パケット → SID照合 → sid_function_entry.vrf_ifindex
  → デカプセル → bpf_fib_lookup(ifindex=VRF) → redirect
```

### 前提条件

VRFとルーティングルールは事前にLinux側で作成しておく必要があります。

```bash
ip link add vrf100 type vrf table 100
ip rule add l3mdev protocol kernel prio 1000
```

## L2VPN (End.DT2 + H.Encaps.L2)

### Bridge Domain (BD)

FDBのスコーピングにBridge Domain IDを使用します。VLANではなくBD IDでFDBをnamespace化することで、VLAN重複時の衝突を防ぎます。

BD IDはconfigで割り当てます。デフォルトでVLAN IDと同じ値にすると直感的です。

```yaml
settings:
  bridge_domains:
    - bridge_name: br100
      bd_id: 100
```

BD自体の詳細な解説は [bridge_domain.md](bridge_domain.md) を参照してください。

### データフロー

```
H.Encaps.L2 送信側（customer port）

  XDP:
    ① headend_l2_map[(ifindex, vlan_id)] → headend_entry（bd_id含む）
    ② src MAC学習: fdb_map[(bd_id, src_MAC)] = {oif=ingress_ifindex}
       read-before-writeにより既存エントリと同じなら書き込みをスキップする
    ③ dst MACチェック
       ├─ broadcast/multicast → BUM meta + XDP_PASS → TC clone-to-self flood
       ├─ fdb_map hit, local → XDP_PASS → bridge forwarding
       ├─ fdb_map hit, remote → bd_peer_map → SRv6 encap → redirect
       └─ fdb_map miss → BUM meta + XDP_PASS → TC clone-to-self flood

End.DT2 受信側

  XDP:
    ① SID照合 → sid_function_entry.bd_id
    ② デカプセル → inner L2フレーム
    ③ inner src MACをリモートエントリとして学習する
    ④ fdb_map[(bd_id, dst_MAC)] lookup
       ├─ hit, local → bpf_redirect(oif)（fast-path）
       ├─ hit, remote → XDP_PASS（routing loop防止）
       └─ miss → bpf_redirect(bridge_ifindex) → bridge flood

FDBウォッチャー（補助）
  XDP_PASSでkernelに落ちたフレーム → bridge学習
  → Netlink RTM_NEWNEIGH → MasterIndexでbridge特定 → bd_idタグ付きでfdb_map同期
```

### BUM転送

XDPは1パケットに対して1アクションしか返せないため、パケットクローンができません。
BUMトラフィックはTC BPFのclone-to-selfパターンで対向PEに転送します。

詳細は [tc_bum_forwarding.md](tc_bum_forwarding.md) を参照してください。

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
