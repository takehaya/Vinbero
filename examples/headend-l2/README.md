# SRv6 Headend (H.Encaps.L2) L2VPN Playground

Vinbero XDPによるSRv6 H.Encaps.L2 (Headend L2 Encapsulation) for L2VPNのデモ環境です。

## 概要

H.Encaps.L2は、L2フレーム全体（Ethernetヘッダーを含む）をSRv6パケットにカプセル化します。
これにより、L2ドメインをSRv6ネットワーク経由で拡張するL2VPNを実現できます。

**トリガー**: VLAN ID（VLANタグ付きパケット、またはVLAN ID 0でタグなしパケット）

## トポロジー

```
┌─────────┐          ┌───────────┐          ┌──────────┐          ┌──────────┐          ┌─────────┐
│  host1  │          │  router1  │          │ router2  │          │ router3  │          │  host2  │
│         │          │ (Vinbero) │          │          │          │          │          │         │
│VLAN 100 ├──────────┤fc00:1::1  ├──────────┤ fc00:12  ├──────────┤fc00:3::3 ├──────────┤VLAN 100 │
│172.16.  │          │H.Encaps.L2│          │   ::2    │          │ End.DX2  │          │172.16.  │
│ 100.1   │          │           │          │   End    │          │          │          │ 100.2   │
└─────────┘          └───────────┘          └──────────┘          └──────────┘          └─────────┘
                     ↑ Vinbero XDP
                     Trigger: VLAN ID 100
                     Segments: [fc00:2::1, fc00:3::3]
```

**パケットの流れ（host1→host2の例）:**
1. host1がVLAN 100タグ付きフレームを送信 (172.16.100.1 → 172.16.100.2)
2. **router1 (Vinbero XDP)** がH.Encaps.L2を実行:
   - L2フレーム全体をIPv6+SRHでカプセル化
   - Next Header: IPPROTO_ETHERNET (143)
   - Outer DA: fc00:2::1 (最初のセグメント)
   - Segment List: [fc00:2::1, fc00:3::3]
3. router2がfc00:2::1でEnd操作を実行（SL減少、次のセグメントへ）
4. router3がfc00:3::3でEnd.DX2を実行（L2フレームに戻す）
5. host2がL2フレームを受信

## クイックスタート

```bash
sudo ./setup.sh    # 環境構築
sudo ./test.sh     # テスト実行
sudo ./teardown.sh # クリーンアップ（環境削除）
```

## 手動実行

### 1. 環境構築とVinbero起動

```bash
sudo ./setup.sh

# Vinbero起動
sudo ip netns exec hl2-router1 ../../out/bin/vinbero -c vinbero_router1.yaml
```

### 2. HeadendL2エントリ登録

```bash
sudo ip netns exec hl2-router1 curl -X POST http://127.0.0.1:8082/vinbero.v1.HeadendL2Service/HeadendL2Create \
  -H "Content-Type: application/json" \
  -d '{
    "headend_l2s": [
      {
        "vlan_id": 100,
        "src_addr": "fc00:1::1",
        "segments": ["fc00:2::1", "fc00:3::3"]
      }
    ]
  }'
```

### 3. テスト

```bash
# VLAN 100経由でpingテスト
sudo ip netns exec hl2-host1 ping -c 3 -I hl2-h1rt1.100 172.16.100.2
```

### 4. パケットキャプチャで確認

```bash
# router1-router2間でSRv6パケットを確認
sudo ip netns exec hl2-router2 tcpdump -i hl2-rt2rt1 -n -v ip6
```

SRv6 Routing Header (RT6) と Next Header 143 (Ethernet) が確認できます。

### 5. 環境のクリーンナップ
```bash
sudo ./teardown.sh
```

## L2VPNユースケース

H.Encaps.L2は以下のようなL2VPNシナリオに適しています：

- **VLAN拡張**: 異なるサイト間でVLANを透過的に接続
- **L2ブリッジング**: リモートサイト間でEthernetセグメントを拡張
- **レガシー対応**: L3サービスに対応していないアプリケーションの接続

## 技術詳細

### SRv6ヘッダー構造

```
+------------------+
| Outer IPv6 Header|
| (SA: fc00:1::1)  |
| (DA: fc00:2::1)  |
+------------------+
| Segment Routing  |
| Header (SRH)     |
| Segments Left: 1 |
| [fc00:2::1,      |
|  fc00:3::3]      |
| Next Header: 143 |
+------------------+
| Original L2 Frame|
| (Ethernet Header)|
| (VLAN 100 Tag)   |
| (IP Payload)     |
+------------------+
```

### End.DX2動作

End.DX2はSRv6パケットからL2フレームを取り出し、指定されたインターフェースに転送します：

```bash
# LinuxでのEnd.DX2設定例
ip -6 route add local fc00:3::3/128 encap seg6local action End.DX2 oif eth1
```
