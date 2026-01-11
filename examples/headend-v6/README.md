# SRv6 Headend (H.Encaps) IPv6 Playground

Vinbero XDPによるSRv6 H.Encaps (Headend Encapsulation) for IPv6のデモ環境です。
IPv6パケットをIPv6+SRHでカプセル化します（IPv6-in-IPv6）。

## トポロジー

```
┌─────────┐          ┌───────────┐          ┌──────────┐          ┌──────────┐          ┌─────────┐
│  host1  │          │  router1  │          │ router2  │          │ router3  │          │  host2  │
│         │          │ (Vinbero) │          │          │          │          │          │         │
│2001:1::1├──────────┤2001:1::2  ├──────────┤ fc00:12  ├──────────┤2001:2::2 ├──────────┤2001:2::1│
│         │          │fc00:1::1  │          │   ::2    │          │fc00:3::3 │          │         │
│         │          │ H.Encaps  │          │   End    │          │ End.DX6  │          │         │
└─────────┘          └───────────┘          └──────────┘          └──────────┘          └─────────┘
                     ↑ Vinbero XDP
                     Trigger: 2001:2::/64
                     Segments: [fc00:2::1, fc00:3::3]
```

**パケットの流れ（host1→host2の例）:**
1. host1が2001:2::1にping6を送信 (IPv6)
2. **router1 (Vinbero XDP)** がH.Encapsを実行:
   - IPv6パケットを外側IPv6+SRHでカプセル化
   - Outer DA: fc00:2::1 (最初のセグメント)
   - Segment List: [fc00:2::1, fc00:3::3]
3. router2がfc00:2::1でEnd操作を実行（SL減少、次のセグメントへ）
4. router3がfc00:3::3でEnd.DX6を実行（内側IPv6を取り出す）
5. host2がping6を受信

## クイックスタート

```bash
sudo ./setup.sh    # 環境構築
sudo ./test.sh     # テスト実行
sudo ./teardown.sh # クリーンアップ
```

## 手動実行

### 1. 環境構築とVinbero起動

```bash
sudo ./setup.sh

# router1のLinux native SRv6ルートを削除
sudo ip netns exec hv6-router1 ip -6 route del 2001:2::/64 2>/dev/null

# Vinbero起動
sudo ip netns exec hv6-router1 ../../out/bin/vinbero -c vinbero_router1.yaml
```

### 2. HeadendV6エントリ登録

```bash
sudo ip netns exec hv6-router1 curl -X POST http://127.0.0.1:8082/vinbero.v1.Headendv6Service/Headendv6Create \
  -H "Content-Type: application/json" \
  -d '{
    "headendv6s": [
      {
        "trigger_prefix": "2001:2::/64",
        "mode": "SRV6_HEADEND_BEHAVIOR_H_ENCAPS",
        "src_addr": "fc00:1::1",
        "dst_addr": "fc00:2::1",
        "segments": ["fc00:2::1", "fc00:3::3"]
      }
    ]
  }'
```

### 3. テスト

```bash
sudo ip netns exec hv6-host1 ping6 -c 3 2001:2::1
```

#### パケットキャプチャ

```bash
# router1-router2間でSRv6パケットを確認
sudo ip netns exec hv6-router2 tcpdump -i hv6-rt2rt1 -n ip6
```

外側IPv6+SRH内に内側IPv6パケットがカプセル化されていることが確認できます。

### 4. 環境のクリーンナップ

```bash
sudo ./teardown.sh
```
