# SRv6 End.DX6 Playground

Vinbero XDPによるSRv6 End.DX6 (Decapsulation with IPv6 Cross-connect) のデモ環境です。

## トポロジー

```
┌─────────┐          ┌───────────┐          ┌──────────┐          ┌──────────┐          ┌─────────┐
│  host1  │          │  router1  │          │ router2  │          │ router3  │          │  host2  │
│         │          │           │          │          │          │ (Vinbero)│          │         │
│2001:1::1├──────────┤2001:1::2  ├──────────┤ fc00:12  ├──────────┤2001:2::2 ├──────────┤2001:2::1│
│         │          │fc00:1::1  │          │   ::2    │          │fc00:3::3 │          │         │
│         │          │ H.Encaps  │          │   End    │          │ End.DX6  │          │         │
└─────────┘          └───────────┘          └──────────┘          └──────────┘          └─────────┘
                                                                  ↑ Vinbero XDP
                                                                  SID: fc00:3::3
                                                                  Action: End.DX6
```

**パケットの流れ（host1→host2の例）:**
1. host1が2001:2::1にping6を送信 (IPv6)
2. router1がLinux native H.Encapsを実行:
   - IPv6パケットをIPv6+SRHでカプセル化 (IPv6-in-IPv6)
   - Outer DA: fc00:2::1 (最初のセグメント)
   - Segment List: [fc00:2::1, fc00:3::3]
3. router2がfc00:2::1でEnd操作を実行（SL減少、次のセグメントへ）
4. **router3 (Vinbero XDP)** がfc00:3::3でEnd.DX6を実行:
   - 外側IPv6+SRHヘッダを除去
   - 内側IPv6パケットをFIBルックアップで転送
5. host2がping6を受信

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

# router3のLinux native End.DX6ルートを削除
sudo ip netns exec dx6-router3 ip -6 route del local fc00:3::3/128 2>/dev/null

# Vinbero起動
sudo ip netns exec dx6-router3 ../../out/bin/vinbero -c vinbero_router3.yaml
```

### 2. SidFunction (End.DX6) エントリ登録

```bash
sudo ip netns exec dx6-router3 curl -X POST http://127.0.0.1:8082/vinbero.v1.SidFunctionService/SidFunctionCreate \
  -H "Content-Type: application/json" \
  -d '{
    "sid_functions": [
      {
        "trigger_prefix": "fc00:3::3/128",
        "action": "SRV6_LOCAL_ACTION_END_DX6"
      }
    ]
  }'
```

### 3. テスト

```bash
sudo ip netns exec dx6-host1 ping6 -c 3 2001:2::1
```

#### パケットキャプチャ

```bash
# router2-router3間でSRv6パケットを確認
sudo ip netns exec dx6-router3 tcpdump -i dx6-rt3rt2 -n ip6

# router3-host2間でデカプセル化後のIPv6パケットを確認
sudo ip netns exec dx6-router3 tcpdump -i dx6-rt3h2 -n ip6
```

### 4. 環境のクリーンナップ
```bash
sudo ./teardown.sh
```
