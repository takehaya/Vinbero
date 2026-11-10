# SRv6 Headend (H.Encaps) IPv4 Playground

*(English: [README.md](./README.md))*

Vinbero XDPによるSRv6 H.Encaps (Headend Encapsulation) for IPv4のデモ環境です。

## トポロジー

```mermaid
graph LR
    host1[host1<br/>172.0.1.1] -->|IPv4| router1[router1 / Vinbero XDP<br/>172.0.1.2<br/>fc00:1::1<br/>H.Encaps<br/>Trigger: 172.0.2.0/24<br/>Segments: fc00:2::1, fc00:3::3]
    router1 -->|SRv6| router2[router2<br/>fc00:12::2<br/>End]
    router2 -->|SRv6| router3[router3<br/>172.0.2.2<br/>fc00:3::3<br/>End.DX4]
    router3 -->|IPv4| host2[host2<br/>172.0.2.1]
```

**パケットの流れ（host1→host2の例）:**
1. host1が172.0.2.1にpingを送信 (IPv4)
2. **router1 (Vinbero XDP)** がH.Encapsを実行:
   - IPv4パケットをIPv6+SRHでカプセル化
   - Outer DA: fc00:2::1 (最初のセグメント)
   - Segment List: [fc00:2::1, fc00:3::3]
3. router2がfc00:2::1でEnd操作を実行（SL減少、次のセグメントへ）
4. router3がfc00:3::3でEnd.DX4を実行（IPv4に戻す）
5. host2がpingを受信

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

# router1のLinux native SRv6ルートを削除
sudo ip netns exec hv4-router1 ip route del 172.0.2.0/24 2>/dev/null

# Vinbero起動
sudo ip netns exec hv4-router1 ../../out/bin/vinberod -c vinbero_router1.yaml
```

### 2. HeadendV4エントリ登録

```bash
sudo ip netns exec hv4-router1 ../../out/bin/vinbero -s http://127.0.0.1:8082 hv4 create --trigger-prefix 172.0.2.0/24 --src-addr fc00:1::1 --segments fc00:2::1,fc00:3::3
```

### 3. テスト

```bash
sudo ip netns exec hv4-host1 ping -c 3 172.0.2.1
```

#### パケットキャプチャ

```bash
# router1-router2間でSRv6パケットを確認
sudo ip netns exec hv4-router2 tcpdump -i hv4-rt2rt1 -n ip6
```

SRv6 Routing Header (RT6) でsegment list: [fc00:2::1, fc00:3::3] が確認できます。

### VRF を指定した headend entry

headend の entry は VRF に属します。`--vrf` を省略すると `hv4` の各 command は global VRF を扱い、`list` と `flush` は `--all-vrfs` で全 VRF を扱います。同じ prefix を、既にある VRF に指定して入れることもできます (存在しない名前は拒否します)。data plane は global VRF で引くので、上の ping は global VRF の entry を使い続けます。

```bash
VB="sudo ip netns exec hv4-router1 ../../out/bin/vinbero -s http://127.0.0.1:8082"
$VB vrf create --name hv4-tenant --table-id 4242
$VB hv4 create --trigger-prefix 172.0.2.0/24 --src-addr fc00:1::1 --segments fc00:9::1 --vrf hv4-tenant
$VB hv4 list --all-vrfs
# TRIGGER PREFIX  VRF         MODE      SRC ADDR   SEGMENTS
# 172.0.2.0/24    global      H_ENCAPS  fc00:1::1  fc00:2::1,fc00:3::3
# 172.0.2.0/24    hv4-tenant  H_ENCAPS  fc00:1::1  fc00:9::1
$VB hv4 delete --trigger-prefix 172.0.2.0/24 --vrf hv4-tenant
$VB vrf delete --name hv4-tenant   # headend の entry が残っている間は拒否されます
```

`test.sh` は ping のテストの後にこの手順を実行します。

### 4. 環境のクリーンアップ
```bash
sudo ./teardown.sh
```
