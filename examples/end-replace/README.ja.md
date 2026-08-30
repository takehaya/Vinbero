# end-replace — REPLACE-CSID の End

*(English: [README.md](./README.md))*

REPLACE-CSID flavor の End (RFC 9800 Sec.4.2) を検証します。packed な
C-SID container は SRH の segment list に置かれ、DA の Argument 下位
bit が container 内の index を運び、各 endpoint は container を歩きな
がら DA の C-SID 部分だけを書き換えます。

Linux oracle phase はありません。seg6local が実装するのは NEXT-C-SID
flavor だけのためです。代わりに C-SID 列を 2 台の Vinbero ノード間で
往復させ、ping の到達と r2 → r3 link の TX packet counter の両方を
検証します。到達だけでは index の壊れ方によって中間 hop を飛ばしても
成功し得るため、counter が echo あたり 2 回の通過を固定します。

設計は [`docs/design/ja/usid.md`](../../docs/design/ja/usid.md) を参照して
ください。

## トポロジ

```mermaid
graph LR
    host1 --- router1
    router1 --- router2
    router2 --- router3
    router3 --- host2
```

C-SID 計画 (48 bit block fd00:aabb:ccdd、32 bit C-SID、K=4):

- router2 (Vinbero): C-SID b2b2:1 と b2b2:2 の End(REP) (/80)
- router3 (Vinbero): C-SID b3b3:1 の End(REP) (/80)
- router3 (Linux): C-SID b3b3:d の terminal End.DX4。REPLACE 列の最終
  C-SID は任意の behavior でよく、DA の argument bit が変動するため
  block + C-SID の /80 で match させます

列 [b2b2:1 (DA), b3b3:1, b2b2:2, b3b3:d] は 1 つの container
(`0:0:b3b3:d:b2b2:2:b3b3:1`) に収まり、パケットは
r2 → r3 → r2 → r3 と渡って、router2 での container 跨ぎ (Index 0 →
K-1) と 2 回の container 内置換を通ります。

## 必要条件

- seg6 encap をサポートする iproute2 (headend から見ると container は
  普通の segment list entry です)

## 使い方

```bash
sudo ./setup.sh
sudo ./test.sh
sudo ./teardown.sh
```

## 検証内容

1. forward の ping が到達し、かつ r2 → r3 の TX counter が echo あた
   り 2 回分増えます。両者を合わせて 4 つの walk step を固定します。
   b2b2:2 を飛ばす index の壊れ方では到達はしても通過が 1 回になります
2. 返り方向が native の baseline として動きます
