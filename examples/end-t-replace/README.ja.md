# end-t-replace — REPLACE-CSID の End.T

*(English: [README.md](./README.md))*

REPLACE-CSID flavor の End.T (RFC 9800 Sec.4.2) を検証します。
[`end-replace`](../end-replace/) と同じ packed container の walk です
が、router2 の 2 つの C-SID は vrf100 に束縛した `END_T_REPLACE` で、
advance のたびに次の C-SID を VRF の table で解決します。

VRF 束縛は構造的に証明します。router2 の main table は locator block
全体を blackhole し、router3 への経路は table 100 だけに置くので、
default FIB に落ちる End(REP) ならパケットは落ちます。Linux oracle
phase はありません (seg6local が実装するのは NEXT-C-SID flavor だけ
です)。テストは到達に加えて、sid list の往復 (格納された END_REPLACE
entry が END_T_REPLACE + VRF として報告されること) と、echo あたり
2 回の r2 → r3 通過を固定する TX counter を検証します。

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

- router2 (Vinbero): C-SID b2b2:1 と b2b2:2 の End.T(REP) (/80)。両方
  vrf100 (table 100) に束縛し、main table は block を blackhole します
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

1. sid list が entry を END_T_REPLACE + vrf100 として報告します (aux
   からの逆引き)
2. forward の ping が到達します。main table は block を blackhole して
   いるため、これは r2 の 2 回の advance が両方 vrf100 で解決したとき
   にだけ成り立ちます。加えて r2 → r3 の TX counter が echo あたり
   2 回分増え、4 つの walk step を固定します
3. 返り方向が native の baseline として動きます
