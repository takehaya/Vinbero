# end-lbs — End.LBS (Locator-Block Swap)

*(English: [README.md](./README.md))*

End.LBS (RFC 9800 Sec.7.1) を検証します。routing domain の境界で、残り
の C-SID 列をひとつの locator block から別の block へ載せ替える behavior
です。実体は uN slot で動き、target block は SID の local property
(`--target-block`) として持ちます。shift は in place でなく target block
の上に新しい DA を合成します。

Linux oracle phase はありません。seg6local は End.LBS もその土台の
compressed-SID flavor も実装していないためです。代わりに構造で証明しま
す。block A は境界ノードより先で blackhole されているため、swap された
DA だけが block B にしか存在しない terminal に到達できます。

## トポロジ

```mermaid
graph LR
    host1 --- router1
    router1 --- router2
    router2 --- router3
    router3 --- host2
```

- block A は fd00:aaaa/32 (r1 側、r2 より先は blackhole)、block B は
  fd77:7777:7777/48 (r3 側) です
- router1 は H.Encaps.Red で単一 container fd00:aaaa:b002:d004:: を付与
  し、返り方向を fc00:1::1 で終端します
- router2 (Vinbero) が fd00:aaaa:b002::/48 の End.LBS を持ちます。
  target block は fd77:7777:7777::/48 で、argument (d004...) が target
  block 上に copy され fd77:7777:7777:d004:: になります
- router3 は fd77:7777:7777:d004::/128 を Linux End.DX4 で終端します

## 使い方

```bash
sudo ./setup.sh
sudo ./test.sh
sudo ./teardown.sh
```

## 検証内容

1. forward の ping が block swap を通って届きます。素の uN shift なら
   block A の DA fd00:aaaa:d004:: になり router2 の blackhole で落ちる
   ため、到達自体が swap を固定します
2. 返り方向が native の baseline として動きます

End.XLBS と REPLACE-CSID variant は同じ aux property を共有し、
data plane の単体テスト (`pkg/bpf/xdp_lbs_test.go`) が押さえています。
