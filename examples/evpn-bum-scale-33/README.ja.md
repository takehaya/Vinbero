# 1 つの bridge domain に PE 33 台の EVPN BUM

*(English: [README.md](./README.md))*

[evpn-bum-scale](../evpn-bum-scale/) を `NUM_PES=33` で動かします。Vinbero の PE 33 台が iBGP の full mesh（528 session）で 1 つの EVPN の bridge domain を作ります。各 PE は RT3 の flood peer を 32 個入れ、これで bridge domain の flood スロット 32 個がすべて埋まります（1 つの bridge domain が flood できる上限、リモート PE 32 台、計 33 node）。RT2 の unicast peer 32 個は flood スロットを使いません。確認の内容は evpn-bum-scale と同じで、台数だけが変わります。各 PE に peer 64 個とリモートの MAC 32 個が入ること、すべてのホストの組で既知 unicast が通ること、未知 unicast、broadcast、ARP が各リモート PE と各ホストにちょうど 1 コピー届き、core へ送り返されないこと、PE 32 と PE 33 が共有する Ethernet Segment での受信側の split horizon です。

daemon 33 個と、flood の確認のたびに 100 個ほどの packet capture を同時に動かします。CPU 4 個で 1 回 3 分ほどかかります。CI では evpn-bum-scale と同じく 3 つの BUM モードで実行します。

```bash
make build            # リポジトリの root で
cd examples/evpn-bum-scale-33
sudo ./setup.sh
sudo BUM_MODE=tc ./test.sh        # または xdp、xdp-native
sudo ./teardown.sh
```
