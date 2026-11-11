# CNI plugin (L3 mode)

*(English: [README.md](./README.md))*

`vinbero` CNI plugin を container runtime と同じ形で実行します。`CNI_COMMAND` を環境変数で、network configuration を stdin で渡します。2 つの PE namespace で vinberod を動かし、loopback 間に iBGP の VPNv4 session を張ります。空の namespace を pod の代わりに使います (PE1 に `pod1`、`pod1b`、`pod1x`、PE2 に `pod2`、`pod2x`)。IPAM は reference plugin の `host-local` です。

`pod1`、`pod1b`、`pod2` は tenant-a (table 100、route target 65000:100) です。`pod1x` と `pod2x` は tenant-b (table 200、route target 65000:200) で、network configuration には tenant-a と同じ subnet を書きます。host-local は network の名前ごとに lease を持つので、`pod1x` は `pod1` と、`pod2x` は `pod2` と同じアドレスになります。

PE1 の network configuration は `rd` / `rts` / `locator` を持つので、tenant ごとに最初の ADD が VRF と BGP binding を作ります。PE2 は両方の VRF と binding を `vinbero_pe2.yaml` で宣言し、network configuration は VRF の名前だけを書きます。

test は次を確認します。

- ADD で pod に /32 が付き、link-local の gateway 経由の経路が入る。host veth が VRF に入り、/32 が static 経路として VRF table に入り、veth が data plane に attach され AC になる
- 各 PE が相手の pod の /32 を、相手の locator の service SID 付きで import し、PE をまたいだ pod 間と同じ PE 内の pod 間で ping が通る
- tenant-b の pod は tenant-a の pod と同じアドレスを持ち、各 PE は同じ /32 を 2 つの VRF に別の service SID で持つ。ping は送り手と同じ tenant の pod にだけ届き、同じアドレスを持つ別 tenant の pod は echo request を 1 つも受けない。PE をまたぐ場合も同じ PE 内でも同じ
- 配線済みの pod で CHECK が通り、DEL の後は失敗する
- PE2 の再起動後に veth が attach し直され、両 tenant の /32 がそれぞれの VRF で再び広告される
- PE1 の再起動後、network configuration から作った binding が state file から元の内容で戻り (次の ADD を待たずに)、両 tenant の /32 が再び広告される
- tenant-b の pod の DEL は、同じアドレスを持つ tenant-a の pod と、その経路と lease に触れない
- DEL の前に veth が消えても、他の pod の ADD と DEL は止まらない
- DEL で /32 が withdraw され、veth が detach と削除され、AC が外れ、アドレスが解放される。2 回目の DEL も成功する

`host-local` は `$CNI_PLUGIN_DIR`、`/opt/cni/bin`、`/usr/lib/cni` の順に探します (Debian / Ubuntu では `apt install containernetworking-plugins`)。

```bash
make build
sudo ./setup.sh
sudo ./test.sh
sudo ./teardown.sh
```

設計と Multus での使い方は [docs/design/ja/cni.md](../../docs/design/ja/cni.md) を参照してください。
