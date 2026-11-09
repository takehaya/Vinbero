# CNI plugin (L3 mode)

*(English: [README.md](./README.md))*

`vinbero` CNI plugin を container runtime と同じ形で実行します。`CNI_COMMAND` を環境変数で、network configuration を stdin で渡します。2 つの PE namespace で vinberod を動かし、loopback 間に iBGP の VPNv4 session を張ります。空の namespace 3 つを pod の代わりに使います (PE1 に `pod1` と `pod1b`、PE2 に `pod2`)。IPAM は reference plugin の `host-local` です。

PE1 の network configuration は `rd` / `rts` / `locator` を持つので、最初の ADD が VRF と BGP binding を作ります。PE2 は両方を `vinbero_pe2.yaml` で宣言し、network configuration は VRF の名前だけを書きます。

test は次を確認します。

- ADD で pod に /32 が付き、link-local の gateway 経由の経路が入る。host veth が VRF に入り、/32 が static 経路として VRF table に入り、veth が data plane に attach され AC になる
- 各 PE が相手の pod の /32 を、相手の locator の service SID 付きで import し、PE をまたいだ pod 間と同じ PE 内の pod 間で ping が通る
- 配線済みの pod で CHECK が通り、DEL の後は失敗する
- PE2 の再起動後に veth が attach し直され、pod2 の /32 が再び広告される
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
