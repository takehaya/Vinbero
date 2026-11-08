# Device の実行時 attach

*(English: [README.md](./README.md))*

vinberod の稼働中に interface を data plane に載せます。CNI plugin が自分で作った veth を載せるときと同じ操作です。トポロジーは [`end-dt4/`](../end-dt4/) と同じで、router3 が End.DT4 で `vrf100` に decap しますが、`internal.devices` には host 側の interface だけを書き、uplink は `vbctl device attach` で載せます。

test は次を確認します。

- uplink を attach している間だけ End.DT4 の通信が host2 に届き、ingress AC と default-deny もその uplink に効く
- 同じ mode の attach は冪等で、mode の変更と config の device の detach は拒否され、detach で program が外れる
- 再起動後に state file から uplink が attach し直される
- interface を削除した device は detach でき、稼働中は link の削除イベントで忘れられ、次の起動では起動を止めずに捨てられる
- `vbctl vrf bridge-member-add` で足した bridge member は再起動後に enslave し直され、daemon の停止中に消えた member は捨てられる

```bash
make build
sudo ./setup.sh
sudo ./test.sh
sudo ./teardown.sh
```

設計は [docs/design/ja/device_attach.md](../../docs/design/ja/device_attach.md) を参照してください。
