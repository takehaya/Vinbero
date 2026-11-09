# Device の実行時 attach

`internal.devices` に書いた interface は起動時に data plane に載りますが、起動後に作られる interface (CNI plugin が pod ごとに作る veth など) は載せられませんでした。`DeviceService` は daemon を止めずに interface を attach / detach し、その状態を再起動後も保ちます。

## attach の単位

attach は interface ごとに管理します。1 つの attach は XDP の entry program (`vinbero_main`) と TCX ingress の program (`vinbero_tc_ingress`、BUM 用) の組です。

- XDP を先に attach し、TCX の attach に失敗したら XDP を外して失敗を返します。片方だけ載った interface は残りません
- mode は XDP の attach mode で、`driver` / `generic` / `offload` のいずれかです。指定しなければ `internal.bpf.device_mode` を使います。`internal.bpf.device_mode` が不正なら、`internal.devices` が空でも起動を拒否します。veth のように native XDP の挙動が kernel に依存する interface は、attach ごとに `generic` を指定できます
- 同じ interface を同じ mode で attach し直すと、kernel に触れず成功します。別の mode で attach し直すと `FAILED_PRECONDITION` で拒否するので、先に detach します
- `settings.l2.bum_mode: xdp` で動いている daemon では、`internal.bpf.device_mode` と違う mode の attach を `FAILED_PRECONDITION` で拒否します。xdp モードの BUM の BPF program は 1 つの XDP mode 向けに作られるためです (下の「xdp モードの BUM」を参照)
- `internal.devices` の interface も同じ経路で attach します。config が持ち主なので state file には記録せず、detach は拒否し、mode は `internal.bpf.device_mode` に固定します

bpf_link は pin しません。attach は daemon の lifetime に縛られ、daemon が終了すると kernel から外れます。再起動後の復旧は state file からの再 attach で行います ([persistence.md](persistence.md) の他の資源と同じ考え方です)。

## API

| 操作 | RPC | CLI |
|---|---|---|
| attach | `DeviceService/DeviceAttach` | `vbctl device attach --name I [--mode generic]` |
| detach | `DeviceService/DeviceDetach` | `vbctl device detach --name I` |
| 一覧 | `DeviceService/DeviceList` | `vbctl device list` |

`device list` の `SOURCE` 列は、`internal.devices` 由来なら `config`、RPC で attach したものなら `api` です。

| 状況 | 結果 |
|---|---|
| interface 名が不正 (空、15 byte 超、`/` を含むなど) / mode が不明 | `INVALID_ARGUMENT` |
| attach 対象の interface が存在しない / detach 対象の interface はあるが attach されていない | `NOT_FOUND` |
| 別の mode で attach 済み / `internal.devices` の device を detach しようとした | `FAILED_PRECONDITION` |
| detach 対象の interface が既に消えている (link の削除イベントで記録が先に消えた場合も) | 成功 (state からも消す) |
| attach されていないが state に記録が残っている (前回の detach で state の書き込みに失敗した、再起動時に attach できなかった) | 成功 (state を書き直す) |

CNI の DEL は冪等である必要があるので、呼び出し側は detach の `NOT_FOUND` を成功として扱えます。

## 永続化と再起動

RPC で attach した device は state file (`settings.state_path`) の `devices` に名前と mode を記録します。

```json
{
  "vrfs": [],
  "bridges": [],
  "devices": [{"name": "veth1a2b3c", "mode": "generic"}]
}
```

起動時の順序は次のとおりです。

1. `internal.devices` を attach します。失敗すると起動を中止します
2. `netresource.Reconcile` が VRF と bridge を復元します
3. state の `devices` を記録された mode で attach し直します

3 は fail-closed にしていません。1 つの veth のために node 全体の data plane を止めないためです。

- interface が消えている entry (daemon の停止中に pod が消えた、host が再起動した) と mode が不正な entry は、warning を出して state から外します
- それ以外の理由で attach に失敗した entry は、warning を出して state に残します。一時的な失敗で device を忘れないためです。次の起動で attach し直し、不要なら `DeviceDetach` で記録を消せます
- `internal.devices` に移った名前の entry は、config が持ち主になるので外します

state への書き込みに失敗した場合、attach / detach の結果は残したままエラーを返します。attach は retry すれば state も書き直します。detach の retry は、device が既に外れていても state を書き直して成功します。

## 消えた interface の後始末

interface を削除すると kernel は XDP と TCX を外します。daemon の記録は次のように片付けます。

- daemon は netlink の link イベント (`RTM_DELLINK`) を購読し、attach 中の interface が削除されると、その記録を閉じて state からも外します。bridge から port が外れたときも `RTM_DELLINK` (family `AF_BRIDGE`) が届くので、名前で引き直して interface が本当に無い (または ifindex が変わった) ことを確かめてから外します
- 購読が失敗した場合 (受信 buffer の溢れなど) は購読し直します。購読のたびに、まず全 interface を 1 回 dump して消えた記録を外すので、購読していない間の削除も取りこぼしません
- `DeviceList` は何も変更しません。1 回の dump で interface を引き、消えた interface の記録は一覧から除くだけです
- `DeviceAttach` は、同じ名前で ifindex が変わった interface (作り直された veth) を見つけると、古い link を閉じて attach し直します
- `DeviceDetach` は interface が消えていても成功します

## bridge member の実行時追加

L2 で使う veth は bridge に enslave する必要があります。`VrfService` の `VrfBridgeMemberAdd` / `VrfBridgeMemberRemove` (CLI は `vbctl vrf bridge-member-add|bridge-member-remove --vrf X --interface I`) は、attach 済みの bridge facet に port を 1 つずつ足し引きします。呼び出し側が直接 `ip link set master` すると state と食い違い、再起動時の Reconcile で member が失われるため、この RPC を通します。

- add は port を enslave し、state の bridge record の `runtime_members` に記録します。既に member なら何もせず成功します。別の device に enslave されている port は付け替えずに拒否します
- remove は port を release し、`members` と `runtime_members` の両方から外します。port が消えている場合と member でない場合も成功します
- config file の `vrfs.entries[].bridge.members` に書いた port の remove は `FAILED_PRECONDITION` で拒否します。config は起動のたびにこの port を enslave し直すので、外すには config から消して再起動します。拒否は config に書いた VRF と bridge の組に対してだけ働きます。その bridge を detach して別の bridge を attach した場合、同じ port でも外せます
- Reconcile は `members` (attach 時に指定した port) が欠けていれば起動を拒否します。`runtime_members` の port が消えている、またはその名前の port が別の device に enslave されている場合は、warning を出して外し、起動を続けます。lookup や enslave がそれ以外の理由で失敗した port は warning を出して記録に残し、次の起動で enslave し直します
- attach 時に指定した port は、別の device に enslave されていれば付け替えます。実行時に足した port は付け替えずに拒否します
- `VrfShow` の bridge の `members` は両方を合わせたものです

member の追加と削除は `VrfBridgeAttach` と同じ mutex の下で行います。FDBWatcher と EVPN は bridge 単位で動くので、member の増減では何もしません。

## xdp モードの BUM

xdp モードの BUM ([bum_mode.md](bum_mode.md)) の devmap と `bum_tx_map` は、`headend_l2` の AC、`bd_peer` の flood slot、経路から組み立てます。どの device に XDP が attach されているかは参照しないので、実行時の attach と detach で devmap を組み直す必要はありません。

- AC は `HeadendL2Create` の時点で、uplink は flood slot の経路が解決した時点で devmap と `bum_tx_map` に入ります。attach の順序は問いません
- detach した device の entry は残ります。その device へ送るコピーの扱いは attach の有無で変わりません
- interface を削除すると、kernel が devmap から entry を外します

## 排他

attach の表は `pkg/vinbero` が mutex 1 つで守ります。attach / detach / list / 起動時の再 attach と終了時の一括 detach はこの mutex の下で行い、state file への書き込みもその中で行います。そのため同じ interface への attach と detach が並行しても、kernel と state の順序は入れ替わりません。`DeviceService` の handler は lock を持ちません。

## 関連ドキュメント

- [persistence.md](persistence.md): state file と再起動時の挙動
- [vrf.md](vrf.md): VRF オブジェクトと bridge facet
- [configuration.md](configuration.md): `internal.devices` と `internal.bpf.device_mode`
- [cni.md](cni.md): `DeviceService` で pod の veth を載せる CNI plugin
