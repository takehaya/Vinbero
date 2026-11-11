# CNI plugin（L2 mode）

*(English: [README.md](./README.md))*

`vinbero` CNI plugin を L2 mode で、container runtime と同じように（環境変数の
`CNI_COMMAND` と stdin の network configuration で）動かします。2 つの PE
namespace が loopback 間で iBGP EVPN session を張った vinberod を動かし、空の
namespace を pod に見立てます。IPAM は参照実装の `host-local` です。

L2 mode では pod は事前宣言された **EVPN bridge domain** に接続します。host 側
の veth が bridge の port になり、pod には on-link の address が付き、1 つの
network の pod が node をまたいで 1 つの Ethernet segment を共有します（同じ
subnet、node をまたぐ ARP / ND、MAC 経路を BGP で配布）。bridge domain（bridge
device と `bd_id`）は各 node の vinberod config で宣言します。plugin はこれを
作りも壊しもしません。

PE1 の `pod1` / `pod1b` / 無言の `pods` と PE2 の `pod2` は `tenant-l2`（bridge
`br-l2`、`bd_id` 100）です。PE1 の `pod1x` と PE2 の `pod2x` は `tenant-l2b`
（bridge `br-l2b`、`bd_id` 200）で、同じ subnet、同じ address、同じ MAC を使う
2 つ目の bridge domain です。全 pod は 1 つの `10.200.0.0/16` を node ごとの
host-local range で分けて使います。

PE1 の `tenant-l2` の network configuration は `rd` / `rts`（family `evpn`）/
`locator` を持つので、最初の ADD が BGP binding を作ります。ほかの binding と
両方の bridge domain は daemon config（`vinbero_pe1.yaml`、`vinbero_pe2.yaml`）
で宣言します。config には `evpn_auto_advertise: true` と
`settings.l2.bum_mode: tc` を入れています。

このテストで確認すること:

- ADD は IPAM の address を on-link で付け（gateway なし、/32 にしない）、host
  veth を bridge と data plane に載せ、AC と `bd_id` の回線として登録し、pod の
  MAC を EVPN RT2 として事前広告する
- bridge domain の bridge は、pod から host stack への経路を与えないように
  hardening される（`disable_ipv6`、`rp_filter`、`arp_ignore`、IPv4 forwarding
  無効）。pod から node address への UDP probe は落ち、`rp_filter` を切ったとき
  だけ届く（negative control）
- pod どうしが node をまたいで、また同じ PE 上で ping と ARP で通信し、IPv6 の
  link-local にも届く（ND は BUM で flood する）
- 無言の pod（一度も送信しない pod）も、static FDB の事前広告で別 node から
  届く
- 同じ subnet、同じ address、同じ MAC を使う 2 つの bridge domain は分離され、
  ping は送信側の bridge domain の pod にだけ届く
- 1422 byte の MTU 内の DF ping は通り、超える DF ping は落ちる
- DEL と再 ADD、pod の veth が先に消えた後の DEL が動く
- daemon の再起動（TERM と KILL）後も、pod を付けたまま host veth が再 attach
  され、`bd_id` の回線が戻り、bridge の hardening が残り、CNI を呼び直さずに
  pod どうしがまた通信できる
- DEL は MAC を withdraw し、veth を detach / 削除し、AC と bridge member を外し、
  address を解放する。最後の pod の後も bridge は残る

テストは `host-local` を `$CNI_PLUGIN_DIR`、`/opt/cni/bin`、`/usr/lib/cni` から
探します（Debian / Ubuntu: `apt install containernetworking-plugins`）。

```bash
make build
sudo ./setup.sh
sudo ./test.sh
sudo ./teardown.sh
```

設計と Multus での導入は [docs/design/ja/cni.md](../../docs/design/ja/cni.md)
を参照してください。
