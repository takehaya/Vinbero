# CNI plugin (L3 mode)

`vinbero` CNI plugin は pod を Vinbero の VRF に接続し、pod のアドレスを /32 の VPNv4 経路として広告します。別 node の pod へは SRv6 L3VPN (End.DT4) で届きます。Multus の secondary network として使う前提です。cluster の primary CNI は ClusterIP、DNS、NetworkPolicy をそのまま担い、Vinbero はテナントごとの追加 interface (`net1` など) だけを受け持ちます。

## 構成

- binary は `cmd/vinbero-cni`、実装は `pkg/cni` です。CNI 1.0 (0.3.1 / 0.4.0 も可) の ADD / DEL / CHECK を実装します
- node 上の作業は binary 自身が netlink で行い、data plane と BGP の操作は同じ node の vinberod に Connect RPC で頼みます。経路は `vbctl` と同じです。CNI 用の常駐 daemon はありません
- IPAM は network configuration の `ipam` に書いた IPAM plugin (host-local、whereabouts など) に委譲します
- NetworkAttachmentDefinition (以下 NAD) 1 つが VRF 1 つに対応します

## 接続の形

pod ごとに veth を 1 組作ります。host 側の名前は `vb` + (container ID と interface 名の hash) で、DEL は記録が無くても同じ名前を求められます。

```
pod netns                              node (host netns)
  net1  10.100.1.2/32   <--- veth --->   vbXXXXXXXXXXX  master tenant-a, XDP generic
  10.100.0.0/16 via 169.254.1.1 onlink   10.100.1.2/32 dev vbX... table 100 proto static
  neigh 169.254.1.1 = host veth MAC      neigh 10.100.1.2 = pod MAC
  (neighbour は両側とも nud permanent)
```

- pod 側には IPAM のアドレスを /32 で付けます。IPAM が返した prefix (例: /16) と IPAM の `routes` は、どこにも付けない gateway `169.254.1.1` 経由の経路にします (`onlink`)。gateway の neighbour は host veth の MAC で permanent に置くので、pod は ARP を出しません。primary network の default route には触れません。IPAM が `0.0.0.0/0` を返すと ADD は失敗し、primary の経路と同じ宛先の経路も置き換えずに失敗させます
- host 側の veth は VRF device に enslave します。同じ node の pod 間は kernel の VRF table で折り返します
- host 側に pod の /32 を `proto static` で VRF table に入れます。vinberod の route watcher は redistribute `static` が RTPROT_STATIC だけを拾うので、これが VPNv4 広告の起点になります。pod の permanent neighbour も入れ、End.DT4 の decap 後の `bpf_fib_lookup` が NO_NEIGH に落ちないようにします
- host veth は `DeviceAttach` で XDP / TC に載せ、`VrfAcAdd` で VRF の ingress AC にします
- MTU は既定で 1436 です。1500 の underlay から外側 IPv6 header (40) と SID 1 つの SRH (8 + 16) を引いた値です

pod から別 node の pod への packet は host veth の XDP で headend (`headend_v4_map`、BGP で学んだ /32) に当たり、SRv6 で encap されて underlay へ redirect されます。相手の node では End.DT4 が decap し、VRF table の /32 と permanent neighbour で host veth へ redirect します。

## network configuration

```json
{
  "cniVersion": "1.0.0",
  "name": "tenant-a",
  "type": "vinbero",
  "server": "127.0.0.1:8080",
  "vrf": "tenant-a",
  "tableId": 100,
  "rd": "65000:100",
  "rts": [{"family": "vpnv4", "rt": "65000:100", "direction": "both"}],
  "locator": "LOC1",
  "ipam": {"type": "whereabouts", "range": "10.100.0.0/16"}
}
```

| field | 既定値 | 意味 |
|---|---|---|
| `server` | `127.0.0.1:8080` | vinberod の RPC address (`internal.server.bind`)。`host:port` か URL |
| `mode` | `l3` | `l3` のみ |
| `vrf` / `tableId` | 必須 | VRF 名と kernel の table。無ければ作り、あれば同じ table か検証します。`global` と table 0 / 253-255 は使えません |
| `rd` / `rts` / `locator` | 省略可 | BGP binding。3 つそろえて書きます。`rts[].family` は `vpnv4` / `vpnv6`、`direction` は `import` / `export` / `both` (省略時 `both`) |
| `maxPrefixes` | 0 (無制限) | binding を作るときの広告数の上限 |
| `deviceMode` | `generic` | host veth の XDP attach mode。`generic` / `driver` |
| `mtu` | 1436 | veth 両端の MTU |
| `dataDir` | `/var/lib/vinbero/cni` | attachment の記録を置く directory。subnet の重なりの検査はこの中の記録を見るので、node 上のすべての NAD で同じ値にします |
| `ipam` | 必須 | 委譲先の IPAM plugin の設定 |

binding の扱いは次のとおりです。

- `rd` / `rts` / `locator` を書くと、ADD は VRF に binding が無ければ `redistribute: [static]` 付きで作ります
- binding が既にあれば書き換えません。RD と locator が一致し、`static` を redistribute していることだけを確かめ、違えば ADD を失敗させます。binding の持ち主は vinberod の config か別の NAD かもしれないためです
- 書かなければ binding には触れません。vinberod の config で VRF と binding を宣言する使い方です

## ADD / DEL / CHECK

ADD は次の順に進みます。

1. IPAM ADD で IPv4 アドレスを得ます
2. 別の VRF の pod が同じ node で使っている subnet と重なれば拒否します (後述)
3. attachment を `dataDir` に記録します。以降で失敗したときは DEL と同じ手順で巻き戻します
4. veth を作り、pod 側を設定します
5. `VrfCreate` (adopt を含む) と、必要なら `VrfBgpBind` を呼びます
6. host veth を VRF に enslave し、`VrfAcAdd`、`DeviceAttach` を呼びます
7. 最後に VRF table へ /32 と neighbour を入れます。veth が data plane に載ってから広告が出ます

DEL は記録を読み、逆順に /32 と neighbour の削除 (withdraw)、`DeviceDetach`、`VrfAcRemove`、veth の削除、IPAM DEL を行います。どの手順も「既に無い」を成功として扱います。記録が無い場合 (ADD が途中で止まった、DEL の再実行) も、veth の名前は導出できるので data plane 側は片付きます。途中の手順が失敗すると記録を残してエラーを返し、runtime の再実行で収束させます。`VrfAcRemove` が失敗した場合は veth の削除と IPAM DEL を行わず、再実行に回します。vinberod に届かない間は DEL も失敗します。

VRF と binding は最後の pod が消えても残します。

CHECK は記録、IPAM CHECK、pod 側のアドレス、host 側の VRF 所属と /32、`DeviceList` の attach を確かめます。

## vinberod 側に必要な設定

```yaml
internal:
  devices: [eth0]            # underlay
  server:
    bind: "127.0.0.1:8080"   # network configuration の server
bgp:
  global:
    local_asn: 65000
    router_id: "10.0.0.1"
    source_locator: LOC1
    auto_advertise: true     # VRF table の static 経路を VPNv4 で広告する
    next_hop: "2001:db8::1"  # この node の loopback
  locators:
    - name: LOC1
      prefix: fd00:1::/48
      block_len: 32
      node_len: 16
      function_len: 16
      argument_len: 64
  peers:
    - neighbor: "2001:db8::2"
      peer_asn: 65000
      families: [vpnv4]
```

VRF と binding も config で宣言しておくことを勧めます。RPC で作った binding と AC は daemon の再起動で消えるためです ([persistence.md](persistence.md))。config で宣言した binding は再起動後も残り、VRF table に残っている /32 は再び広告されます。host veth の attach は state file から戻ります。

```yaml
vrfs:
  entries:
    - name: tenant-a
      table_id: 100
bgp:
  vrf_bindings:
    - vrf_name: tenant-a
      rd: "65000:100"
      default_locator: LOC1
      redistribute: [static]
      families:
        vpnv4:
          route_targets:
            - rt: "65000:100"
              direction: both
```

## 導入

1. 各 node に binary を `/opt/cni/bin/vinbero` として置きます (`type` の値が binary 名です)。DaemonSet の initContainer で配る形を想定しています
2. vinberod を host network で動かし、上の設定を入れます
3. NAD を作ります

```yaml
apiVersion: k8s.cni.cncf.io/v1
kind: NetworkAttachmentDefinition
metadata:
  name: tenant-a
spec:
  config: |
    {
      "cniVersion": "1.0.0",
      "name": "tenant-a",
      "type": "vinbero",
      "vrf": "tenant-a",
      "tableId": 100,
      "ipam": {"type": "whereabouts", "range": "10.100.0.0/16"}
    }
```

pod は `k8s.v1.cni.cncf.io/networks: tenant-a` の annotation で接続します。whereabouts は cluster 全体でアドレスを払い出すので、node をまたいで同じ range を使えます。host-local は node ごとに重ならない range を書きます (`routes` に cluster 全体の range を足すと、pod は別 node の pod にも net1 で届きます)。

## 制約

- IPv4 だけです。IPAM が IPv6 を返すと ADD は失敗します
- L3 mode だけです。EVPN L2 mode は未実装です
- `headend_v4_map` は VRF を key に持たないので、VRF 間で pod の subnet が重なると encap の LPM が衝突します。plugin は同じ node の記録 (veth が残っているもの) どうしで subnet の重なりを拒否しますが、別 node で別の VRF が同じ subnet を使う場合は検出できません。NAD 間で subnet を重ねないでください
- vinberod を再起動すると、plugin が足した AC と、network configuration から作った binding は消えます。default-deny を有効にしている node では、再起動後の pod の通信が AC 不在で落ちます。binding は config で宣言し、default-deny を使う場合は再起動後に pod を作り直してください
- vinberod が `settings.l2.bum_mode: xdp` で動いている node では、host veth の attach mode は `internal.bpf.device_mode` と同じでなければなりません。`device_mode: driver` の node では `deviceMode: driver` を指定しないと ADD が失敗します
- `deviceMode: driver` (veth の native XDP) では、host veth へ redirect した frame を pod 側 veth が受け取るために、pod 側 veth にも XDP program か GRO が要ります。plugin はそれを設定しないので、既定の `generic` を使ってください
- MTU は SID 1 つの SRH を前提にしています。SR Policy で transport SID を足す場合や underlay の MTU が違う場合は `mtu` で指定してください

## 関連ドキュメント

- [device_attach.md](device_attach.md): `DeviceService` と実行時 attach
- [vrf.md](vrf.md): VRF オブジェクトと AC
- [srv6_bgp.md](srv6_bgp.md): VPNv4 の auto-advertise
- [persistence.md](persistence.md): 再起動で残るもの
- [examples/cni-l3](../../../examples/cni-l3/): 2 PE の E2E
