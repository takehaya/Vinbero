# CNI plugin

`vinbero` CNI plugin は pod を Vinbero のテナントに接続します。Multus の secondary network として使う前提です。cluster の primary CNI は ClusterIP、DNS、NetworkPolicy をそのまま担い、Vinbero はテナントごとの追加 interface (`net1` など) だけを受け持ちます。

mode が 2 つあります。

- **L3 mode** (既定、`mode: l3`)。pod を Vinbero の VRF に接続し、pod のアドレスを /32 の VPNv4 経路として広告します。別 node の pod へは SRv6 L3VPN (End.DT4) で届きます。
- **L2 mode** (`mode: l2`)。pod を EVPN の bridge domain に接続します。1 つの network の pod は、別 node でも同じ Ethernet segment を共有します (同じ subnet、node をまたぐ ARP/ND、MAC 経路を BGP で配布)。別 node の pod へは SRv6 L2VPN (End.DT2U/DT2M) で届きます。[L2 mode](#l2-mode) を参照してください。

以下は L3 mode を既定として説明します。L2 mode の差分は [L2 mode](#l2-mode) にまとめます。

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
- host 側の veth は VRF device に enslave します。同じ node の pod 間は kernel の VRF table で折り返します。VRF は vinberod が作る (plugin の `VrfCreate` か config の `vrfs.entries[]`) ので、table は IPv4 / IPv6 の unreachable default で終わります ([vrf.md](vrf.md#kernel-device-facet))。pod が net1 に送った宛先が VRF table にも headend の表にも無ければ、node の kernel が止めて ICMP unreachable を返し、main table には進みません
- host 側に pod の /32 を `proto static` で VRF table に入れます。vinberod の route watcher は redistribute `static` が RTPROT_STATIC だけを拾うので、これが VPNv4 広告の起点になります。pod の permanent neighbour も入れ、End.DT4 の decap 後の `bpf_fib_lookup` が NO_NEIGH に落ちないようにします
- host veth は `DeviceAttach` で XDP / TC に載せ、`VrfAcAdd` で VRF の ingress AC にします
- MTU は既定で 1436 です。1500 の underlay から外側 IPv6 header (40) と SID 1 つの SRH (8 + 16) を引いた値です

pod から別 node の pod への packet は host veth の XDP で、pod の VRF の headend entry (`headend_v4_map`、BGP で学んだ /32) に当たり、SRv6 で encap されて underlay へ redirect されます。host veth は VRF の AC なので、外側の IPv6 ヘッダの経路は VRF table ではなく main table で引きます。相手の node では End.DT4 が decap し、VRF table の /32 と permanent neighbour で host veth へ redirect します。

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
| `mode` | `l3` | `l3` または `l2` ([L2 mode](#l2-mode)) |
| `vrf` / `tableId` | 必須 | VRF 名と kernel の table。無ければ作り、あれば同じ table か検証します。`global` と table 0 / 253-255 は使えません。`tableId` は L2 mode では使いません |
| `rd` / `rts` / `locator` | 省略可 | BGP binding。3 つそろえて書きます。`rts[].family` は `vpnv4` / `vpnv6`、`direction` は `import` / `export` / `both` (省略時 `both`) |
| `maxPrefixes` | 0 (無制限) | binding を作るときの広告数の上限 |
| `deviceMode` | `generic` | host veth の XDP attach mode。`generic` / `driver` |
| `mtu` | 1436 | veth 両端の MTU |
| `dataDir` | `/var/lib/vinbero/cni` | attachment の記録を置く directory。記録は container ID と interface 名ごとの file で、DEL と CHECK が読みます |
| `ipam` | 必須 | 委譲先の IPAM plugin の設定 |

binding の扱いは次のとおりです。

- `rd` / `rts` / `locator` を書くと、ADD は VRF に binding が無ければ `redistribute: [static]` 付きで作ります
- binding が既にあれば書き換えません。RD、locator、NAD に書いた family の route target、(指定があれば) `maxPrefixes` が一致し、`static` を redistribute していることを確かめ、違えば ADD を失敗させます。binding の持ち主は vinberod の config か別の NAD かもしれないためです
- 書かなければ binding には触れません。vinberod の config で VRF と binding を宣言する使い方です
- vpnv4 / vpnv6 の RT を持つ binding が 1 つも無い間、その family の VPN 経路はすべて受け入れられます。binding の作成や削除でその family の import 判定が変わると、vinberod はその family の受信済み経路を評価し直します。最初の binding の時点でこの全受け入れは終わるので、どの VRF も import しない経路は data plane から消えます。評価は ADD の RPC とは別に非同期で行い、失敗すれば log に残して再試行します ([srv6_bgp.md](srv6_bgp.md#binding-と-locator-の変更による再評価))

## ADD / DEL / CHECK

ADD は次の順に進みます。

1. IPAM ADD で IPv4 アドレスを得ます
2. attachment を `dataDir` に記録します。以降で失敗したときは DEL と同じ手順で巻き戻します
3. veth を作り、pod 側を設定します
4. VRF が無ければ `VrfCreate` を呼び、必要なら `VrfBgpBind` を呼びます
5. host veth を VRF に enslave し、`VrfAcAdd`、`DeviceAttach` を呼びます
6. 最後に VRF table へ /32 と neighbour を入れます。veth が data plane に載ってから広告が出ます

DEL は記録を読み、逆順に /32 と neighbour の削除 (withdraw)、`DeviceDetach`、`VrfAcRemove`、veth の削除、IPAM DEL を行います。どの手順も「既に無い」を成功として扱います。記録が無い場合 (ADD が途中で止まった、DEL の再実行) も、veth の名前は導出できるので data plane 側は片付きます。途中の手順が失敗すると記録を残してエラーを返します。`VrfAcRemove` が失敗した場合は veth の削除と IPAM DEL を行いません。vinberod に届かない間は DEL も失敗します。

失敗した DEL が片付くかどうかは runtime によります。DEL を再実行する runtime なら、次の DEL で残りを片付けます。Multus の thick plugin は delegate の DEL の失敗を runtime に返さないので、再実行は来ません。この場合 veth と /32 は pod の netns とともに消えますが、次のものが残ります。

- IPAM の lease。whereabouts なら reconciler が回収します。host-local には回収の仕組みがありません
- `dataDir` の attachment の記録。ほかの pod の ADD、DEL、CHECK は読まないので、通信にも配線にも関係しません。不要なら file を消します
- vinberod が持つ attach の記録 (`DeviceDetach` が失敗したとき)。interface はもう無いので通信には関係せず、vinberod の次の再起動で消えます
- vinberod が持つ AC の記録 (`VrfAcRemove` が失敗したとき)。これも通信には関係しません。再起動後も `state.json` に残り、reconcile で飛ばされます (warning は 1 度だけ出ます)。消すには `vbctl vrf ac-remove` を実行します

VRF と binding は最後の pod が消えても残します。

CHECK は記録、IPAM CHECK (whereabouts のように CHECK を実装しない IPAM plugin の "not implemented" は無視します)、pod 側のアドレス、host 側の VRF 所属と /32、`DeviceList` の attach を確かめます。

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
    listen_port: 179         # 既定の -1 は listen しない
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

vinberod は `--bgp-enabled` を付けて起動します。付けないと `bgp` の設定があっても BGP は動きません。`listen_port` の既定値 `-1` では TCP の listen をしないので、node どうしの iBGP には例のように `179` を指定します。`router_id`、`next_hop`、locator の `prefix` は node ごとに変えます。

network configuration から作った binding は state file に保存され、daemon の再起動後も同じ内容で戻ります ([persistence.md](persistence.md#vrf-の-bgp-binding))。config で宣言した binding も再起動後に残り、どちらでも VRF table に残っている /32 は再び広告されます。host veth の attach と、plugin が足した AC も state file から戻ります。network configuration の `locator` は config の `bgp.locators` で宣言するか、`vbctl locator create` で登録します。API で登録した locator も state file に保存され、再起動では binding より前に戻るので、それを使う binding は再起動の後もそのまま広告されます ([persistence.md](persistence.md#locator))。VRF と binding と locator を config で宣言しておくと、node の設定が config だけで分かります。

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

`vrfs.default_deny: true` にすると、どの VRF の AC でもない interface の packet をすべて drop します。underlay の interface も対象なので、`global` VRF の AC にしてください。そうしないと SRv6 も BGP も止まります ([vrf.md](vrf.md))。

```yaml
vrfs:
  default_deny: true
  entries:
    - name: global
      acs:
        - interface: eth0    # underlay
```

## node の準備

各 node に、vinberod の起動より前に次を設定します。node の再起動で消えるので、起動のたびに必要です。

- BGP の peer と `next_hop` に使う loopback の IPv6 アドレス (/128)
- ほかの node の loopback への経路。BGP の TCP の source を loopback にするため `src` を指定します
- ほかの node の locator への経路
- IPv4 と IPv6 の forwarding の sysctl

node 1 の例です。underlay は eth0 で、node 2 の eth0 のアドレスを `2001:db8:12::2` とします。

```bash
ip -6 addr add 2001:db8::1/128 dev lo
ip -6 route add 2001:db8::2/128 via 2001:db8:12::2 dev eth0 src 2001:db8::1
ip -6 route add fd00:2::/48 via 2001:db8:12::2 dev eth0
sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
```

`bpf_fib_lookup` は forwarding が無効な interface では失敗するので、この 2 つは必須です。SRv6 は XDP が処理するので `seg6_enabled` は要りません。

同じ node の pod 間の packet は kernel の forwarding を通るので、node の netfilter も通ります。cluster CIDR 以外の宛先をまとめて MASQUERADE する規則 (kindnet の kind-masq-agent など) があると、IPv4 アドレスを持たない host veth では packet が捨てられ、dmesg に `vbXXXXXXXXXXX ate my IP address` と出ます。host veth を NAT の対象から外してください。この規則も node の起動のたびに必要です。

```bash
iptables -t nat -I POSTROUTING 1 -o vb+ -j RETURN
```

## 導入

1. 各 node を [上記](#node-の準備) のとおり準備します
2. 各 node に binary を `/opt/cni/bin/vinbero` として置きます (`type` の値が binary 名です)。DaemonSet の initContainer で配る形を想定しています
3. vinberod を host network で `--bgp-enabled` を付けて動かし、上の設定を入れます
4. NAD を作ります

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

## テナントの分離

NAD ごとに VRF が分かれ、pod の通信は次のように VRF の中に閉じます。

- pod の /32 は NAD の `tableId` の VRF table に入り、permanent neighbour は pod ごとの host veth に付きます
- host veth はその VRF の AC なので、pod が net1 に送った packet は、その VRF の headend entry だけで引かれます。一致しなければ、global VRF も別の VRF も引かずに kernel へ渡し、kernel はその VRF table を引きます。table に無い宛先は unreachable default で止まります。kernel が `BPF_FIB_LOOKUP_TBID` を受け付けない場合と `internal.bpf.fib_lookup_tbid: "off"` の場合は unreachable default が入らず、table に無い宛先は main table へ進みます ([vrf.md](vrf.md#encap-の外側の経路))
- 別の node の pod の /32 は、受信した経路の RT がその VRF の import RT に一致したときだけ、その VRF の headend entry になります

そのため pod が net1 で届くのは、同じ VRF の pod (同じ node なら VRF table で、別の node なら SRv6 で) と、その VRF が import した経路の宛先です。VRF table が unreachable default で終わらない上の場合は、main table の宛先にも届きます。NET_ADMIN を持つ pod が net1 経由の経路を足しても、別の VRF の pod へは encap されません。tenant の AC から来た packet は node の local SID も使えないので、別の VRF の End.DT4 の SID を宛先にしても decap されません ([vrf.md](vrf.md#local-sid-と-ac))。

### 同じ subnet を別の NAD で使う

VRF が違えば、NAD どうしで subnet が重なっていても、同じアドレスが 2 つの tenant にあっても構いません。同じ node でも別の node でも、それぞれの pod は自分の VRF の pod にだけ届きます。2 つ目の NAD では次を 1 つ目と変えます。

- `vrf` と `tableId`
- RD。pod の /32 は VRF ごとに、その VRF の RD で広告されます。2 つの VRF が同じ RD で同じ /32 を広告すると、BGP では 1 つの経路になり、片方が届かなくなります
- route target。import RT が相手の VRF の export RT と重なると、相手の経路も取り込みます
- IPAM の pool。whereabouts は range ごとに 1 つの pool で払い出すので、`ipam` に NAD ごとの `network_name` を書いて pool を分けます。host-local は network の `name` ごとに lease を持つので、`name` が違えば別々に払い出します

```json
"ipam": {"type": "whereabouts", "range": "10.100.0.0/16", "network_name": "tenant-b"}
```

同じ VRF の中でアドレスが重ならないようにするのは IPAM の役目で、plugin は検査しません。同じ VRF を指す NAD を複数作る場合は、range が重ならないようにします。

## L2 mode

L2 mode (`mode: l2`) は pod を EVPN の bridge domain に接続します。host 側 veth を bridge の port にし、pod には IPAM のアドレスを on-link で付けます。同じ network の pod は、別 node でも 1 つの Ethernet segment を共有します。別 node の pod へは SRv6 L2VPN (End.DT2U/DT2M) で届き、MAC 経路は EVPN RT2、BUM の宛先は RT3 で配ります ([fdb_vrf.md](fdb_vrf.md)、[bridge_domain.md](bridge_domain.md))。

### bridge domain の所有

bridge domain (bridge device と `bd_id`) は node の vinberod config で事前に宣言します (`vrfs.entries[].bridge`)。plugin は bridge domain を作りも壊しもせず、最後の pod が消えても残します。そのため、1 つの network に参加する node の数は、pod の有無ではなく「その bridge domain を宣言した node の数」で数えます。bridge domain を宣言した各 node は、ほかの node の flood スロットを 1 つずつ使います (1 つの bridge domain に remote PE 32 台、計 33 node。[bum_mode.md](bum_mode.md))。参加しない node では宣言しないでください。

### network configuration

```json
{
  "cniVersion": "1.0.0",
  "name": "tenant-l2",
  "type": "vinbero",
  "mode": "l2",
  "vrf": "tenant-l2",
  "bridge": "br-l2",
  "bdId": 100,
  "rd": "65100:1001",
  "rts": [{"family": "evpn", "rt": "65000:100", "direction": "both"}],
  "locator": "LOC1",
  "mtu": 1422,
  "ipam": {"type": "whereabouts", "range": "10.200.0.0/16"}
}
```

| field | 既定値 | 意味 |
|---|---|---|
| `mode` | — | `l2` |
| `vrf` | 必須 | bridge domain を持つ VRF の名前。config で bridge facet を宣言した VRF と一致させます。`tableId` は使えません |
| `bridge` / `bdId` | 必須 | config で宣言した bridge device 名と `bd_id` (1..65535)。plugin は VRF がこの bridge facet を持つことを確認し、無ければ ADD を失敗させます |
| `rd` / `rts` / `locator` | 省略可 | EVPN binding。3 つそろえて書きます。`rts[].family` は `evpn` だけです。書けば、binding が無い VRF に `redistribute` なしで binding を作ります。書かなければ config の binding を使います |
| `mtu` | 1422 | underlay 1500 から外側 IPv6 (40)、SID 1 つの SRH (24)、内側 Ethernet (14) を引いた値です |
| `deviceMode` / `dataDir` / `server` / `maxPrefixes` | L3 と同じ | |
| `ipam` | 必須 | IPv4 のみ。委譲先の IPAM。1 つの bridge domain は node 間で重ならない払い出しが要ります (whereabouts、または host-local を node ごとに range 分け) |

RD は node ごと、RT は tenant ごとにそろえます。推奨は、config で node 固有の binding と locator を宣言し、NAD には共通の bridge/`bdId`/VRF と IPAM を書く形です。

### 接続の形

```
pod netns                               node (host netns)
  net1  10.200.1.5/16 (on-link)  <-veth->  vbXXXXXXXXXXX  master br-l2, XDP generic
  (gateway なし。同じ subnet は ARP で)              br-l2  bd_id 100  (L3 role なし)
```

- pod 側には IPAM の prefix をそのまま on-link で付けます。疑似 gateway も permanent neighbour も使いません。IPAM が外部経路や default route を返すと ADD は失敗します (L2 は直結 subnet だけを運びます)。IPv6 IPAM は範囲外です (IPAM が IPv6 を返すと失敗します)。Ethernet としての IPv6/ND は運べます
- host 側 veth は bridge の member にし (`VrfBridgeMemberAdd`)、tenant の AC (`{veth, VLAN 0}`) にし (`VrfAcAdd`)、`bd_id` 付きの `headend_l2` 回線にし (`HeadendL2Create`)、`DeviceAttach` で XDP に載せます
- tc BUM mode では、ADD で pod の MAC を bridge の static FDB に登録します。pod がまだ 1 フレームも送っていなくても RT2 を広告でき、無言の pod にも別 node から届きます

pod が net1 に送ったフレームは host veth の XDP で処理します。宛先 MAC が bridge domain で既知 (RT2 で学習済み) なら End.DT2U で SRv6 encap して相手 node へ送り、未知 unicast と broadcast/multicast は BUM として RT3 の相手へ flood します。相手 node では End.DT2U/DT2M が decap し、bridge domain の FDB で local の pod へ届けます。

### bridge に L3 の役割を持たせない (host stack の分離)

bridge domain の bridge は L2 専用です。IP アドレスも gateway も持ちません。ただし bridge device には host の IP 入力経路があり、pod が bridge の MAC 宛にフレームを送ると host stack に届きます。forwarding は underlay のために有効なので、それを塞がないと、pod が別 PE の SID 宛に送ったフレームが underlay へ出て別 tenant に decap されたり、IPv4/GTP-U が node のサービスや別 PE の headend に届いたりします。plugin は、pod の port を bridge に入れる前に (pod 側を down に保ったまま) bridge device でこの経路を両 family とも塞ぎ、CHECK で検証します。

| 設定 | 値 | 塞ぐもの |
|---|---|---|
| `net.ipv6.conf.<bridge>.disable_ipv6` | 1 | bridge の IPv6 stack 全体 (link-local、ND 応答、IPv6 forwarding)。別 BD の SID 宛の SRv6 もここで止まります |
| `net.ipv4.conf.<bridge>.forwarding` | 0 | bridge で受けた IPv4 の forwarding |
| `net.ipv4.conf.<bridge>.rp_filter` | 1 | strict RPF。bridge は pod source への戻り経路を持たないので、local delivery・forwarding・broadcast が source 検証で落ちます |
| `net.ipv4.conf.<bridge>.arp_ignore` | 8 | local address 宛の ARP 応答 |
| `net.ipv4.conf.<bridge>.{accept_local,route_localnet,proxy_arp}` | 0 | local source の受信、127/8 の route、proxy ARP |
| `net.mpls.conf.<bridge>.input` | 0 | MPLS (kernel が対応する場合) |

これらはどれも L2 の転送を壊しません。host veth の XDP は host stack より前に動き、decap の bridge への redirect は L2 送信 (IP 入力ではない) で、FDB 学習も L2 だからです。これらは bridge device の属性で、daemon の再起動では消えません (node の再起動では消えるので、bridge を宣言した node の準備に含めます)。**operator は bridge に IP アドレスや gateway を付けないでください。** 付けると分離が崩れます。

vinberod を通さず operator が `headend-l2` などで bridge domain を組む場合も、bridge を VRF device に enslave しない限り同じ露出があります。これは「VRF device に enslave されていない AC」の一例です ([vrf.md](vrf.md#local-sid-と-ac))。bridge に同じ sysctl を設定してください。

### ADD / DEL / CHECK

ADD は次の順です。VRF 0 への露出を避けるため、pod 側は最後まで down に保ちます。

1. IPAM ADD で IPv4 アドレスを得て、attachment を記録します
2. config の bridge facet (と、binding を書いていれば binding) を確認します
3. bridge を hardening します
4. veth を作ります (pod 側は down)
5. host veth を bridge の member にし、up にします
6. `VrfAcAdd`、`HeadendL2Create` (`bd_id`)、`DeviceAttach` で front door を用意します
7. tc BUM では pod MAC を bridge の static FDB に登録します
8. 最後に pod 側に on-link アドレスを付けて up にします

DEL は記録の mode に従い逆順に、static FDB、`HeadendL2Delete`、`DeviceDetach`、`VrfAcRemove`、bridge member の削除、veth の削除、IPAM DEL を行います。転送を先に止めてから AC と member を外し、AC と member が消えるまで veth と lease を解放しません。`not_found` はその対象の成功として扱います。netns 消失、veth 消失、DEL の再実行に対応します。bridge domain と binding は最後の pod が消えても残します。

CHECK は記録、IPAM CHECK、pod の on-link アドレス、bridge の hardening、host veth の member 所属、`bd_id` の回線、device attach を確かめます。`mode` の無い旧記録は L3 として読むので、古い plugin が作った attachment の DEL と CHECK はそのまま動きます。

### restart と上限

daemon を再起動しても、bridge facet と member、binding、VRF の vrf_id、実行時 AC、L2 回線は state file から戻り、BGP から RT2/RT3/FDB/peer を受け直します。再起動した daemon は、CNI を呼び直さずに既存の L2 pod を転送します ([persistence.md](persistence.md))。

ADD の成功は、全 remote PE がこの node を受け入れたことを意味しません。bridge domain が flood の上限 (remote PE 32 台) に達した node や、remote peer を入れられなかった node があると、あふれた相手には届きません。daemon の log に `maximum number of peers` が出ます。operator は `vbctl bd-peer list --bd-id N` と daemon の log で、参加 node 数と peer を確認します。

## 制約

- IPv4 だけです。IPAM が IPv6 を返すと ADD は失敗します (L2 mode も同じ。Ethernet としての IPv6/ND は運べます)
- 1 つの pod に、同じ subnet (または同じ `routes` の宛先) を持つ 2 つの NAD は付けられません。pod の経路表は 1 つなので、2 つ目の ADD は同じ宛先の経路を足せずに失敗します。subnet が重なるだけで同じでなければ ADD は通りますが、重なる範囲の宛先には prefix の長い方の network が使われますpod の経路表は 1 つなので、2 つ目の ADD は同じ宛先の経路を足せずに失敗します。subnet が重なるだけで同じでなければ ADD は通りますが、重なる範囲の宛先には prefix の長い方の network が使われます
- vinberod を再起動しても、network configuration から作った binding、plugin が足した AC、VRF の vrf_id は state file から戻るので、pod は再起動後も同じ VRF に分類され、同じ RD と RT で広告されます。config が同じ VRF を bind していれば config の binding が使われます
- node を再起動すると、Multus が CNI の設定を書き直す前に kubelet が pod の sandbox を作り直すことがあります。その pod は primary network だけで Running になり、net1 がありません。`k8s.v1.cni.cncf.io/network-status` annotation は古い値のままなので、再起動後は pod の中で net1 を確認し、無ければ pod を作り直してください
- vinberod が `settings.l2.bum_mode: xdp` で動いている node では、host veth の attach mode は `internal.bpf.device_mode` と同じでなければなりません。`device_mode: driver` の node では `deviceMode: driver` を指定しないと ADD が失敗します
- `deviceMode: driver` (veth の native XDP) では、host veth へ redirect した frame を pod 側 veth が受け取るために、pod 側 veth にも XDP program か GRO が要ります。plugin はそれを設定しないので、既定の `generic` を使ってください
- MTU は SID 1 つの SRH を前提にしています。SR Policy で transport SID を足す場合や underlay の MTU が違う場合は `mtu` で指定してください。L2 mode は内側 Ethernet のぶん 14 byte 小さい 1422 が既定です
- L2 mode の BUM は TC が既定 (`settings.l2.bum_mode: tc`)、attach mode は generic です。XDP BUM と native attach での L2 pod は、MAC の即時撤回と pod 側 veth の受信条件を別に扱うため、今は TC/generic を使ってください
- L2 mode の bridge domain 内では pod どうしが 1 つの L2 に属し、分離はありません。NetworkPolicy は primary network のもので、net1 には効きません

## 関連ドキュメント

- [device_attach.md](device_attach.md): `DeviceService` と実行時 attach
- [vrf.md](vrf.md): VRF オブジェクトと AC
- [srv6_bgp.md](srv6_bgp.md): VPNv4 の auto-advertise
- [fdb_vrf.md](fdb_vrf.md): End.DT2 / bridge domain のデータプレーン (L2 mode)
- [bridge_domain.md](bridge_domain.md): bridge domain と MAC 学習
- [bum_mode.md](bum_mode.md): BUM の複製と flood スロット
- [persistence.md](persistence.md): 再起動で残るもの
- [examples/cni-l3](../../../examples/cni-l3/): L3 mode の 2 PE E2E
- [examples/cni-l2](../../../examples/cni-l2/): L2 mode の 2 PE E2E
