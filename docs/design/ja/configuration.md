# Configuration (`vinbero.yml`)

Vinbero の daemon (`vinberod`) は YAML ファイル 1 本で設定します (`-c <path>` で指定、デフォルトは `/etc/vinbero/vinbero.yaml`)。ランタイム状態 (SID / Headend / FDB 等) は API / CLI 経由で投入する想定で、YAML には **起動時に固定したい値** だけを書きます。

## ファイル構造

トップレベルは 2 セクション:

```yaml
internal:    # daemon 内部 (デバイス, BPF, server bind, logger)
  ...
settings:    # 挙動フラグと map capacity
  ...
```

## 全フィールド一覧

### `internal.devices` (必須)

XDP をアタッチするインターフェース名の配列。`make bpf-gen` 済みの BPF オブジェクトが各デバイスの ingress に attach されます。

```yaml
internal:
  devices:
    - eth0
    - eth1
```

### `internal.bpf.*`

| キー | 型 | デフォルト | 説明 |
|---|---|---|---|
| `device_mode` | enum | `driver` | XDP attach mode。`generic` / `driver` / `offload` |
| `verifier_log_level` | int | `2` | eBPF verifier ログレベル (0-4) |
| `verifier_log_size` | uint32 | `1073741823` | verifier log バッファサイズ |

```yaml
internal:
  bpf:
    device_mode: generic       # veth / netns テスト時は generic
    verifier_log_level: 2
```

`device_mode` の使い分け:
- `generic`: どの NIC / veth でも動く汎用モード。dev / test 向け
- `driver`: NIC ドライバ (XDP native) モード。本番パフォーマンス最大
- `offload`: NIC HW へ offload (対応 NIC のみ)

### `internal.server.*`

| キー | 型 | デフォルト | 説明 |
|---|---|---|---|
| `bind` | string | `0.0.0.0:8080` | Connect RPC サーバの待受アドレス |

```yaml
internal:
  server:
    bind: "127.0.0.1:8080"
```

### `internal.logger.*`

| キー | 型 | デフォルト | 説明 |
|---|---|---|---|
| `level` | enum | `info` | `debug` / `info` / `warn` / `error` |
| `format` | enum | `text` | `text` / `json` |
| `no_color` | bool | `false` | 色出力を無効化 (journal 等) |
| `add_caller` | bool | `false` | caller file:line を付ける (debug 用) |

```yaml
internal:
  logger:
    level: debug
    format: text
    no_color: false
    add_caller: true
```

### `settings.enable_stats`

`true` で per-action global stats (`stats_map`) と per-slot invocation stats (`slot_stats_*`) を有効化します。BPF 側は `const volatile enable_stats` としてコンパイル時置換され、`false` 時は stats 書き込み経路自体が dead code 化 (hot path コスト 0)。

```yaml
settings:
  enable_stats: true
```

有効化しないと `vinbero stats show` / `stats slot show` は全ゼロを返します。

### `settings.pin_maps.*`

制御状態 BPF マップを `/sys/fs/bpf/` に pin して **daemon 再起動後もデータを残す**オプション。デフォルト無効 (従来通り in-memory)。詳細と運用上の注意は [persistence.md](persistence.md) を参照。

| キー | 型 | デフォルト | 説明 |
|---|---|---|---|
| `enabled` | bool | `false` | pin を有効化 |
| `path` | string | `/sys/fs/bpf/vinbero` | pin 先ディレクトリ (bpffs 上) |

```yaml
settings:
  pin_maps:
    enabled: true
    path: /sys/fs/bpf/vinbero
```

pin 対象: `sid_function_map` / `sid_aux_map` / `headend_v4_map` / `headend_v6_map` / `headend_l2_map` / `fdb_map` / `bd_peer_map` / `bd_peer_reverse_map` / `dx2v_map` の 9 本。stats / slot_stats / PROG_ARRAY 等は pin しません。

### `settings.state_path`

ネットワークリソース (Bridge / VRF) の **管理状態を永続化する JSON ファイル**。詳しくは [persistence.md](persistence.md) を参照。

| 型 | デフォルト | 説明 |
|---|---|---|
| string | `/var/lib/vinbero/state.json` | state ファイルパス |

```yaml
settings:
  state_path: /var/lib/vinbero/state.json
```

### `settings.fdb_aging_seconds`

End.DT2 の FDB エントリを aging で削除する秒数。`0` で aging 無効 (静的 FDB のみ)。

| 型 | デフォルト |
|---|---|
| int | `300` (5 分) |

```yaml
settings:
  fdb_aging_seconds: 300
```

### `settings.entries.*.capacity`

各 BPF マップの `max_entries`。ELF 上のコンパイル時値は 1024 ですが、このキーで **ロード時に拡張**できます (縮小は kernel 仕様上不可)。

| キー | デフォルト | 対応 map |
|---|---|---|
| `sid_function.capacity` | `1024` | `sid_function_map` (LPM_TRIE) |
| `headendv4.capacity` | `1024` | `headend_v4_map` |
| `headendv6.capacity` | `1024` | `headend_v6_map` |
| `headend_l2.capacity` | `1024` | `headend_l2_map` |
| `fdb.capacity` | `1024` | `fdb_map` |
| `bd_peer.capacity` | `1024` | `bd_peer_map` |
| `vlan_table.capacity` | `1024` | `dx2v_map` |
| `max_segments` | `10` | SRv6 segment list の最大長 |

```yaml
settings:
  entries:
    sid_function:
      capacity: 8192
    fdb:
      capacity: 65536
    max_segments: 10
```

### `vrfs.*`

VRF オブジェクトを boot 時に宣言します (設計は [vrf.md](vrf.md) を参照)。runtime の変更は `vbctl vrf` / `VrfService` で行い、この section は加算的です。entry を消しても作成済みの kernel device は消えません (削除は明示的な `vbctl vrf delete`)。

| キー | 型 | 説明 |
|---|---|---|
| `vrfs.default_deny` | bool | どの VRF にも分類されない ingress AC のパケットを drop する (global default-deny) |
| `vrfs.deny_action` | string | default-deny 時の動作。`drop` (デフォルト) か `pass` |
| `vrfs.entries[].name` | string | VRF 名。予約名 `global` は vrf_id 0 (underlay) に対応し、AC は持てるが kernel device は持てない |
| `vrfs.entries[].table_id` | uint32 | 0 以外で kernel VRF device を作成 (既存 device は adopt)。End.DT4/DT6/DT46 の FIB lookup 先 |
| `vrfs.entries[].members` | []string | device に enslave する interface。`table_id` が必要 |
| `vrfs.entries[].enable_l3mdev_rule` | bool | l3mdev ip rule (prio 1000) を入れる。`table_id` が必要 |
| `vrfs.entries[].acs[].interface` | string | この VRF に分類する ingress interface |
| `vrfs.entries[].acs[].vlan` | uint16 | VLAN ID (0 = untagged) |
| `vrfs.entries[].bridge.name` | string | L2 facet の bridge device 名。End.DT2/DT2M の配送先 |
| `vrfs.entries[].bridge.bd_id` | uint16 | Bridge Domain ID (1..65535)。EVPN の bridge domain はこの facet が唯一の出所で、同じ VRF の binding が受信した EVPN route はこの bd に install される |
| `vrfs.entries[].bridge.members` | []string | bridge に enslave する interface |

```yaml
vrfs:
  default_deny: false
  entries:
    - name: vrf-cust          # kernel device + ingress 分類の両 facet
      table_id: 100
      enable_l3mdev_rule: true
      acs:
        - interface: eth1
          vlan: 100
    - name: vpn-a             # deviceless (ingress 分類のみ、MUP gateway 等)
      acs:
        - interface: eth2
```

default_deny を有効にする場合、underlay や control plane が使う interface も必ずどこかの VRF (通常は `global`) に map してください。未分類 AC が drop されるため、忘れると host 宛の BGP/NDP が通らなくなります。

## 最小構成サンプル

```yaml
internal:
  devices:
    - eth0
    - eth1
  bpf:
    device_mode: driver
  server:
    bind: "0.0.0.0:8080"
  logger:
    level: info

settings:
  enable_stats: true
  entries:
    sid_function:
      capacity: 1024
```

## デモ / 開発向けサンプル

`sdk/examples/plugin-counter/vinbero_config.yaml` のように veth + netns 環境では:

```yaml
internal:
  devices:
    - plgcnt-rt2rt1
    - plgcnt-rt2rt3
  bpf:
    device_mode: generic          # veth は native XDP 非対応
    verifier_log_level: 2
  server:
    bind: "127.0.0.1:8082"
  logger:
    level: debug
    format: text
    add_caller: true

settings:
  enable_stats: true
  entries:
    sid_function:
      capacity: 1024
    headendv4:
      capacity: 1024
    headendv6:
      capacity: 1024
```

## 起動

```bash
sudo ./out/bin/vinberod -c vinbero.yml
```

YAML に書かない動的設定 (SID function / Headend / Bridge / VRF / FDB / plugin 等) は [`vinbero` CLI](getting_started.md) もしくは Connect RPC で daemon に投入します。
