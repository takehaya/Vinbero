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
