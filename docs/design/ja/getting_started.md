# Getting Started

## 前提条件

- Linux kernel 5.15 以上 (eBPF/XDP 対応)
- Go 1.21 以上
- Docker (BPF コード生成用)
- root 権限 (eBPF 操作に必要)

## インストール

```bash
git clone https://github.com/takehaya/Vinbero.git
cd Vinbero
make install-dev-pkg
make install-build-tools
make bpf-gen
make build
```

ビルドが完了すると `out/bin/vinberod` (デーモン) と `out/bin/vinbero` (CLI) が生成されます。

## 最小限の設定ファイル

`vinbero.yml` にはデバイスとサーバーバインドの設定のみ記述します。VRF / Bridge 等のリソースは起動後に API / CLI 経由で設定します。全フィールドの一覧は [configuration.md](configuration.md)、再起動時に何が残る / 消えるかは [persistence.md](persistence.md) を参照してください。

```yaml
internal:
  devices:
    - eth0
    - eth1
  bpf:
    device_mode: generic
  server:
    bind: "0.0.0.0:8080"
  logger:
    level: info

settings:
  enable_stats: true        # vinbero stats / stats slot を使う場合
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

## CLI の使い方

`vinbero` CLI はサーバ URL を `--server` (短縮 `-s`) または `VINBERO_SERVER` 環境変数で指定します。以降の例は `http://localhost:8080` を前提とします。

```bash
export VINBERO_SERVER=http://localhost:8080
# あるいは vinbero -s http://localhost:8080 ... と毎回指定
```

主なコマンド:

| コマンド | 役割 |
|---|---|
| `sid` (`sid-function`) | SRv6 endpoint function 管理 (End / End.DT4 / End.DT2 / ...) |
| `hv4` / `hv6` (`headend-v4/-v6`) | IPv4/IPv6 trigger の Headend (encap) 管理 |
| `hl2` (`headend-l2`) | L2 フレームの Headend (H.Encaps.L2) 管理 |
| `peer` (`bd-peer`) | Bridge Domain のリモート PE (BUM flood 先) 管理 |
| `bridge` | Linux bridge デバイス管理 |
| `vrf` | Linux VRF デバイス管理 |
| `fdb` | FDB エントリ管理 (L2VPN の MAC テーブル) |
| `vt` (`vlan-table`) | VLAN cross-connect (End.DX2V) テーブル |
| `stats` | XDP 統計表示 (global + per-slot) |
| `plugin` | カスタム BPF プラグインの validate / register / unregister |

グローバルフラグ: `--json` で JSON 出力に切替可。

## L2VPN (P2MP) のセットアップ例

2 拠点間の L2VPN (Bridge Domain + BUM flooding) を CLI で構築します。

### 1. Bridge 作成 (decap 側: router3)

```bash
vinbero bridge create \
  --name br100 --bd-id 100 --members eth1
```

### 2. SID 登録 (decap 側: End.DT2)

```bash
vinbero sid create \
  --trigger-prefix fc00:3::3/128 \
  --action END_DT2 \
  --bd-id 100 \
  --bridge-name br100
```

### 3. Headend L2 設定 (両端)

```bash
# router1: forward path
vinbero hl2 create \
  --interface eth0 \
  --vlan-id 100 \
  --src-addr fc00:1::1 \
  --segments fc00:2::1,fc00:3::3 \
  --bd-id 100

# router3: return path
vinbero hl2 create \
  --interface eth1 \
  --vlan-id 100 \
  --src-addr fc00:3::3 \
  --segments fc00:2::2,fc00:1::2 \
  --bd-id 100
```

### 4. リモート PE 登録 (両端 / BUM flood 先)

```bash
# router1 → router3 へ flood
vinbero peer create \
  --bd-id 100 \
  --src-addr fc00:1::1 \
  --segments fc00:2::1,fc00:3::3

# router3 → router1 へ flood
vinbero peer create \
  --bd-id 100 \
  --src-addr fc00:3::3 \
  --segments fc00:2::2,fc00:1::2
```

## L3VPN のセットアップ例

```bash
# VRF 作成
vinbero vrf create \
  --name vrf100 \
  --table-id 100 \
  --members eth0 \
  --enable-l3mdev-rule

# End.DT4 SID (VRF 名で指定)
vinbero sid create \
  --trigger-prefix fc00:3::3/128 \
  --action END_DT4 \
  --vrf-name vrf100
```

## プラグイン: カスタム XDP 機能の追加

プラグインは `sid_endpoint_progs` の slot 32-63 / `headend_v{4,6}_progs` の slot 16-31 に動的ロードできます。ビルドとコンテキストの詳細は [plugin-sdk.md](plugin-sdk.md) 参照。

```bash
# ローカル検証 (サーバ不要 / CI 向き)
vinbero plugin validate --prog plugin.o --program plugin_counter

# サーバへ登録
vinbero plugin register \
  --type endpoint --index 32 \
  --prog plugin.o --program plugin_counter

# そのスロットに紐付く SID を作成
# aux は JSON で (サーバが plugin BTF を使って byte に変換)
vinbero sid create \
  --trigger-prefix fc00:2::32/128 \
  --action 32 \
  --plugin-aux-json '{"increment": 10}'

# 取り外し
vinbero plugin unregister --type endpoint --index 32
```

## 動作確認

```bash
# 管理リソース一覧
vinbero bridge list
vinbero vrf list

# SID / Headend 一覧
vinbero sid list
vinbero hv4 list
vinbero hv6 list
vinbero hl2 list

# FDB エントリ確認
vinbero fdb list

# BD peer
vinbero peer list --bd-id 100

# 統計
vinbero stats show                            # RX / PASS / DROP / REDIRECT / ABORTED
vinbero stats slot show --type endpoint       # builtin + plugin の slot 毎
vinbero stats slot show --plugin-only --top 10 # 人気の plugin slot
```

JSON で取りたいときは `--json` を足します (スクリプト向き):

```bash
vinbero --json sid list | jq '.sid_functions[] | {prefix: .trigger_prefix, action}'
```
