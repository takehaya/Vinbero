# Getting Started

## 前提条件

- Linux kernel 5.15 以上（eBPF/XDP対応）
- Go 1.21 以上
- Docker（BPFコード生成用）
- root権限（eBPF操作に必要）

## インストール

```bash
git clone https://github.com/takehaya/Vinbero.git
cd Vinbero
make install-dev-pkg
make install-build-tools
make bpf-gen
make build
```

ビルドが完了すると `out/bin/vinberod`（デーモン）と `out/bin/vinbero`（CLI）が生成されます。

## 最小限の設定ファイル

`vinbero.yml` にはデバイスとサーバーバインドの設定のみ記述します。VRF/Bridge等のリソースは起動後にAPI経由で設定します。

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

## L2VPN（P2MP）のセットアップ例

2拠点間のL2VPN（Bridge Domain + BUM flooding）を構築する手順です。

### 1. Bridge作成

```bash
# router3: End.DT2用のbridge作成
curl -X POST http://localhost:8080/vinbero.v1.NetworkResourceService/BridgeCreate \
  -H "Content-Type: application/json" \
  -d '{
    "bridges": [{
      "name": "br100",
      "bd_id": 100,
      "members": ["eth1"]
    }]
  }'
```

### 2. SID登録

```bash
# router3: End.DT2 (decap側)
curl -X POST http://localhost:8080/vinbero.v1.SidFunctionService/SidFunctionCreate \
  -H "Content-Type: application/json" \
  -d '{
    "sid_functions": [{
      "trigger_prefix": "fc00:3::3/128",
      "action": "SRV6_LOCAL_ACTION_END_DT2",
      "bd_id": 100,
      "bridge_name": "br100"
    }]
  }'
```

### 3. Headend L2設定（両端）

```bash
# router1: forward path
curl -X POST http://localhost:8080/vinbero.v1.HeadendL2Service/HeadendL2Create \
  -H "Content-Type: application/json" \
  -d '{
    "headend_l2s": [{
      "vlan_id": 100,
      "interface_name": "eth0",
      "src_addr": "fc00:1::1",
      "segments": ["fc00:2::1", "fc00:3::3"],
      "bd_id": 100
    }]
  }'

# router3: return path
curl -X POST http://localhost:8080/vinbero.v1.HeadendL2Service/HeadendL2Create \
  -H "Content-Type: application/json" \
  -d '{
    "headend_l2s": [{
      "vlan_id": 100,
      "interface_name": "eth1",
      "src_addr": "fc00:3::3",
      "segments": ["fc00:2::2", "fc00:1::2"],
      "bd_id": 100
    }]
  }'
```

### 4. リモートPE登録（両端）

```bash
# router1: router3へのBUM flood
curl -X POST http://localhost:8080/vinbero.v1.BdPeerService/BdPeerCreate \
  -H "Content-Type: application/json" \
  -d '{
    "peers": [{
      "bd_id": 100,
      "src_addr": "fc00:1::1",
      "segments": ["fc00:2::1", "fc00:3::3"]
    }]
  }'

# router3: router1へのBUM flood
curl -X POST http://localhost:8080/vinbero.v1.BdPeerService/BdPeerCreate \
  -H "Content-Type: application/json" \
  -d '{
    "peers": [{
      "bd_id": 100,
      "src_addr": "fc00:3::3",
      "segments": ["fc00:2::2", "fc00:1::2"]
    }]
  }'
```

## L3VPN のセットアップ例

```bash
# VRF作成
curl -X POST http://localhost:8080/vinbero.v1.NetworkResourceService/VrfCreate \
  -H "Content-Type: application/json" \
  -d '{
    "vrfs": [{
      "name": "vrf100",
      "table_id": 100,
      "members": ["eth0"],
      "enable_l3mdev_rule": true
    }]
  }'

# End.DT4 SID登録（VRF名で指定）
curl -X POST http://localhost:8080/vinbero.v1.SidFunctionService/SidFunctionCreate \
  -H "Content-Type: application/json" \
  -d '{
    "sid_functions": [{
      "trigger_prefix": "fc00:3::3/128",
      "action": "SRV6_LOCAL_ACTION_END_DT4",
      "vrf_name": "vrf100"
    }]
  }'
```

## 動作確認

```bash
# 管理リソース一覧
curl -s -X POST http://localhost:8080/vinbero.v1.NetworkResourceService/BridgeList \
  -H "Content-Type: application/json" -d '{}' | jq
curl -s -X POST http://localhost:8080/vinbero.v1.NetworkResourceService/VrfList \
  -H "Content-Type: application/json" -d '{}' | jq

# SID一覧
curl -s -X POST http://localhost:8080/vinbero.v1.SidFunctionService/SidFunctionList \
  -H "Content-Type: application/json" -d '{}' | jq

# FDBエントリ確認
curl -s -X POST http://localhost:8080/vinbero.v1.DmacService/DmacList \
  -H "Content-Type: application/json" -d '{}' | jq
```
