#!/bin/bash
# Bring up the Vinbero PE inside the containerlab node.
#
# Order matters: vinberod must be running before `vbctl locator create`,
# and the locator must exist before BGP routes from FRR settle -- the
# BGP applier needs the source locator registered to turn a received
# VPN route into a headend_v4/v6 map entry.

# setknob writes a sysctl best-effort: container sysfs may be read-only
# for some keys, which must not abort the script.
setknob() {
    sysctl -w "$1=$2" >/dev/null 2>&1 || true
}

# eth1 faces FRR: the BGP session and the SRv6 underlay both ride it.
ip -6 addr add 2001:db8:ff::2/64 dev eth1 2>/dev/null || true
ip link set eth1 up

# SRv6 dataplane knobs (namespace-scoped, best-effort).
setknob net.ipv6.conf.all.forwarding 1
setknob net.ipv6.conf.all.seg6_enabled 1
setknob net.ipv6.conf.eth1.seg6_enabled 1
setknob net.ipv4.conf.all.rp_filter 0

# veth + generic XDP: VLAN offload would hide tags from the XDP program.
ethtool -K eth1 txvlan off 2>/dev/null || true
ethtool -K eth1 rxvlan off 2>/dev/null || true

# BPF filesystem for pinned maps / XDP links.
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

mkdir -p /etc/vinbero
cp /vinbero.yml /etc/vinbero/vinbero.yaml

# Start the daemon with the in-process BGP speaker enabled.
/usr/local/bin/vinberod --bgp-enabled -c /etc/vinbero/vinbero.yaml \
    > /var/log/vinberod.log 2>&1 &
echo $! > /var/run/vinberod.pid

# Wait for the RPC server (localhost:8080) to accept connections.
for i in $(seq 1 30); do
    if /usr/local/bin/vbctl locator list >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Register the SRv6 source locator. `source_locator: LOC1` in
# vinbero.yml references this by name; the applier resolves the encap
# source from its prefix. fd00:100::/48 == Vinbero's locator block.
/usr/local/bin/vbctl locator create \
    --name LOC1 \
    --prefix fd00:100::/48 \
    --block-len 32 --node-len 16 --function-len 16 --argument-len 64 \
    --behavior classic || true

echo "[start.sh] vinbero PE ready"
