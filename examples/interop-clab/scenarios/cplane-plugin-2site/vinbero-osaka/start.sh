#!/bin/bash
# pe-osaka: the PE that ADVERTISES a route carrying the plugin's own SRv6
# endpoint behavior.
#
# The control-plane plugin here is granted only `advertise`. It is told,
# through its config blob, which prefix to originate and which SID to put
# behind it, and it stamps its own behavior codepoint (0xFE01) into the
# SID TLV. Nothing in vinbero or in BGP knows what that codepoint means:
# the far end's plugin is what gives it meaning.
#
# The SID itself is an ordinary End.DT4 endpoint provisioned by the
# operator on this node. A plugin that ships its own eBPF half would ask
# the daemon for a SID pointing at its own slot instead; this scenario
# tests the control-plane path, and using a real End.DT4 here is what
# lets the customer ping actually complete.
#
# Interfaces:
#   eth1  pe-osaka <-> core     underlay 2001:db8:2::/64  (pe-osaka = ::1)
#   eth2  pe-osaka <-> ce-osaka customer 10.2.0.0/24      (pe-osaka = .1)
#   lo    loopback 2001:db8:ff::2

setknob() {
    sysctl -w "$1=$2" >/dev/null 2>&1 || true
}

# --- interface addressing --------------------------------------------------
ip -6 addr add 2001:db8:2::1/64 dev eth1 2>/dev/null || true
ip link set eth1 up
ip addr add 10.2.0.1/24 dev eth2 2>/dev/null || true
ip link set eth2 up
ip -6 addr add 2001:db8:ff::2/128 dev lo 2>/dev/null || true
ip link set lo up

# --- SRv6 dataplane knobs --------------------------------------------------
setknob net.ipv4.ip_forward 1
setknob net.ipv6.conf.all.forwarding 1
setknob net.ipv6.conf.all.seg6_enabled 1
setknob net.ipv6.conf.eth1.seg6_enabled 1
setknob net.ipv6.conf.eth2.seg6_enabled 1
setknob net.ipv4.conf.all.rp_filter 0
setknob net.ipv4.conf.default.rp_filter 0
setknob net.ipv4.conf.eth2.rp_filter 0

# veth + generic XDP: VLAN offload would hide tags from the XDP program.
for i in eth1 eth2; do
    ethtool -K "$i" txvlan off 2>/dev/null || true
    ethtool -K "$i" rxvlan off 2>/dev/null || true
done

# Return-path table for the End.DT4 endpoint: decapped customer traffic
# resolves 10.2.0.0/24 out of table 100.
ip route replace 10.2.0.0/24 dev eth2 table 100

# --- static underlay routes ------------------------------------------------
ip -6 route replace 2001:db8:ff::1/128 via 2001:db8:2::2 dev eth1 \
    src 2001:db8:ff::2
ip -6 route replace fd00:100::/48 via 2001:db8:2::2 dev eth1

mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

mkdir -p /etc/vinbero
cp /vinbero.yml /etc/vinbero/vinbero.yaml

/usr/local/bin/vinberod --bgp-enabled -c /etc/vinbero/vinbero.yaml \
    > /var/log/vinberod.log 2>&1 &
echo $! > /var/run/vinberod.pid

for i in $(seq 1 30); do
    if /usr/local/bin/vbctl locator list >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# This node's SRv6 locator block.
/usr/local/bin/vbctl locator create \
    --name LOC2 \
    --prefix fd00:200::/48 \
    --block-len 32 --node-len 16 --function-len 16 --argument-len 64 \
    --behavior classic || true

/usr/local/bin/vbctl vrf create \
    --name vrf-cust \
    --table-id 100 \
    --enable-l3mdev-rule || true
if ! ip link show vrf-cust >/dev/null 2>&1; then
    echo "ERROR: failed to create VRF vrf-cust -- is the kernel 'vrf' module loaded on the host? (modprobe vrf)" >&2
    exit 1
fi

# The endpoint the advertised SID resolves to. Traffic the far end steers
# into fd00:200:0:1:: lands here, is decapped, and leaves towards ce-osaka.
/usr/local/bin/vbctl sid create \
    --trigger-prefix fd00:200:0:1::/128 \
    --action END_DT4 \
    --vrf-name vrf-cust || true

# --- the control-plane plugin ----------------------------------------------
# Config blob, in the plugin's own protobuf message (see the example's
# README for the field numbers):
#   1 behavior       0xFE01
#   3 prefix         10.2.0.0/24
#   4 RD             65100:200
#   6 advertise SID  fd00:200:0:1::
#   7 next hop       2001:db8:ff::2   (this node's loopback)
printf '\010\201\374\003\032\013\061\060\056\062\056\060\056\060\057\062\064\042\011\066\065\061\060\060\072\062\060\060\062\016\146\144\060\060\072\062\060\060\072\060\072\061\072\072\072\016\062\060\060\061\072\144\142\070\072\146\146\072\072\062' \
    > /tmp/plugin-config.bin

# Granted `advertise` only. It has no business writing forwarding state on
# this node, and a capability it was not granted is not a call that fails
# but a host function its module cannot reach.
/usr/local/bin/vbctl plugin cplane register \
    --name custom-behavior \
    --wasm /plugin.wasm \
    --config /tmp/plugin-config.bin \
    --behavior 0xFE01 \
    --family vpnv4 \
    --capability advertise || true

# Pre-resolve neighbours so the first packet is not queued behind NDP/ARP.
ping6 -c 1 -W 2 2001:db8:2::2 >/dev/null 2>&1 || true
ping -c 1 -W 2 10.2.0.10 >/dev/null 2>&1 || true

echo "[start.sh] pe-osaka (Vinbero, advertising plugin) ready"
