#!/bin/bash
# pe-tokyo: the PE whose plugin RECEIVES the custom behavior.
#
# The control-plane plugin here is granted only `headend`. It claims the
# behavior codepoint 0xFE01, which means routes carrying it are withheld
# from vinbero's own appliers: they would read an unrecognized codepoint
# as an ordinary service SID and install an entry with the wrong meaning.
# The plugin reads the route instead and declares the headend entry that
# steers the customer prefix into the advertised SID.
#
# So the forwarding state for 10.2.0.0/24 on this node exists only
# because a plugin put it there. That is what the scenario tests.
#
# Interfaces:
#   eth1  pe-tokyo <-> core     underlay 2001:db8:1::/64  (pe-tokyo = ::1)
#   eth2  pe-tokyo <-> ce-tokyo customer 10.1.0.0/24      (pe-tokyo = .1)
#   lo    loopback 2001:db8:ff::1

setknob() {
    sysctl -w "$1=$2" >/dev/null 2>&1 || true
}

# --- interface addressing --------------------------------------------------
ip -6 addr add 2001:db8:1::1/64 dev eth1 2>/dev/null || true
ip link set eth1 up
ip addr add 10.1.0.1/24 dev eth2 2>/dev/null || true
ip link set eth2 up
ip -6 addr add 2001:db8:ff::1/128 dev lo 2>/dev/null || true
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

for i in eth1 eth2; do
    ethtool -K "$i" txvlan off 2>/dev/null || true
    ethtool -K "$i" rxvlan off 2>/dev/null || true
done

# Return-path table for this node's own End.DT4 endpoint.
ip route replace 10.1.0.0/24 dev eth2 table 100

# --- static underlay routes ------------------------------------------------
ip -6 route replace 2001:db8:ff::2/128 via 2001:db8:1::2 dev eth1 \
    src 2001:db8:ff::1
ip -6 route replace fd00:200::/48 via 2001:db8:1::2 dev eth1

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

/usr/local/bin/vbctl locator create \
    --name LOC1 \
    --prefix fd00:100::/48 \
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

# This node's own service SID, for the return direction. The far end
# reaches ce-tokyo through it over an ordinary L3VPN route -- the return
# path deliberately does NOT involve the plugin, so a failure in one
# direction points at the plugin and a failure in both points at the lab.
/usr/local/bin/vbctl sid create \
    --trigger-prefix fd00:100:0:1::/128 \
    --action END_DT4 \
    --vrf-name vrf-cust || true

/usr/local/bin/vbctl bgp advertise-vpn --family vpnv4 \
    --prefix 10.1.0.0/24 --rd 65100:100 --rts 65000:200 \
    --sid fd00:100:0:1:: --next-hop 2001:db8:ff::1 || true

# --- the control-plane plugin ----------------------------------------------
# Config blob: field 1 is the behavior codepoint to claim (0xFE01). This
# end originates nothing, so the locator, prefix and SID fields are absent
# and the plugin runs receive-only.
printf '\010\201\374\003' > /tmp/plugin-config.bin

# Granted `headend` only: it declares forwarding state and nothing else.
# It cannot originate a route or allocate a SID, and the host functions
# for those are not linked into its module at all.
#
# The scope says where that capability may be exercised. The headend maps
# are keyed on the destination prefix alone, so without it the plugin could
# install a longer prefix over anything this node forwards -- including the
# operator's own VPN traffic, which wins on longest match without ever
# touching the entry it shadows. 10.2.0.0/16 covers the far end's customer
# subnet and nothing else here.
/usr/local/bin/vbctl plugin cplane register \
    --name custom-behavior \
    --wasm /plugin.wasm \
    --config /tmp/plugin-config.bin \
    --behavior 0xFE01 \
    --family vpnv4 --tick-ms 1000 \
    --capability headend \
    --headend-prefix 10.2.0.0/16 || true

ping6 -c 1 -W 2 2001:db8:1::2 >/dev/null 2>&1 || true
ping -c 1 -W 2 10.1.0.10 >/dev/null 2>&1 || true

echo "[start.sh] pe-tokyo (Vinbero, receiving plugin) ready"
