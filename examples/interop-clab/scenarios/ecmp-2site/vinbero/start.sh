#!/bin/bash
# Bring up the Vinbero PE (pe-tokyo) for the ecmp-2site scenario.
#
# Identical in structure to the l3vpn-2site start.sh, with the underlay
# routes doubled: this PE reaches TWO FRR PEs (loopbacks + locator
# blocks) through the core, learns the same customer prefix from both,
# and aggregates them into one ECMP group. See that scenario for the
# rationale of each step; only the ecmp-specific parts are annotated.
#
# Interfaces:
#   eth1  pe-tokyo <-> core      underlay 2001:db8:1::/64 (pe-tokyo = ::1)
#   eth2  pe-tokyo <-> ce-tokyo  customer 10.1.0.0/24     (pe-tokyo = .1)
#   lo    loopback 2001:db8:ff::1  (iBGP peering / SRv6 transport / probe source)

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

ethtool -K eth1 txvlan off 2>/dev/null || true
ethtool -K eth1 rxvlan off 2>/dev/null || true
ethtool -K eth2 txvlan off 2>/dev/null || true
ethtool -K eth2 rxvlan off 2>/dev/null || true

# --- return-path routing table for the End.DT4 endpoint --------------------
ip route replace 10.1.0.0/24 dev eth2 table 100

# --- static underlay routes ------------------------------------------------
# Both FRR PEs' loopbacks (iBGP peers, and the prober's echo targets)
# and locator blocks, all via the core.
ip -6 route replace 2001:db8:ff::2/128 via 2001:db8:1::2 dev eth1 \
    src 2001:db8:ff::1
ip -6 route replace 2001:db8:ff::3/128 via 2001:db8:1::2 dev eth1 \
    src 2001:db8:ff::1
ip -6 route replace fd00:200::/48 via 2001:db8:1::2 dev eth1
ip -6 route replace fd00:300::/48 via 2001:db8:1::2 dev eth1

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

# --- return-path End.DT4 endpoint ------------------------------------------
/usr/local/bin/vbctl sid create \
    --trigger-prefix fd00:100:0:1::/128 \
    --action END_DT4 \
    --vrf-name vrf-cust || true

# --- advertise the ce-tokyo customer subnet into the L3VPN -----------------
# Both FRR PEs import RT 65000:200, so both install the return route --
# whichever gateway ce-osaka uses can reach ce-tokyo.
/usr/local/bin/vbctl bgp advertise-vpn --family vpnv4 \
    --prefix 10.1.0.0/24 --rd 65100:200 --rts 65000:200 \
    --sid fd00:100:0:1:: --next-hop 2001:db8:ff::1 || true

# Pre-resolve neighbours for the XDP BPF FIB lookups.
ping6 -c 1 -W 2 2001:db8:1::2 >/dev/null 2>&1 || true
ping -c 1 -W 2 10.1.0.10 >/dev/null 2>&1 || true

echo "[start.sh] pe-tokyo (Vinbero) PE ready"
