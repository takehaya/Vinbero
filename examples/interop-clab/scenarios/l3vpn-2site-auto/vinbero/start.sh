#!/bin/bash
# Bring up the Vinbero PE (pe-tokyo) for the auto-advertise variant.
#
# Unlike l3vpn-2site, this scenario does NOT call `vbctl sid create` or
# `vbctl bgp advertise-vpn`. The locator (LOC1), the vrf-cust binding, and the
# auto_advertise toggle are declared in vinbero.yml; the exporter mints the
# End.DT4/DT6 service SID and advertises the VRF-local customer prefix on its
# own once it sees the route in the vrf-cust table.
#
# Interfaces:
#   eth1  pe-tokyo <-> core   underlay 2001:db8:1::/64  (pe-tokyo = ::1)
#   eth2  pe-tokyo <-> ce-tokyo  customer 10.1.0.0/24   (pe-tokyo = .1)
#   lo    loopback 2001:db8:ff::1  (iBGP peering / SRv6 transport)

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

# --- SRv6 dataplane knobs (namespace-scoped, best-effort) ------------------
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

# --- customer VRF (table 100): decap endpoint + auto-advertise source ------
# The auto-advertise exporter resolves vrf-cust to its table id and watches
# that table. The VRF must exist before vinberod starts so EnableVRF can
# resolve it at startup.
if ! ip link show vrf-cust >/dev/null 2>&1; then
    ip link add vrf-cust type vrf table 100
fi
if ! ip link show vrf-cust >/dev/null 2>&1; then
    echo "ERROR: failed to create VRF vrf-cust -- is the kernel 'vrf' module loaded on the host? (modprobe vrf)" >&2
    exit 1
fi
ip link set vrf-cust up
ip rule add l3mdev protocol kernel prio 1000 2>/dev/null || true
# The local customer subnet, in table 100. `proto static` is required: the
# route watcher's redistribute=[static] allowlist only forwards RTPROT_STATIC;
# a bare `ip route` would be RTPROT_BOOT, which is intentionally excluded to
# avoid leaking casually-added routes into the VPN. The End.DT4 BPF FIB lookup
# (keyed by the vrf-cust ifindex) also resolves it for the decap return path.
ip route replace 10.1.0.0/24 dev eth2 table 100 proto static

# --- static underlay routes ------------------------------------------------
# `src 2001:db8:ff::1` forces the outbound iBGP TCP connection to source from
# our loopback so the loopback-to-loopback session establishes.
ip -6 route replace 2001:db8:ff::2/128 via 2001:db8:1::2 dev eth1 \
    src 2001:db8:ff::1
ip -6 route replace fd00:200::/48 via 2001:db8:1::2 dev eth1

# BPF filesystem for pinned maps / XDP links.
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

mkdir -p /etc/vinbero
cp /vinbero.yml /etc/vinbero/vinbero.yaml

# Start the daemon. LOC1, the vrf-cust binding, and auto_advertise are all in
# vinbero.yml, so no vbctl calls are needed: the exporter mints the End.DT4/DT6
# SID and advertises 10.1.0.0/24 by itself.
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

# Bind vrf-cust to its BGP route-target policy. vpnv4 + vpnv6 are listed
# explicitly so the exporter advertises VPNv4/VPNv6 of 10.1.0.0/24 with RT
# 65000:200 and the applier accepts FRR's 10.2.0.0/24 under the same RT.
# `--rt` and `--rd` together replace the deleted YAML vrf_bindings entry.
/usr/local/bin/vbctl vrf-bgp bind \
    --vrf vrf-cust \
    --rd 65100:200 \
    --rt vpnv4:65000:200:both \
    --rt vpnv6:65000:200:both \
    --default-locator LOC1 \
    --redistribute static || true

# Pre-resolve neighbours so the first XDP BPF FIB lookups never hit
# BPF_FIB_LKUP_RET_NO_NEIGH on the first packet.
ping6 -c 1 -W 2 2001:db8:1::2 >/dev/null 2>&1 || true
ping -c 1 -W 2 10.1.0.10 >/dev/null 2>&1 || true

echo "[start.sh] pe-tokyo (Vinbero, auto-advertise) PE ready"
