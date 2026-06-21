#!/bin/bash
# Access-side MUP-GW (MUP Gateway), mup-gw, for the mup-2site-multivrf
# scenario.
#
# Hosts TWO VRFs on one node. Both access interfaces carry the same N3
# addressing (172.16.0.254/24) and both VPNs use the same TEID, so the F-TEID
# tuple {endpoint, TEID} is identical across them — the VRFs (the ingress AC
# membership classifying each access interface to a vrf_id) are what keep the
# two F-TEID entries apart, keyed by vrf_id.
#
#   eth1  gnb-a <-> mup-gw  N3-A   172.16.0.254/24
#   eth2  gnb-b <-> mup-gw  N3-B   172.16.0.254/24  (same addressing)
#   eth3  mup-gw <-> core   SRv6   2001:db8:1::1/64
#   lo    loopback 2001:db8:ff::a
set -u

ip addr add 172.16.0.254/24 dev eth1 2>/dev/null || true
ip link set eth1 up
ip addr add 172.16.0.254/24 dev eth2 2>/dev/null || true
ip link set eth2 up
ip -6 addr add 2001:db8:1::1/64 dev eth3 2>/dev/null || true
ip link set eth3 up
ip -6 addr add 2001:db8:ff::a/128 dev lo 2>/dev/null || true
ip link set lo up

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.seg6_enabled=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.eth3.seg6_enabled=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.eth1.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.eth2.rp_filter=0 >/dev/null 2>&1 || true
for i in eth1 eth2 eth3; do ethtool -K $i txvlan off 2>/dev/null || true; ethtool -K $i rxvlan off 2>/dev/null || true; done

# Underlay: mup-pe loopback + its direct-segment block, and the controller.
ip -6 route replace 2001:db8:ff::d/128 via 2001:db8:1::2 dev eth3 src 2001:db8:ff::a
ip -6 route replace 2001:db8:ff::c/128 via 2001:db8:1::2 dev eth3 src 2001:db8:ff::a
ip -6 route replace fd00:d::/48 via 2001:db8:1::2 dev eth3

mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
mkdir -p /etc/vinbero; cp /vinbero.yml /etc/vinbero/vinbero.yaml
/usr/local/bin/vinberod --bgp-enabled -c /etc/vinbero/vinbero.yaml > /var/log/vinberod.log 2>&1 &
echo $! > /var/run/vinberod.pid

for _ in $(seq 1 30); do /usr/local/bin/vbctl locator list >/dev/null 2>&1 && break; sleep 1; done

# Source locator = this gateway's SRv6 block (uplink encap source).
/usr/local/bin/vbctl locator create --name LOC1 --prefix fd00:a::/48 \
    --block-len 32 --node-len 16 --function-len 16 --argument-len 64 --behavior classic || true

# One VRF per VPN, created at runtime via the operator surface. The ingress AC
# ({interface} -> vrf_id) classifies WHICH packets belong to the VRF; adding
# the first AC allocates the VRF's vrf_id and enables the ingress front door.
# The access interfaces share N3 addressing, so the AC membership is the only
# thing separating the two F-TEID entries. No kernel VRF is needed on the GW.
/usr/local/bin/vbctl vrf ac-add --vrf vpn-a --interface eth1 || true
/usr/local/bin/vbctl vrf ac-add --vrf vpn-b --interface eth2 || true

# The BGP facet of each VRF: its mup_ipv4 import RT decides WHICH received
# T2STs install under the VRF's vrf_id. Binding the same vrf name attaches the
# policy to the VRF the AC already created (they share the vrf_id via Ensure).
/usr/local/bin/vbctl vrf-bgp bind --vrf vpn-a --rd 65100:1 \
    --rt mup_ipv4:100:6001:import || true
/usr/local/bin/vbctl vrf-bgp bind --vrf vpn-b --rd 65100:2 \
    --rt mup_ipv4:100:6002:import || true

# Pre-resolve the core next hop so bpf_fib_lookup on the redirect succeeds.
ping6 -c 1 -W 2 2001:db8:1::2 >/dev/null 2>&1 || true

echo "[start.sh] mup-gw (access MUP-GW) ready; VRFs and bindings:"
/usr/local/bin/vbctl vrf show || true
/usr/local/bin/vbctl vrf-bgp list || true
