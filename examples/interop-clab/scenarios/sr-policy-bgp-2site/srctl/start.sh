#!/bin/bash
# Bring up srctl, the Vinbero SR Policy controller, inside the containerlab
# node. srctl has no data-plane role: it runs the in-process BGP speaker and
# advertises one SR Policy (SAFI 73) to pe-tokyo over the direct eth1 link.
# pe-tokyo receives it (origin BGP) and steers FRR's color-100 route onto it.
#
# Interfaces:
#   eth1  srctl <-> pe-tokyo   SR Policy control link 2001:db8:cc::/64 (= ::2)

setknob() {
    sysctl -w "$1=$2" >/dev/null 2>&1 || true
}

# eth1 carries the SAFI 73 iBGP session to pe-tokyo (2001:db8:cc::1).
ip -6 addr add 2001:db8:cc::2/64 dev eth1 2>/dev/null || true
ip link set eth1 up

setknob net.ipv6.conf.all.forwarding 1
setknob net.ipv6.conf.all.seg6_enabled 1

# generic XDP: drop VLAN offload so it matches the other Vinbero nodes.
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

# Advertise the SR Policy pe-tokyo will receive and steer onto. The endpoint
# equals the color route's IPv6 next hop on the PE (FRR's loopback); the
# transport segment is FRR's End SID; the next hop is our link address.
# gobgp accepts the path immediately and sends it once the session is up, so
# advertising here (before ESTABLISHED) is safe.
/usr/local/bin/vbctl bgp advertise-sr-policy \
    --color 100 \
    --endpoint 2001:db8:ff::2 \
    --segments fd00:200:0:ee::1 \
    --distinguisher 1 \
    --next-hop 2001:db8:cc::2 || true

echo "[start.sh] srctl (Vinbero SR Policy controller) ready"
