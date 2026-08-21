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

# Enslave the customer interface to vrf-cust. This is what makes the decap
# genuinely VRF-scoped: eth2's connected 10.2.0.0/24 route moves out of the
# main table and into table 100, so a plugin-dispatched End.DT4 that fell
# back to the main table (the old behavior) would now find nothing and drop.
# Only the host-owned grant that names vrf-cust resolves the return route.
ip link set eth2 master vrf-cust
# Re-assert the address and route in case enslaving flushed them, and keep
# eth2 up.
ip addr add 10.2.0.1/24 dev eth2 2>/dev/null || true
ip link set eth2 up
ip route replace 10.2.0.0/24 dev eth2 table 100

# The eBPF half of the custom behavior, in endpoint slot 32. The
# control-plane plugin allocates a SID pointing at this slot, so traffic
# the far end steers into that SID lands in this program, which counts it
# and hands it to End.DT4 to be decapped towards ce-osaka.
#
# The operator provisions no SID here: the plugin asks for one and the
# daemon picks the address. That is the half of the mechanism the lab did
# not previously exercise.
/usr/local/bin/vbctl plugin register \
    --type endpoint --index 32 \
    --prog /plugin.o --program plugin_custom_behavior || true

# The VRF the plugin originates into. It names the VRF and nothing else:
# the route distinguisher and the route targets come from this binding,
# because the route targets are what decide which VRF a peer imports the
# route into. A plugin able to spell them could put a route in a VPN it was
# never given.
#
# The import RT has to be here too. Once any binding declares a family,
# the built-in applier stops default-allowing received routes of it and
# requires an RT some VRF imports; binding this VRF for export alone would
# therefore drop the far end's 10.1.0.0/24 on the floor.
/usr/local/bin/vbctl vrf-bgp bind \
    --vrf vrf-cust \
    --rd 65100:200 \
    --export-rts 65000:200 \
    --import-rts 65000:200 || true

# --- the control-plane plugin ----------------------------------------------
# Config blob, in the plugin's own protobuf message (see the example's
# README for the field numbers):
#   1 behavior       0xFE01
#   2 locator        LOC2             (allocate a SID from this block)
#   3 prefix         10.2.0.0/24
#   4 VRF            vrf-cust
#   5 slot           32               (its own eBPF half, registered above)
#   7 next hop       2001:db8:ff::2   (this node's loopback)
#   8 decap VRF      vrf-cust         (where its End.DT4 handoff decaps)
#
# No field 6: the plugin allocates its SID rather than advertising one an
# operator provisioned. That is what makes this the whole loop -- the
# address in the SID TLV on the wire is one the daemon handed the plugin.
#
# Field 8's wire bytes, so the blob can be checked without decoding by hand:
# tag \102 = (field 8 << 3) | wire-type 2 (length-delimited), \010 = length 8,
# then "vrf-cust" (\166\162\146\055\143\165\163\164). The same eight name bytes
# appear after field 4's tag \042 above.
#
# Field 8 is the return direction: the eBPF half hands decapsulated traffic
# to a built-in End.DT4, and naming the VRF here makes the host record a
# grant so that decap lands in vrf-cust's table rather than dropping.
printf '\010\201\374\003\022\004\114\117\103\062\032\013\061\060\056\062\056\060\056\060\057\062\064\042\010\166\162\146\055\143\165\163\164\050\040\072\016\062\060\060\061\072\144\142\070\072\146\146\072\072\062\102\010\166\162\146\055\143\165\163\164' \
    > /tmp/plugin-config.bin

# Granted `advertise` and `local_sid`, and no more. The capability says
# what it may do; the scope says where: it may originate only into
# vrf-cust, may allocate only from LOC2, and may point a SID only at slot
# 32, which is the one its own eBPF half occupies. Pointing at another
# plugin's slot would have that plugin read this one's aux bytes under a
# layout that does not describe them.
#
# It still cannot write forwarding state on this node: `headend` was not
# granted, and a capability it was not granted is not a call that fails but
# a host function its module cannot reach.
/usr/local/bin/vbctl plugin cplane register \
    --name custom-behavior \
    --wasm /plugin.wasm \
    --config /tmp/plugin-config.bin \
    --behavior 0xFE01 \
    --family vpnv4 \
    --capability advertise --capability local_sid \
    --vrf vrf-cust --locator LOC2 --endpoint-slot 32 || true

# Pre-resolve neighbours so the first packet is not queued behind NDP/ARP.
# The customer neighbour lives in vrf-cust now that eth2 is enslaved, so the
# warm-up ping has to resolve in that table rather than the main one.
ping6 -c 1 -W 2 2001:db8:2::2 >/dev/null 2>&1 || true
ip vrf exec vrf-cust ping -c 1 -W 2 10.2.0.10 >/dev/null 2>&1 || true

echo "[start.sh] pe-osaka (Vinbero, advertising plugin) ready"
