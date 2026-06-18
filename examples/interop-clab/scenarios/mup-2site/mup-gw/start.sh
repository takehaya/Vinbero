#!/bin/bash
# Access-side MUP-GW (MUP Gateway), mup-gw, for the mup-2site scenario.
#
# Hosts the interwork segment (End.M.GTP4.E, downlink SRv6->GTP toward the gNB)
# locally, and applies the controller's T2ST as the uplink F-TEID + gate.
#
#   eth1  gNB <-> mup-gw  N3       172.16.0.254/24  (= the N3/UPF endpoint)
#   eth2  mup-gw <-> core SRv6     2001:db8:1::1/64
#   lo    loopback 2001:db8:ff::a
set -u

ip addr add 172.16.0.254/24 dev eth1 2>/dev/null || true
ip link set eth1 up
ip -6 addr add 2001:db8:1::1/64 dev eth2 2>/dev/null || true
ip link set eth2 up
ip -6 addr add 2001:db8:ff::a/128 dev lo 2>/dev/null || true
ip link set lo up

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.seg6_enabled=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.eth2.seg6_enabled=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.eth1.rp_filter=0 >/dev/null 2>&1 || true
for i in eth1 eth2; do ethtool -K $i txvlan off 2>/dev/null || true; ethtool -K $i rxvlan off 2>/dev/null || true; done

# Underlay: mup-pe loopback + its direct-segment block, and the controller, via core.
ip -6 route replace 2001:db8:ff::d/128 via 2001:db8:1::2 dev eth2 src 2001:db8:ff::a
ip -6 route replace 2001:db8:ff::c/128 via 2001:db8:1::2 dev eth2 src 2001:db8:ff::a
ip -6 route replace fd00:d::/48 via 2001:db8:1::2 dev eth2

mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
mkdir -p /etc/vinbero; cp /vinbero.yml /etc/vinbero/vinbero.yaml
/usr/local/bin/vinberod --bgp-enabled -c /etc/vinbero/vinbero.yaml > /var/log/vinberod.log 2>&1 &
echo $! > /var/run/vinberod.pid

for _ in $(seq 1 30); do /usr/local/bin/vbctl locator list >/dev/null 2>&1 && break; sleep 1; done

# Source locator = this gateway's SRv6 block (also the interwork segment block).
/usr/local/bin/vbctl locator create --name LOC1 --prefix fd00:a::/48 \
    --block-len 32 --node-len 16 --function-len 16 --argument-len 64 --behavior classic || true

# Interwork segment: End.M.GTP4.E. SRv6 packets to fd00:a::/56 are decapped and
# re-encapsulated as GTP-U toward the gNB, reading gNB/TEID/QFI from the SID's
# Args.Mob.Session at offset 7. /56 because bytes 7-15 carry the per-session args.
# --gtp-v4-src-position 64 is the RFC 9433 §6.6 receiver side: the GTP-U outer
# IPv4 source is extracted from the outer IPv6 source at bit 64, where mup-pe
# embeds the session's UPF N3 anchor right after its per-VRF
# mup_gtp4_source_prefix (fd00:d::/64 -- the position equals that prefix
# length). The static --gtp-v4-src-addr alternative remains for senders that
# do not embed.
/usr/local/bin/vbctl sid create \
    --trigger-prefix fd00:a::/56 --action END_M_GTP4_E \
    --gtp-v4-src-position 64 --args-offset 7 || true

# Originate this gateway's Interwork Segment Discovery route via MupService
# (a managed local table auto-advertised into SAFI 85): it hosts the
# End.M.GTP4.E interwork segment (SID fd00:a:0:1::) reachable for the gNB N3
# block. The controller's (SID-less) T1ST resolves its interwork SID from this
# ISD by gNB endpoint, so the SID is carried here, not on the T1ST.
# The RD is this gateway's own (per-advertiser, RFC 4364 §4.2), distinct from
# the controller's session RD 65100:1; VPN membership is the route target
# (100:2000, the downlink VPN shared with the T1ST), so the PE's resolution
# crosses RDs and is RT-scoped.
sleep 6
/usr/local/bin/vbctl mup create --route-type isd \
    --rd 65100:11 --prefix 172.16.0.0/24 \
    --route-targets 100:2000 --sid fd00:a:0:1:: --next-hop 2001:db8:ff::a || true
echo "[start.sh] mup-gw originated ISD; local MUP table:"
/usr/local/bin/vbctl mup list || true

# Pre-resolve neighbours so bpf_fib_lookup on the redirect path succeeds.
ping6 -c 1 -W 2 2001:db8:1::2 >/dev/null 2>&1 || true
ping -c 1 -W 2 172.16.0.1 >/dev/null 2>&1 || true

echo "[start.sh] mup-gw (access MUP-GW) ready; advertised ISD"
