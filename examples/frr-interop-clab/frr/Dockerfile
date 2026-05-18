# FRR image for the interop lab's remote PE.
#
# FRR's SRv6 L3VPN configuration syntax is version-dependent, so the
# base tag is PINNED. 10.2.x carries stable `segment-routing srv6` +
# per-VRF `sid vpn per-vrf export` support, which is what frr.conf below
# relies on. Bump the tag only together with a frr.conf review.
FROM quay.io/frrouting/frr:10.2.1

# tcpdump for data-plane debugging; jq so test.sh can parse vtysh JSON
# from inside the container if needed.
RUN apk update \
 && apk add --no-cache tcpdump jq iproute2

# Integrated vtysh config: a single frr.conf drives every daemon.
RUN touch /etc/frr/vtysh.conf \
 && echo "service integrated-vtysh-config" >> /etc/frr/vtysh.conf \
 && mkdir -p /var/log/frr \
 && touch /var/log/frr/frr.log \
 && chmod 766 /var/log/frr/frr.log
