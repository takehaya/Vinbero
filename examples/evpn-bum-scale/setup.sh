#!/bin/bash
# examples/evpn-bum-scale/setup.sh
# NUM_PES PEs (default 9) of one EVPN bridge domain on one core segment.
#
#   ebs-ceN (host, 10.100.0.N) -- ebs-peN (Vinbero PE) -- ebs-core (bridge)
#
# Each PE's uplink ebs-uN has 2001:db8:e0::N on the shared core segment and
# routes every other PE's locator fd00:0:M::/48 to that PE. The core bridge
# has no XDP program, so captures on its ports see what each PE receives.

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"
check_root

NUM_PES="${NUM_PES:-9}"
hex() { printf '%x' "$1"; }

print_info "Creating the core segment..."
run ip netns add ebs-core
ip -n ebs-core link set lo up
run ip -n ebs-core link add ebs-cbr type bridge
ip -n ebs-core link set ebs-cbr up

for i in $(seq 1 "$NUM_PES"); do
    pe=ebs-pe$i
    ce=ebs-ce$i
    print_info "Creating PE $i and its host..."
    run ip netns add "$pe"
    run ip netns add "$ce"
    ip -n "$pe" link set lo up
    ip -n "$ce" link set lo up
    ip netns exec "$ce" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
    ip netns exec "$pe" sysctl -qw net.ipv6.conf.all.forwarding=1
    ip netns exec "$pe" sysctl -qw net.ipv6.conf.all.seg6_enabled=1

    run ip link add "ebs-u$i" netns "$pe" type veth peer name "ebs-c$i" netns ebs-core
    ip -n ebs-core link set "ebs-c$i" master ebs-cbr
    ip -n ebs-core link set "ebs-c$i" up
    ip netns exec "$pe" sysctl -qw "net.ipv6.conf.ebs-u$i.seg6_enabled=1"
    ip -n "$pe" -6 addr add "2001:db8:e0::$(hex "$i")/64" dev "ebs-u$i" nodad
    ip -n "$pe" link set "ebs-u$i" up

    run ip link add "ebs-a$i" netns "$pe" type veth peer name "ebs-h$i" netns "$ce"
    ip netns exec "$pe" sysctl -qw "net.ipv6.conf.ebs-a$i.disable_ipv6=1"
    ip -n "$ce" link set "ebs-h$i" address "$(printf '02:00:00:00:%02x:01' "$i")"
    ip -n "$ce" addr add "10.100.0.$i/24" dev "ebs-h$i"
    ip -n "$ce" link set "ebs-h$i" up
    ip -n "$pe" link set "ebs-a$i" up

    # The data plane reads the VLAN tag from the packet.
    for dev in "ebs-u$i" "ebs-a$i"; do
        ip netns exec "$pe" ethtool -K "$dev" txvlan off rxvlan off > /dev/null 2>&1 || true
    done
    ip netns exec "$ce" ethtool -K "ebs-h$i" txvlan off rxvlan off > /dev/null 2>&1 || true
    ip netns exec ebs-core ethtool -K "ebs-c$i" txvlan off rxvlan off > /dev/null 2>&1 || true
done

print_info "Routing every PE's locator..."
for i in $(seq 1 "$NUM_PES"); do
    for j in $(seq 1 "$NUM_PES"); do
        [ "$i" = "$j" ] && continue
        ip -n "ebs-pe$i" -6 route add "fd00:0:$(hex "$j")::/48" via "2001:db8:e0::$(hex "$j")" dev "ebs-u$i"
    done
done

print_success "evpn-bum-scale topology with $NUM_PES PEs is ready"
