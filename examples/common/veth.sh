#!/bin/bash
# examples/common/veth.sh
# veth pair utility functions

# Create veth pair and move to namespaces
# Usage: create_veth_pair <veth1_name> <ns1> <veth2_name> <ns2>
create_veth_pair() {
    local veth1="$1"
    local ns1="$2"
    local veth2="$3"
    local ns2="$4"

    # Delete existing veth if any
    ip link del "$veth1" 2>/dev/null || true
    ip link del "$veth2" 2>/dev/null || true

    # Create veth pair
    ip link add "$veth1" type veth peer name "$veth2"

    # Move to namespaces
    ip link set "$veth1" netns "$ns1"
    ip link set "$veth2" netns "$ns2"

    # Bring up interfaces
    ip netns exec "$ns1" ip link set "$veth1" up
    ip netns exec "$ns2" ip link set "$veth2" up

    echo "Created veth pair: $veth1 ($ns1) <-> $veth2 ($ns2)"
}

# Configure veth with IP address (auto-detects IPv4/IPv6)
# Usage: configure_veth <namespace> <veth_name> <addr/prefix>
configure_veth() {
    local ns="$1"
    local veth="$2"
    local addr="$3"
    local ip_ver=""
    local proto="IPv4"

    # Auto-detect IPv6 by presence of colon
    if [[ "$addr" == *":"* ]]; then
        ip_ver="-6"
        proto="IPv6"

        # Disable DAD for faster setup on IPv6
        ip netns exec "$ns" sysctl -w "net.ipv6.conf.${veth}.accept_dad=0" > /dev/null 2>&1 || \
            echo "Warning: Could not disable DAD on $veth in $ns" >&2
    fi

    ip netns exec "$ns" ip $ip_ver addr add "$addr" dev "$veth"

    echo "Configured $veth in $ns with $addr ($proto)"
}

