#!/bin/bash
# examples/common/netns.sh
# Network Namespace utility functions

# Create a network namespace
# Usage: create_netns <name>
create_netns() {
    local name="$1"
    if [ -z "$name" ]; then
        echo "Error: namespace name required"
        return 1
    fi

    # Delete if exists (for idempotency)
    ip netns del "$name" 2>/dev/null || true

    ip netns add "$name"

    # Enable loopback
    ip netns exec "$name" ip link set lo up

    echo "Created namespace: $name"
}

# Delete a network namespace
# Usage: delete_netns <name>
delete_netns() {
    local name="$1"
    if [ -z "$name" ]; then
        echo "Error: namespace name required"
        return 1
    fi

    ip netns del "$name" 2>/dev/null || true
    echo "Deleted namespace: $name"
}

# Set sysctl parameter in namespace (with unified output handling)
# Usage: ns_sysctl <namespace> <key> <value>
ns_sysctl() {
    local ns="$1"
    local key="$2"
    local value="$3"
    ip netns exec "$ns" sysctl -w "${key}=${value}" > /dev/null
}

# Enable SRv6 in namespace
# Usage: ns_enable_srv6 <namespace>
ns_enable_srv6() {
    local ns="$1"
    ns_sysctl "$ns" net.ipv6.conf.all.seg6_enabled 1
    ns_sysctl "$ns" net.ipv6.conf.default.seg6_enabled 1
}
