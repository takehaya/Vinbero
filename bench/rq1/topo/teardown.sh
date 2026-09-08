#!/bin/bash
# bench/rq1/topo/teardown.sh
# Remove the RQ1 topology. Deleting the namespaces also detaches any XDP
# program still attached to their interfaces, which would otherwise block a
# later attach.

set -euo pipefail

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-rq1-}"
[[ "$TOPO_NS_PREFIX" =~ ^[a-zA-Z0-9-]{1,9}$ ]] || { echo "invalid namespace prefix" >&2; exit 1; }

namespaces="$(ip netns list)"
status=0
for suffix in src rt pea peb; do
    ns="${TOPO_NS_PREFIX}${suffix}"
    if awk '{print $1}' <<< "$namespaces" | grep -Fxq -- "$ns"; then
        if ! ip netns del "$ns"; then
            echo "could not delete namespace: $ns" >&2
            status=1
        fi
    fi
done
exit "$status"
