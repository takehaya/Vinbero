#!/bin/bash
# bench/rq1/topo/teardown.sh
# Remove the RQ1 topology. Deleting the namespaces also detaches any XDP
# program still attached to their interfaces, which would otherwise block a
# later attach.

set -euo pipefail

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-rq1-}"
[[ "$TOPO_NS_PREFIX" =~ ^[a-zA-Z0-9-]{1,9}$ ]] || { echo "invalid namespace prefix" >&2; exit 1; }

namespaces="$(ip netns list)"
owned=()
if [[ -n "${TOPOLOGY_OWNED_FILE:-}" ]]; then
    # A failed setup may own only part of the topology. Never broaden that
    # ownership to other namespaces just because they share a prefix.
    if [[ ! -f "$TOPOLOGY_OWNED_FILE" ]]; then exit 0; fi
    mapfile -t owned < "$TOPOLOGY_OWNED_FILE"
else
    for suffix in src rt pea peb; do owned+=("${TOPO_NS_PREFIX}${suffix}"); done
fi
status=0
for ns in "${owned[@]}"; do
    case "$ns" in
        "${TOPO_NS_PREFIX}src"|"${TOPO_NS_PREFIX}rt"|"${TOPO_NS_PREFIX}pea"|"${TOPO_NS_PREFIX}peb") ;;
        *) echo "invalid owned namespace: $ns" >&2; status=1; continue ;;
    esac
    if awk '{print $1}' <<< "$namespaces" | grep -Fxq -- "$ns"; then
        if ! ip netns del "$ns"; then
            echo "could not delete namespace: $ns" >&2
            status=1
        fi
    fi
done
exit "$status"
