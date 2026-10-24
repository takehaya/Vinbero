#!/usr/bin/env bash
# Read-only, best-effort snapshots before route-withdrawal checks change state.
set -u

run() {
    printf '\n[diagnostics]'
    printf ' %q' "$@"
    printf '\n'
    timeout 5s "$@" 2>&1
    printf '[diagnostics] exit=%s\n' "$?"
    return 0
}

run date -u +%FT%TZ
run uname -a
for site in pe1 pe2 pe3; do
    node="clab-evpn-multihoming-$site"
    run docker inspect --format 'image={{.Image}} state={{.State.Status}} pid={{.State.Pid}}' "$node"
    run docker exec "$node" sha256sum /usr/local/bin/vinberod /usr/local/bin/vinbero
    run docker exec "$node" tail -n 1000 /var/log/vinberod.log
    run docker exec "$node" vbctl --json fdb list
    run docker exec "$node" vbctl --json bd-peer list --bd-id 100
    run docker exec "$node" vbctl --json vrf show
    run docker exec "$node" vbctl --json vrf-bgp list
    run docker exec "$node" vbctl --json es list
    run docker exec "$node" vbctl --json hl2 list
    run docker exec "$node" vbctl --json headend-group list
    run docker exec "$node" vbctl --json sid list
    run docker exec "$node" vbctl --json stats show
    run docker exec "$node" vbctl --json stats slot show --all
    run docker exec "$node" ip -d link show
    run docker exec "$node" ip address show
    run docker exec "$node" ip -6 route show table all
    run docker exec "$node" ip neigh show
    run docker exec "$node" ip -6 neigh show
    run docker exec "$node" bridge fdb show
    run docker exec "$node" ss -ntp
done

for site in ce-mh ce-remote core; do
    node="clab-evpn-multihoming-$site"
    run docker inspect --format 'image={{.Image}} state={{.State.Status}} pid={{.State.Pid}}' "$node"
    run docker exec "$node" ip -d link show
    run docker exec "$node" ip address show
    run docker exec "$node" ip route show
    run docker exec "$node" ip -6 route show
    run docker exec "$node" ip neigh show
    run docker exec "$node" ip -6 neigh show
    run docker exec "$node" bridge fdb show
done

# Disabled counters and CLI projections are not raw BPF map or BGP RIB dumps.
echo '[diagnostics] snapshot complete (command failures retained above)'
exit 0
