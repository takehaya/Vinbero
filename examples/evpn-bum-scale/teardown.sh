#!/bin/bash
# examples/evpn-bum-scale/teardown.sh
set -u
for ns in $(ip netns list | awk '{print $1}' | grep '^ebs-'); do
    ip netns pids "$ns" 2> /dev/null | xargs -r kill 2> /dev/null || true
    ip netns del "$ns" 2> /dev/null || true
done
# The daemons' state files (their L2 headend circuits and bindings).
rm -f /tmp/vinbero_ebs_*_state.json
rm -rf /tmp/vinbero_ebs
exit 0
