#!/bin/bash
# examples/evpn-bum-scale-33/teardown.sh
# evpn-bum-scale with 33 PEs: 32 remote PEs per PE, every flood slot of the
# bridge domain in use.
export NUM_PES=33
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../evpn-bum-scale/teardown.sh" "$@"
