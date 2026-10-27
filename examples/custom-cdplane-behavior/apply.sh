#!/usr/bin/env bash
# Thin lab wrapper: grants stay explicit and independent of the policy JSON.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

if (($# < 2 || $# > 3)); then
    echo "Usage: $0 pe1|pe2 POLICY.json [native|wasm]" >&2
    exit 2
fi
node=$1
policy=$2
backend=${3:-native}
[[ -r "$policy" ]] || { print_error "Cannot read policy: $policy"; exit 1; }
args=()
case "$backend" in
    native) args=(--native custom-cdplane-behavior) ;;
    wasm)
        [[ -s "$WASM" ]] || { print_error "Build first: make cplane-custom-cdplane-behavior"; exit 1; }
        args=(--wasm "$WASM")
        ;;
    *) print_error "Unknown backend: $backend (expected native or wasm)"; exit 2 ;;
esac

case "$node" in
    pe1)
        ctl "$PE1" plugin cplane register --name custom-cdplane-behavior "${args[@]}" \
            --config "$policy" --behavior 0xFE01 --family vpnv4 --tick-ms 1000 \
            --capability headend --headend-prefix 10.2.0.0/24
        ;;
    pe2)
        ctl "$PE2" plugin cplane register --name custom-cdplane-behavior "${args[@]}" \
            --config "$policy" --behavior 0xFE01 --family vpnv4 --tick-ms 1000 \
            --capability advertise --capability local_sid \
            --vrf vrf-cust --locator LOC2 --endpoint-slot 32
        ;;
    *) print_error "Unknown node: $node (expected pe1 or pe2)"; exit 2 ;;
esac
