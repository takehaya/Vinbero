#!/usr/bin/env bash
# Verify the SDK tarball is self-contained and produces a valid plugin.
# Layout assertions match docs/plan/plugin-sdk-3-tarball-distribution.md §2.
set -euo pipefail

TARBALL="${1:?usage: sdk_archive_verify.sh <tarball>}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# 1. Extract tarball to a fake /usr/local prefix.
mkdir -p "$WORK/prefix"
tar xzf "$TARBALL" -C "$WORK/prefix"

# 2. Confirm the expected files landed at the documented paths.
required=(
  "$WORK/prefix/include/vinbero/plugin.h"
  "$WORK/prefix/include/vinbero/maps.h"
  "$WORK/prefix/include/vinbero/types.h"
  "$WORK/prefix/include/vinbero/helpers.h"
  "$WORK/prefix/include/vinbero/headend_l2_helpers.h"
  "$WORK/prefix/include/vinbero/Makefile.plugin"
  "$WORK/prefix/include/core/xdp_tailcall.h"
  "$WORK/prefix/include/core/xdp_prog.h"
  "$WORK/prefix/include/core/xdp_map.h"
  "$WORK/prefix/include/core/xdp_stats.h"
  "$WORK/prefix/include/core/srv6.h"
  "$WORK/prefix/share/vinbero-sdk/README.md"
  "$WORK/prefix/share/vinbero-sdk/LICENSE"
  "$WORK/prefix/share/vinbero-sdk/examples/plugin-counter/Makefile"
  "$WORK/prefix/share/vinbero-sdk/examples/plugin-counter/plugin.c"
  "$WORK/prefix/share/vinbero-sdk/examples/simple-acl/Makefile"
  "$WORK/prefix/share/vinbero-sdk/examples/simple-acl/plugin.c"
  "$WORK/prefix/share/vinbero-sdk/examples/plugin-counter-l2/Makefile"
  "$WORK/prefix/share/vinbero-sdk/examples/plugin-counter-l2/plugin.c"
  "$WORK/prefix/share/vinbero-sdk/examples/plugin-custom-sh/Makefile"
  "$WORK/prefix/share/vinbero-sdk/examples/plugin-custom-sh/plugin.c"
)
for f in "${required[@]}"; do
  test -f "$f" || { echo "missing: $f" >&2; exit 1; }
done

# 3. Build each example using only headers from the tarball; this fails
#    immediately if a #include path is wrong or a header is missing.
#    MAKEFILE_PLUGIN points at the template shipped inside the tarball
#    so the in-tree relative include (../../c/Makefile.plugin) is bypassed.
for ex in plugin-counter simple-acl plugin-counter-l2 plugin-custom-sh; do
  exdir="$WORK/prefix/share/vinbero-sdk/examples/$ex"
  echo "[verify] building $ex"
  make -C "$exdir" \
    VINBERO_SDK_ROOT="$WORK/prefix/include" \
    VINBERO_CORE_ROOT="$WORK/prefix/include" \
    MAKEFILE_PLUGIN="$WORK/prefix/include/vinbero/Makefile.plugin" \
    BPF_CLANG="${BPF_CLANG:-clang}"
done

# 4. Validate the plugin contract using the in-tree CLI. This catches any
#    regressions in the tailcall_epilogue / forbidden-helper rules.
#    Note: the binary is named `vinbero` in this repo (not `vbctl`); the
#    `plugin validate` subcommand is provided by cmd/vinbero.
VBCTL="${VBCTL:-./out/bin/vinbero}"
if [ ! -x "$VBCTL" ]; then
  echo "vinbero CLI not found at $VBCTL — run 'make build' first" >&2
  exit 1
fi
"$VBCTL" plugin validate \
  --prog "$WORK/prefix/share/vinbero-sdk/examples/plugin-counter/plugin.o" \
  --program plugin_counter
"$VBCTL" plugin validate \
  --prog "$WORK/prefix/share/vinbero-sdk/examples/simple-acl/plugin.o" \
  --program simple_acl
"$VBCTL" plugin validate \
  --prog "$WORK/prefix/share/vinbero-sdk/examples/plugin-counter-l2/plugin.o" \
  --program plugin_counter_l2
"$VBCTL" plugin validate \
  --prog "$WORK/prefix/share/vinbero-sdk/examples/plugin-custom-sh/plugin.o" \
  --program plugin_custom_sh

echo "[verify] OK"
