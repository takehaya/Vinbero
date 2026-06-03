#!/usr/bin/env bash
# Verify the SDK tarball is self-contained and produces a valid plugin.
# Layout assertions match docs/plan/plugin-sdk-3-tarball-distribution.md §2.
set -euo pipefail

TARBALL="${1:?usage: sdk_archive_verify.sh <tarball>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# 1. Extract to a fake /usr/local prefix. First assert the tarball matches the
#    contract install_vinbero.sh enforces on download — no path traversal, only
#    regular files/dirs, only include/ and share/ at the top level. The tarball
#    is built in-house, so this is a producer/installer contract test: it fails
#    CI if goreleaser ever ships something the installer would reject (e.g. the
#    binary-leak / collapsed-header regressions this packaging has already hit).
while IFS= read -r entry; do
  [ -n "$entry" ] || continue
  case "$entry" in
    /*|..|../*|*/../*|*/..) echo "unsafe path in SDK tarball: $entry" >&2; exit 1 ;;
  esac
done <<<"$(tar -tzf "$TARBALL")"
# Only regular files / directories — the installer rejects symlink/device/fifo.
while IFS= read -r line; do
  [ -n "$line" ] || continue
  case "$line" in
    -*|d*) ;;
    *) echo "non-regular entry in SDK tarball: $line" >&2; exit 1 ;;
  esac
done <<<"$(tar -tvzf "$TARBALL")"
mkdir -p "$WORK/prefix"
tar xzf "$TARBALL" -C "$WORK/prefix"

# Top level must be only include/ and share/ (catches a stray entry — e.g. a
# leaked binary — that the installer would also reject).
for entry in "$WORK"/prefix/*; do
  case "$(basename "$entry")" in
    include|share) ;;
    *) echo "unexpected top-level entry in SDK tarball: $(basename "$entry")" >&2; exit 1 ;;
  esac
done

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
)
for f in "${required[@]}"; do
  test -f "$f" || { echo "missing: $f" >&2; exit 1; }
done

# The tarball ships headers + docs only; examples are NOT bundled (they live in
# the repo under sdk/examples/). Confirm no stray example tree leaked in.
if [ -e "$WORK/prefix/share/vinbero-sdk/examples" ]; then
  echo "unexpected: examples/ should not be in the SDK tarball" >&2
  exit 1
fi

# 3. Build the repo's example plugins against ONLY the tarball's headers. The
#    sources come from the repo (sdk/examples/, not shipped in the tarball) but
#    every #include resolves against the extracted headers, so a wrong include
#    path or a missing/collapsed core header fails the build immediately.
#    MAKEFILE_PLUGIN points at the template shipped inside the tarball so the
#    in-tree relative include (../../c/Makefile.plugin) is bypassed.
EXAMPLES_SRC="${EXAMPLES_SRC:-$ROOT/sdk/examples}"
for ex in plugin-counter simple-acl plugin-counter-l2 plugin-custom-sh; do
  exdir="$WORK/examples/$ex"
  mkdir -p "$exdir"
  cp "$EXAMPLES_SRC/$ex/Makefile" "$EXAMPLES_SRC/$ex/plugin.c" "$exdir/"
  echo "[verify] building $ex (repo source, tarball headers)"
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
VBCTL="${VBCTL:-$ROOT/out/bin/vinbero}"
if [ ! -x "$VBCTL" ]; then
  echo "vinbero CLI not found at $VBCTL — run 'make build' first" >&2
  exit 1
fi
"$VBCTL" plugin validate \
  --prog "$WORK/examples/plugin-counter/plugin.o" \
  --program plugin_counter
"$VBCTL" plugin validate \
  --prog "$WORK/examples/simple-acl/plugin.o" \
  --program simple_acl
"$VBCTL" plugin validate \
  --prog "$WORK/examples/plugin-counter-l2/plugin.o" \
  --program plugin_counter_l2
"$VBCTL" plugin validate \
  --prog "$WORK/examples/plugin-custom-sh/plugin.o" \
  --program plugin_custom_sh

echo "[verify] OK"
