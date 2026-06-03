#!/usr/bin/env bash
# Stage the plugin SDK tree (headers + docs) into <dest>.
#
# This is the single source of truth for the SDK tarball contents. Both
# `make sdk-archive` (used by CI's SDK Archive Verify) and the goreleaser
# release archive stage from here, so the verified tarball and the released
# tarball can never drift apart.
#
# Resulting layout mirrors what gets extracted to /usr/local:
#   <dest>/include/vinbero/   public ABI headers + Makefile.plugin
#   <dest>/include/core/      internal headers the public ones #include
#   <dest>/share/vinbero-sdk/ README + LICENSE
set -euo pipefail

DEST="${1:?usage: stage_sdk.sh <dest-dir>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Guard the rm -rf below against obviously catastrophic destinations. Strip
# trailing slashes first so "/", "$HOME/" etc. can't slip past the match.
norm="$DEST"
while [ -n "$norm" ] && [ "$norm" != "${norm%/}" ]; do norm="${norm%/}"; done
[ -n "$norm" ] || norm="/"
case "$norm" in
  /|.|..|"$HOME") echo "stage_sdk.sh: refusing to wipe '$DEST'" >&2; exit 1 ;;
esac

rm -rf "$DEST"
install -d "$DEST/include/vinbero" "$DEST/include/core" "$DEST/share/vinbero-sdk"

# Public ABI headers + the one-liner plugin build template.
install -m 644 "$ROOT"/sdk/c/include/vinbero/*.h "$DEST/include/vinbero/"
install -m 644 "$ROOT/sdk/c/Makefile.plugin" "$DEST/include/vinbero/Makefile.plugin"

# Internal headers that the public ones #include via "core/...". Shipped
# wholesale on purpose: the public headers pull a transitive subset, and a
# glob avoids a hand-kept list that silently breaks plugin builds the moment a
# public header starts depending on another core header.
install -m 644 "$ROOT"/src/core/*.h "$DEST/include/core/"

# Static docs under share/ (FHS). Examples are intentionally NOT shipped: they
# live in the repo under sdk/examples/ and are linked from the SDK README.
install -m 644 "$ROOT/sdk/README.md" "$DEST/share/vinbero-sdk/README.md"
install -m 644 "$ROOT/LICENSE" "$DEST/share/vinbero-sdk/LICENSE"
