#!/bin/bash
# Install build tools
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/libs/install_utils.sh"

# goreleaser は go.mod の go directive (現状 1.25.x) でビルドできる版に pin する。
# v2.14.0 以降は go 1.26 を要求し、GOTOOLCHAIN=local の環境で go install が失敗する。
# Go を上げるときはこの pin も合わせて見直す。
# install_tool は既存コマンドがあるとスキップするため、別経路で入った版に引きずられ
# ないよう、goreleaser は常に pinned 版を go install で入れ直す。
GORELEASER_VERSION="v2.13.0"
echo "Installing goreleaser ${GORELEASER_VERSION}..."
go install "github.com/goreleaser/goreleaser/v2@${GORELEASER_VERSION}"

# go install の配置先 (GOBIN もしくは GOPATH/bin) を直接見て実行できるか検証する。
# PATH 設定に依存せず install の成否を確認するため。
gobin="$(go env GOBIN)"
if [ -z "$gobin" ]; then
  # GOPATH は : 区切りで複数返ることがある。go install は先頭要素の bin に置く。
  gopath="$(go env GOPATH)"
  gobin="${gopath%%:*}/bin"
fi
# 先頭の ~ は変数展開では $HOME に展開されないため、明示的に展開してパスを確定する。
case "$gobin" in
  "~") gobin="$HOME" ;;
  "~/"*) gobin="$HOME/${gobin#\~/}" ;;
esac
if ! "${gobin}/goreleaser" --version >/dev/null 2>&1; then
  echo "✗ goreleaser is not executable at ${gobin}/goreleaser after install" >&2
  exit 1
fi
echo "✓ goreleaser ${GORELEASER_VERSION} installed at ${gobin}/goreleaser"
# 実際に実行される goreleaser は PATH の優先順位で決まる。make goreleaser 等で
# pinned 版を使うため、PATH 解決結果が ${gobin}/goreleaser と一致するか確認する。
resolved="$(command -v goreleaser 2>/dev/null || true)"
if [ -z "$resolved" ]; then
  echo "note: ${gobin} is not on PATH; add it (e.g. export PATH=\"${gobin}:\$PATH\") to use 'make goreleaser'." >&2
elif [ "$resolved" != "${gobin}/goreleaser" ]; then
  echo "note: 'goreleaser' on PATH resolves to ${resolved}, not the pinned ${gobin}/goreleaser; PATH order may run a different version." >&2
fi

echo "✅ All build tools have been installed successfully!"
