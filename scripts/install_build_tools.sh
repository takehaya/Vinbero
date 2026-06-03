#!/bin/bash
# Install build tools
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/libs/install_utils.sh"

# goreleaser は go.mod の go directive (現状 1.25.x) でビルドできる版に pin する。
# v2.14.0 以降は go 1.26 を要求し、GOTOOLCHAIN=local の環境で go install が失敗する。
# Go を上げるときはこの pin も合わせて見直す。
# install_tool は既存コマンドがあるとスキップするため、別経路で入った版に引きずられ
# ないよう、goreleaser は常に pinned 版を go install して version を保証する。
GORELEASER_VERSION="v2.13.0"
echo "Installing goreleaser ${GORELEASER_VERSION}..."
go install "github.com/goreleaser/goreleaser/v2@${GORELEASER_VERSION}"
echo "✓ goreleaser ${GORELEASER_VERSION} installed"

echo "✅ All build tools have been installed successfully!"
