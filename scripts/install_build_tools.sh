#!/bin/bash
# Install build tools
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/libs/install_utils.sh"

# goreleaser は go.mod の go directive (現状 1.25.x) でビルドできる版に pin する。
# v2.14.0 以降は go 1.26 を要求し、GOTOOLCHAIN=local の環境で go install が失敗する。
# Go を上げるときはこの pin も合わせて見直す。
install_tool "goreleaser" "go install github.com/goreleaser/goreleaser/v2@v2.13.0"

echo "✅ All build tools have been installed successfully!"
