#!/usr/bin/env bash
# Vinbero one-liner installer.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/takehaya/vinbero/main/scripts/install_vinbero.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/takehaya/vinbero/main/scripts/install_vinbero.sh | sudo bash -s -- --version v0.0.4
#   curl -fsSL https://raw.githubusercontent.com/takehaya/vinbero/main/scripts/install_vinbero.sh | sudo bash -s -- --with-sdk
#
# GitHub release から goreleaser 生成のバイナリ (vinberod / vinbero) を取得し
# /usr/local/bin に配置する。--with-sdk を付けると plugin SDK tarball も
# /usr/local 以下へ展開する。
set -euo pipefail

REPO="takehaya/vinbero"
BIN_DIR="/usr/local/bin"
SHARE_DIR="/usr/local/share/vinbero"
STATE_FILE="${SHARE_DIR}/.installed-from-tag"
SDK_PREFIX="/usr/local"

VERSION="${VINBERO_VERSION:-}"
WITH_SDK=0

usage() {
  cat >&2 <<'EOF'
Usage: install_vinbero.sh [--version <tag>] [--with-sdk]

  --version <tag>   install a specific release tag (e.g. v0.0.4).
                    defaults to the latest release.
                    can also be set via VINBERO_VERSION.
  --with-sdk        also install the plugin SDK (headers + examples)
                    under /usr/local.
  -h, --help        show this help.
EOF
}

# 引数 parse。`bash -s -- --version v0.0.4 --with-sdk` の順不同を許容する。
while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      VERSION="${2:?--version requires a value}"
      shift 2
      ;;
    --version=*)
      VERSION="${1#*=}"
      shift
      ;;
    --with-sdk)
      WITH_SDK=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

# 必須コマンドの確認。常に使う curl / jq / install のみ必須にする。
# tar は --with-sdk 時にだけ、sha256sum は checksums 検証時にだけ確認する。
for cmd in curl jq install; do
  command -v "$cmd" >/dev/null 2>&1 || {
    case "$cmd" in
      install) pkg="coreutils" ;;  # install は coreutils 由来でパッケージ名が異なる
      *) pkg="$cmd" ;;
    esac
    echo "Required command not found: $cmd (provided by the '$pkg' package)" >&2
    exit 1
  }
done

# write 権限の確認。root でない場合は早めに知らせる。配置先が存在すればそのディレクトリ、
# 無ければ最初に存在する親ディレクトリの書き込み可否を見る。配下にファイルを作るには
# 書き込み (w) に加えて探索 (x) 権が要るため両方を確認する。
writable_target() {
  local d="$1"
  while [ ! -e "$d" ]; do d="$(dirname "$d")"; done
  [ -w "$d" ] && [ -x "$d" ]
}
if [ "$(id -u)" -ne 0 ]; then
  for d in "$BIN_DIR" "$SHARE_DIR"; do
    writable_target "$d" || {
      echo "This installer needs to write under ${d}; re-run with sudo." >&2
      exit 1
    }
  done
fi

# Vinbero は linux バイナリのみ配布するため、Linux 以外は早期に中断する。
case "$(uname -s)" in
  Linux) ;;
  *) echo "Unsupported OS: $(uname -s) (Vinbero ships linux binaries only)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac

if [ -z "$VERSION" ] || [ "$VERSION" = "latest" ]; then
  META_URL="https://api.github.com/repos/${REPO}/releases/latest"
else
  META_URL="https://api.github.com/repos/${REPO}/releases/tags/${VERSION}"
fi
JSON="$(curl -fsSL "$META_URL")"

TAG_NAME="$(printf '%s' "$JSON" | jq -r '.tag_name // empty')"

# goreleaser の format=binary は各バイナリを
# `{{ .Binary }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}` (例: vinberod_0.0.4_linux_amd64) で upload する。
# JSON を渡すのに echo を使うと xpg_echo などでバックスラッシュが解釈され壊れうるため printf を使う。
asset_url() {
  local pattern="$1"
  printf '%s' "$JSON" | jq -r --arg p "$pattern" '
    .assets[]?.browser_download_url | select(test($p))
  ' | head -n1
}

CHK_URL="$(asset_url "/checksums\\.txt$")"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# checksums.txt があれば best-effort で sha256 を検証する。
verify_checksum() {
  local file="$1"
  [ -n "$CHK_URL" ] || return 0
  if ! command -v sha256sum >/dev/null 2>&1; then
    echo "warning: sha256sum not found, skipping checksum verification" >&2
    return 0
  fi
  if [ ! -f "$TMP/checksums.txt" ]; then
    # 取得に失敗しても install は止めず、検証だけスキップする (best-effort)。
    curl -fsSL "$CHK_URL" -o "$TMP/checksums.txt" || {
      echo "warning: failed to download checksums.txt, skipping verification" >&2
      return 0
    }
  fi
  local base line; base="$(basename "$file")"
  # checksums.txt は `<sha256>  <filename>` 形式。ファイル名を第2フィールドで厳密一致
  # させ、grep の正規表現で `.` などが任意文字として誤マッチするのを避ける。
  line="$(awk -v f="$base" '$2 == f {print; exit}' "$TMP/checksums.txt")"
  if [ -n "$line" ]; then
    ( cd "$TMP" && printf '%s\n' "$line" | sha256sum -c - >/dev/null )
    echo "verified  ${base}"
  else
    echo "warning: no checksum entry for ${base}, skipping verification" >&2
  fi
}

mkdir -p "$BIN_DIR" "$SHARE_DIR"

# vinberod (daemon) と vinbero (CLI) を取得して /usr/local/bin に配置する。
# CLI の `vinbero_` は daemon の `vinberod_` と接頭辞が衝突しない (末尾 `_` が次の文字を分ける)。
for bin in vinberod vinbero; do
  url="$(asset_url "/${bin}_.*_linux_${ARCH}$")"
  [ -n "$url" ] || { echo "No ${bin} binary matched for linux_${ARCH} in ${TAG_NAME:-$META_URL}" >&2; exit 1; }
  file="$TMP/$(basename "$url")"
  curl -fsSL "$url" -o "$file"
  verify_checksum "$file"
  install -m 0755 "$file" "$BIN_DIR/$bin"
done

# plugin SDK (optional)
if [ "$WITH_SDK" -eq 1 ]; then
  command -v tar >/dev/null 2>&1 || { echo "Required command not found: tar (needed for --with-sdk)" >&2; exit 1; }
  SDK_URL="$(asset_url "/vinbero-sdk-.*\\.tar\\.gz$")"
  if [ -n "$SDK_URL" ]; then
    SDK_FILE="$TMP/$(basename "$SDK_URL")"
    curl -fsSL "$SDK_URL" -o "$SDK_FILE"
    verify_checksum "$SDK_FILE"
    # root で /usr/local に展開するため、path traversal を防ぐ。展開前に各 entry を
    # 検証し、絶対パス・`..`・include/ share/ 配下以外を含む場合は中断する。grep の
    # -v / -q は実装差があるため、移植性のある case で 1 行ずつ判定する。
    sdk_entries="$(tar tzf "$SDK_FILE")"
    while IFS= read -r entry; do
      [ -n "$entry" ] || continue
      case "$entry" in
        /*|..|../*|*/../*|*/..)
          echo "error: SDK tarball contains absolute or '..' paths; aborting" >&2
          exit 1 ;;
      esac
      case "${entry#./}" in
        include|share|include/*|share/*) ;;
        *)
          echo "error: SDK tarball has entries outside include/ or share/; aborting" >&2
          exit 1 ;;
      esac
    done <<<"$sdk_entries"
    # tarball の top-level は include/ と share/ なので /usr/local に直接展開する。
    # root 実行を想定し、archive 内の owner / permission を持ち込まない。
    tar --no-same-owner --no-same-permissions -xzf "$SDK_FILE" -C "$SDK_PREFIX"
    echo "SDK      ${SDK_PREFIX}/include/vinbero, ${SDK_PREFIX}/share/vinbero-sdk"
  else
    echo "warning: --with-sdk requested but no SDK tarball found in ${TAG_NAME:-release}" >&2
  fi
fi

echo "${TAG_NAME:-${VERSION:-latest}}" > "$STATE_FILE"

cat <<EOF

Installed Vinbero
  daemon   ${BIN_DIR}/vinberod
  CLI      ${BIN_DIR}/vinbero
  version  ${TAG_NAME:-${VERSION:-latest}}

Next steps:
  sudo vinberod -c vinbero.yml   # start the SRv6 daemon
  vinberod --help                # daemon options
  vinbero --help                 # CLI usage
EOF
