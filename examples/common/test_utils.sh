#!/bin/bash
# examples/common/test_utils.sh
# Test utility functions

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        exit 1
    fi
}

# Execute command with echo (for debugging)
# Usage: run <command...>
run() {
    echo "$@"
    "$@" || exit 1
}

# Print success message
print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

# Print error message
print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Print info message
print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}


# Test ping connectivity (auto-detects IPv4/IPv6)
# Usage: test_ping <namespace> <destination> [count]
test_ping() {
    local ns="$1"
    local dst="$2"
    local count="${3:-3}"
    local cmd="ping"
    local proto="IPv4"

    # Auto-detect IPv6 by presence of colon
    if [[ "$dst" == *":"* ]]; then
        cmd="ping6"
        proto="IPv6"
    fi

    print_info "Testing $proto ping from $ns to $dst..."

    if ip netns exec "$ns" $cmd -c "$count" -W 2 "$dst" > /dev/null 2>&1; then
        print_success "$proto ping to $dst succeeded"
        return 0
    else
        print_error "$proto ping to $dst failed"
        return 1
    fi
}


