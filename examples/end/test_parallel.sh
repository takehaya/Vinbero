#!/bin/bash
# examples/end/test_parallel.sh
# Demonstrate parallel execution of multiple test instances

set -e

if [[ $(id -u) -ne 0 ]]; then
    echo "Please run with sudo"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}==========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}==========================================${NC}"
}

# Test instances with different prefixes
TEST_PREFIXES=("test1-" "test2-" "test3-")

print_header "Parallel Execution Test"
echo "This test will run ${#TEST_PREFIXES[@]} instances in parallel"
echo ""

# Cleanup function
cleanup() {
    print_info "Cleaning up all test instances..."
    for prefix in "${TEST_PREFIXES[@]}"; do
        export TOPO_NS_PREFIX="$prefix"
        "${SCRIPT_DIR}/teardown.sh" > /dev/null 2>&1 || true
    done
}

# Register cleanup on exit (only on success or interrupt)
trap cleanup INT TERM

# Setup all instances in parallel
print_info "Setting up ${#TEST_PREFIXES[@]} test instances in parallel..."
pids=()
for prefix in "${TEST_PREFIXES[@]}"; do
    (
        export TOPO_NS_PREFIX="$prefix"
        "${SCRIPT_DIR}/setup.sh" > "/tmp/setup_${prefix}.log" 2>&1
    ) &
    pids+=($!)
done

# Wait for all setups to complete
failed=0
for i in "${!pids[@]}"; do
    if wait "${pids[$i]}"; then
        print_success "Setup completed for ${TEST_PREFIXES[$i]}"
    else
        print_error "Setup failed for ${TEST_PREFIXES[$i]}"
        cat "/tmp/setup_${TEST_PREFIXES[$i]}.log"
        failed=1
    fi
done

if [ $failed -eq 1 ]; then
    print_error "Some setups failed. Aborting."
    exit 1
fi

echo ""
print_header "Verifying parallel execution"

# Verify all instances are isolated
print_info "Listing all network namespaces..."
for prefix in "${TEST_PREFIXES[@]}"; do
    echo "  ${prefix}:"
    ip netns list | grep "^${prefix}" | sed 's/^/    /'
done

echo ""
# Give time for routes to settle
sleep 2

print_info "Running quick connectivity tests in parallel..."

# Run ping tests in parallel
pids=()
for prefix in "${TEST_PREFIXES[@]}"; do
    (
        ns_host1="${prefix}host1"
        if ip netns exec "$ns_host1" ping -c 1 -W 2 172.0.2.1 > /dev/null 2>&1; then
            exit 0
        else
            exit 1
        fi
    ) &
    pids+=($!)
done

# Wait for all tests
failed=0
for pid in "${pids[@]}"; do
    if wait "$pid"; then
        :  # Success, no output needed
    else
        failed=1
    fi
done

# Print results
if [ $failed -eq 0 ]; then
    for prefix in "${TEST_PREFIXES[@]}"; do
        print_success "${prefix} connectivity test passed"
    done
else
    for prefix in "${TEST_PREFIXES[@]}"; do
        print_error "${prefix} connectivity test failed"
    done
fi

echo ""
if [ $failed -eq 0 ]; then
    print_header "Parallel Execution Test: SUCCESS"
    print_success "All ${#TEST_PREFIXES[@]} instances ran successfully in parallel!"
    print_success "No namespace conflicts detected"
    cleanup
    exit 0
else
    print_header "Parallel Execution Test: FAILED"
    print_error "Some tests failed"
    print_info "Namespaces left for debugging. Run cleanup manually if needed."
    exit 1
fi
