#!/bin/bash
# examples/run_all.sh
# Run all example scenarios for testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common/test_utils.sh"

check_root

# Find all scenario directories (directories with test.sh)
SCENARIOS=()
for dir in "${SCRIPT_DIR}"/*/; do
    if [ -f "${dir}test.sh" ]; then
        scenario_name=$(basename "$dir")
        SCENARIOS+=("$scenario_name")
    fi
done

if [ ${#SCENARIOS[@]} -eq 0 ]; then
    print_error "No scenarios found"
    exit 1
fi

print_info "Found ${#SCENARIOS[@]} scenario(s): ${SCENARIOS[*]}"
echo ""

# Track results
PASSED=0
FAILED=0
FAILED_SCENARIOS=()

# Run each scenario
for scenario in "${SCENARIOS[@]}"; do
    echo "========================================"
    print_info "Running scenario: $scenario"
    echo "========================================"

    scenario_dir="${SCRIPT_DIR}/${scenario}"

    # Setup
    if [ -f "${scenario_dir}/setup.sh" ]; then
        print_info "Setting up $scenario..."
        if ! "${scenario_dir}/setup.sh"; then
            print_error "Setup failed for $scenario"
            FAILED=$((FAILED + 1))
            FAILED_SCENARIOS+=("$scenario")
            continue
        fi
    fi

    # Run test
    if [ -f "${scenario_dir}/test.sh" ]; then
        print_info "Testing $scenario..."
        if "${scenario_dir}/test.sh"; then
            print_success "Scenario $scenario passed"
            PASSED=$((PASSED + 1))
        else
            print_error "Scenario $scenario failed"
            FAILED=$((FAILED + 1))
            FAILED_SCENARIOS+=("$scenario")
        fi
    fi

    # Teardown (always run)
    if [ -f "${scenario_dir}/teardown.sh" ]; then
        print_info "Tearing down $scenario..."
        "${scenario_dir}/teardown.sh" || true
    fi

    echo ""
done

# Summary
echo "========================================"
echo "Summary"
echo "========================================"
print_info "Total: $((PASSED + FAILED))"
print_success "Passed: $PASSED"

if [ $FAILED -gt 0 ]; then
    print_error "Failed: $FAILED"
    print_error "Failed scenarios: ${FAILED_SCENARIOS[*]}"
    exit 1
else
    print_success "All scenarios passed!"
    exit 0
fi
