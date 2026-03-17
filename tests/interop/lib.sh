#!/usr/bin/env bash
# ============================================================================
# Shared interop test harness
#
# Source this from test scripts:  source "$(dirname "$0")/lib.sh"
# ============================================================================

set -euo pipefail

PKI="${PKI_BIN:-./target/release/pki}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
SKIP=0

# run_test "name" command args...
# Captures stdout/stderr, reports pass/fail
run_test() {
    local name="$1"
    shift
    echo -n "  TEST: $name ... "
    if "$@" > "$WORK/stdout" 2> "$WORK/stderr"; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        local code=$?
        echo "FAIL (exit $code)"
        echo "    stdout: $(head -3 "$WORK/stdout" 2>/dev/null || true)"
        echo "    stderr: $(head -3 "$WORK/stderr" 2>/dev/null || true)"
        FAIL=$((FAIL + 1))
    fi
}

# run_test_expect_fail "name" command args...
# Passes if the command FAILS (for negative/error-path testing)
run_test_expect_fail() {
    local name="$1"
    shift
    echo -n "  TEST: $name ... "
    if "$@" > "$WORK/stdout" 2> "$WORK/stderr"; then
        echo "FAIL (expected failure, got success)"
        FAIL=$((FAIL + 1))
    else
        echo "PASS (correctly rejected)"
        PASS=$((PASS + 1))
    fi
}

# expect_contains file pattern
# Asserts that file contains the grep pattern
expect_contains() {
    grep -q "$2" "$1"
}

# save_output "name"
# Copies $WORK/stdout to $WORK/$name for later inspection
save_output() {
    cp "$WORK/stdout" "$WORK/$1"
}

# report_summary
# Prints final pass/fail/skip summary and exits with appropriate code
report_summary() {
    echo ""
    echo "============================================"
    echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"
    echo "============================================"
    if [ "$FAIL" -gt 0 ]; then
        exit 1
    fi
}

# files_match file1 file2
# Compares two files by SHA-256 hash
files_match() {
    local hash1 hash2
    hash1=$(sha256sum "$1" | cut -d' ' -f1)
    hash2=$(sha256sum "$2" | cut -d' ' -f1)
    [ "$hash1" = "$hash2" ]
}
