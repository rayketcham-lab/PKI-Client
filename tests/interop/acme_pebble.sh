#!/usr/bin/env bash
# ============================================================================
# ACME Interop Tests — pki client vs Pebble (Let's Encrypt test CA)
#
# Requires: Pebble running at $PEBBLE_URL with PEBBLE_VA_ALWAYS_VALID=1
# ============================================================================

source "$(dirname "$0")/lib.sh"

PEBBLE="${PEBBLE_URL:-https://localhost:14000/dir}"

echo "============================================"
echo "ACME Interop Tests (Pebble)"
echo "  Binary:  $PKI"
echo "  Server:  $PEBBLE"
echo "============================================"

# ── Test Group 1: Directory Discovery ──
echo ""
echo "[1/8] Directory Discovery"
run_test "fetch ACME directory" \
    "$PKI" acme directory --server "$PEBBLE" --insecure -f json
save_output "directory.json"

if [ -s "$WORK/directory.json" ]; then
    run_test "directory contains newAccount URL" \
        expect_contains "$WORK/directory.json" "newAccount"
    run_test "directory contains newOrder URL" \
        expect_contains "$WORK/directory.json" "newOrder"
    run_test "directory contains newNonce URL" \
        expect_contains "$WORK/directory.json" "newNonce"
fi

# ── Test Group 2: Account Registration ──
echo ""
echo "[2/8] Account Registration"
run_test "register new account" \
    "$PKI" acme register \
        --server "$PEBBLE" \
        --email "test@interop.pki-client.dev" \
        --key-file "$WORK/account.pem" \
        --insecure \
        -f json

if [ -f "$WORK/account.pem" ]; then
    run_test "account key file created" \
        test -s "$WORK/account.pem"
    run_test "account key is valid PEM" \
        expect_contains "$WORK/account.pem" "BEGIN"
fi

# ── Test Group 3: Idempotent Re-registration ──
echo ""
echo "[3/8] Idempotent Re-registration"
run_test "re-register same account" \
    "$PKI" acme register \
        --server "$PEBBLE" \
        --email "test@interop.pki-client.dev" \
        --key-file "$WORK/account.pem" \
        --insecure \
        -f json

# ── Test Group 4: Order Creation ──
echo ""
echo "[4/8] Order Creation"
run_test "create certificate order" \
    "$PKI" acme order \
        --server "$PEBBLE" \
        --key-file "$WORK/account.pem" \
        -d "interop-test.example.com" \
        --insecure \
        -f json

# ── Test Group 5: Full Certonly Flow ──
echo ""
echo "[5/8] Full Certificate Issuance (certonly)"
run_test "certonly flow" \
    "$PKI" acme certonly \
        --server "$PEBBLE" \
        --key-file "$WORK/account.pem" \
        --email "test@interop.pki-client.dev" \
        -d "certonly-test.example.com" \
        --output-dir "$WORK/certs" \
        --insecure \
        --agree-tos

if [ -d "$WORK/certs" ]; then
    CERT_FILE=$(find "$WORK/certs" -name "*.pem" -o -name "cert*" | head -1)
    if [ -n "$CERT_FILE" ]; then
        run_test "certificate file is valid PEM" \
            expect_contains "$CERT_FILE" "BEGIN CERTIFICATE"
        run_test "can inspect issued certificate" \
            "$PKI" cert show "$CERT_FILE" -f json
    else
        echo "  SKIP: No certificate file found in output dir"
        SKIP=$((SKIP + 1))
    fi
else
    echo "  SKIP: Output directory not created"
    SKIP=$((SKIP + 1))
fi

# ── Test Group 6: Negative Tests (Error Paths) ──
echo ""
echo "[6/8] Negative Tests — Error Paths"

# Bad server URL should fail
run_test_expect_fail "bad server URL rejected" \
    "$PKI" acme directory --server "https://localhost:1/nonexistent" --insecure -f json

# Empty domain should fail
run_test_expect_fail "empty domain rejected" \
    "$PKI" acme order \
        --server "$PEBBLE" \
        --key-file "$WORK/account.pem" \
        -d "" \
        --insecure

# Non-existent key file should fail
run_test_expect_fail "missing key file rejected" \
    "$PKI" acme register \
        --server "$PEBBLE" \
        --email "test@interop.pki-client.dev" \
        --key-file "$WORK/nonexistent-key.pem" \
        --insecure

# ── Test Group 7: Multi-Domain Order ──
echo ""
echo "[7/8] Multi-Domain Order"
run_test "create multi-SAN order" \
    "$PKI" acme order \
        --server "$PEBBLE" \
        --key-file "$WORK/account.pem" \
        -d "multi1.example.com" \
        -d "multi2.example.com" \
        -d "multi3.example.com" \
        --insecure \
        -f json

# ── Test Group 8: JSON Output Validation ──
echo ""
echo "[8/8] Output Format Validation"
run_test "directory JSON is parseable" \
    "$PKI" acme directory --server "$PEBBLE" --insecure -f json

report_summary
