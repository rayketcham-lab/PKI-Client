#!/usr/bin/env bash
# ============================================================================
# TLS Probe Interop Tests — validate probe against real-world endpoints
#
# Tests pki probe against well-known public TLS servers to verify:
# - TLS version detection
# - Certificate chain parsing
# - Cipher suite reporting
# - JSON output format
# ============================================================================

source "$(dirname "$0")/lib.sh"

# Network pre-check: skip gracefully if we can't reach the internet
echo -n "Network connectivity check... "
if ! timeout 10 bash -c 'echo >/dev/tcp/google.com/443' 2>/dev/null; then
    echo "SKIPPED (no network connectivity)"
    echo "TLS probe interop tests require internet access."
    exit 0
fi
echo "OK"

echo "============================================"
echo "TLS Probe Interop Tests"
echo "  Binary: $PKI"
echo "============================================"

# ── Test Group 1: Basic Connectivity ──
echo ""
echo "[1/5] Basic TLS Connectivity"

TARGETS=("google.com:443" "cloudflare.com:443" "github.com:443")

for target in "${TARGETS[@]}"; do
    run_test "probe check $target" \
        "$PKI" probe check "$target" --timeout 15
done

# ── Test Group 2: Full Server Probe ──
echo ""
echo "[2/5] Full Server Probe"

run_test "probe server google.com (text)" \
    "$PKI" probe server google.com:443 --timeout 15 -f text

run_test "probe server google.com (json)" \
    "$PKI" probe server google.com:443 --timeout 15 -f json
save_output "google-probe.json"

if [ -s "$WORK/google-probe.json" ]; then
    run_test "JSON output contains protocol version" \
        expect_contains "$WORK/google-probe.json" "tls"
    run_test "JSON output contains certificate info" \
        expect_contains "$WORK/google-probe.json" "cert"
fi

# ── Test Group 3: Certificate Chain Fetch ──
echo ""
echo "[3/5] Certificate Chain Fetch"

run_test "fetch chain from google.com" \
    "$PKI" probe fetch google.com:443 -o "$WORK/google-chain.pem" --timeout 15

if [ -f "$WORK/google-chain.pem" ]; then
    run_test "chain file is valid PEM" \
        expect_contains "$WORK/google-chain.pem" "BEGIN CERTIFICATE"
    run_test "inspect fetched chain" \
        "$PKI" cert show "$WORK/google-chain.pem"
fi

# ── Test Group 4: TLS Version Detection ──
echo ""
echo "[4/5] TLS Version Detection"

run_test "detect TLS 1.3 on cloudflare.com" \
    "$PKI" probe server cloudflare.com:443 --timeout 15 -f json
save_output "cf-probe.json"

if [ -s "$WORK/cf-probe.json" ]; then
    run_test "cloudflare reports TLS 1.3" \
        expect_contains "$WORK/cf-probe.json" "1.3"
fi

# ── Test Group 5: Probe + Cert Inspection Pipeline ──
echo ""
echo "[5/5] Probe + Cert Inspection Pipeline"

run_test "fetch github.com chain" \
    "$PKI" probe fetch github.com:443 -o "$WORK/gh-chain.pem" --timeout 15

if [ -f "$WORK/gh-chain.pem" ]; then
    run_test "show github cert details" \
        "$PKI" cert show "$WORK/gh-chain.pem" -f json
    run_test "check github cert expiry" \
        "$PKI" cert expires "$WORK/gh-chain.pem" --within 7d
fi

report_summary
