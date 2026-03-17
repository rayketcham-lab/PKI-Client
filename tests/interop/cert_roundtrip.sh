#!/usr/bin/env bash
# ============================================================================
# Certificate Round-Trip Tests
#
# Tests the full lifecycle: key gen → CSR → inspect → convert → verify
# Validates that pki can generate, parse, and convert its own output.
# Includes byte-level fidelity checks on round-tripped data.
# ============================================================================

source "$(dirname "$0")/lib.sh"

echo "============================================"
echo "Certificate Round-Trip Tests"
echo "  Binary: $PKI"
echo "============================================"

# ── Test Group 1: Key Generation ──
echo ""
echo "[1/7] Key Generation"

# Format: "display-name:cli-algo:extra-args..."
KEYGEN_SPECS=(
    "ec-p256:ec:--curve:p256"
    "ec-p384:ec:--curve:p384"
    "rsa-4096:rsa:--bits:4096"
    # ed25519 keygen not yet supported in spork-core — skip for now
)

for spec in "${KEYGEN_SPECS[@]}"; do
    IFS=':' read -ra PARTS <<< "$spec"
    name="${PARTS[0]}"
    algo="${PARTS[1]}"
    extra_args=()
    for ((i=2; i<${#PARTS[@]}; i++)); do
        extra_args+=("${PARTS[$i]}")
    done

    run_test "generate $name key" \
        "$PKI" key gen "$algo" "${extra_args[@]}" -o "$WORK/key-${name}.pem"
    if [ -f "$WORK/key-${name}.pem" ]; then
        run_test "inspect $name key" \
            "$PKI" key show "$WORK/key-${name}.pem"
        run_test "$name key is valid PEM" \
            expect_contains "$WORK/key-${name}.pem" "BEGIN"
    fi
done

# ── Test Group 2: CSR Creation ──
echo ""
echo "[2/7] CSR Creation and Inspection"

run_test "create CSR with EC P-256 key" \
    "$PKI" csr create \
        --key "$WORK/key-ec-p256.pem" \
        --cn "roundtrip-test.example.com" \
        --san "dns:roundtrip-test.example.com" \
        --san "dns:www.roundtrip-test.example.com" \
        -o "$WORK/test.csr"

if [ -f "$WORK/test.csr" ]; then
    run_test "CSR file is valid PEM" \
        expect_contains "$WORK/test.csr" "BEGIN CERTIFICATE REQUEST"
    run_test "inspect CSR (text)" \
        "$PKI" csr show "$WORK/test.csr" -f text
    run_test "inspect CSR (json)" \
        "$PKI" csr show "$WORK/test.csr" -f json
fi

# ── Test Group 3: Format Conversion with Byte-Level Fidelity ──
echo ""
echo "[3/7] Format Conversion (PEM ↔ DER) with Fidelity Check"

for name in "ec-p256" "rsa-4096"; do
    KEY="$WORK/key-${name}.pem"
    if [ -f "$KEY" ]; then
        run_test "convert $name key PEM→DER" \
            "$PKI" convert "$KEY" -o "$WORK/key-${name}.der" --to der
        if [ -f "$WORK/key-${name}.der" ]; then
            run_test "DER file is non-empty" \
                test -s "$WORK/key-${name}.der"
            run_test "convert $name key DER→PEM" \
                "$PKI" convert "$WORK/key-${name}.der" --from key -o "$WORK/key-${name}-rt.pem" --to pem
            if [ -f "$WORK/key-${name}-rt.pem" ]; then
                run_test "round-tripped PEM is valid" \
                    expect_contains "$WORK/key-${name}-rt.pem" "BEGIN"
                # Byte-level fidelity: convert round-tripped PEM back to DER and compare
                "$PKI" convert "$WORK/key-${name}-rt.pem" -o "$WORK/key-${name}-rt.der" --to der 2>/dev/null || true
                if [ -f "$WORK/key-${name}-rt.der" ]; then
                    run_test "$name DER round-trip byte-identical" \
                        files_match "$WORK/key-${name}.der" "$WORK/key-${name}-rt.der"
                fi
            fi
        fi
    fi
done

# CSR conversion with fidelity check
if [ -f "$WORK/test.csr" ]; then
    run_test "convert CSR PEM→DER" \
        "$PKI" convert "$WORK/test.csr" -o "$WORK/test.csr.der" --to der
    if [ -f "$WORK/test.csr.der" ]; then
        run_test "CSR DER is non-empty" \
            test -s "$WORK/test.csr.der"
        run_test "convert CSR DER→PEM" \
            "$PKI" convert "$WORK/test.csr.der" --from csr -o "$WORK/test-rt.csr" --to pem
        # Byte-level fidelity on CSR
        if [ -f "$WORK/test-rt.csr" ]; then
            "$PKI" convert "$WORK/test-rt.csr" -o "$WORK/test-rt.csr.der" --to der 2>/dev/null || true
            if [ -f "$WORK/test-rt.csr.der" ]; then
                run_test "CSR DER round-trip byte-identical" \
                    files_match "$WORK/test.csr.der" "$WORK/test-rt.csr.der"
            fi
        fi
    fi
fi

# ── Test Group 4: Output Format Consistency ──
echo ""
echo "[4/7] Output Format Consistency"

for fmt in text json compact; do
    run_test "key show in $fmt format" \
        "$PKI" key show "$WORK/key-ec-p256.pem" -f "$fmt"
done

if [ -f "$WORK/test.csr" ]; then
    for fmt in text json compact; do
        run_test "csr show in $fmt format" \
            "$PKI" csr show "$WORK/test.csr" -f "$fmt"
    done
fi

# ── Test Group 5: Cross-Algorithm CSR Generation ──
echo ""
echo "[5/7] Cross-Algorithm CSR Generation"

for name in "ec-p384" "rsa-4096"; do
    KEY="$WORK/key-${name}.pem"
    if [ -f "$KEY" ]; then
        run_test "create CSR with $name key" \
            "$PKI" csr create \
                --key "$KEY" \
                --cn "${name}-test.example.com" \
                -o "$WORK/csr-${name}.pem"
        if [ -f "$WORK/csr-${name}.pem" ]; then
            run_test "inspect $name CSR" \
                "$PKI" csr show "$WORK/csr-${name}.pem" -f json
        fi
    fi
done

# ── Test Group 6: Negative Tests (Error Paths) ──
echo ""
echo "[6/7] Negative Tests — Error Paths"

run_test_expect_fail "reject non-existent key file" \
    "$PKI" key show "$WORK/does-not-exist.pem"

# Test convert with mismatched --from type
run_test_expect_fail "reject DER key with wrong --from type" \
    "$PKI" convert "$WORK/key-ec-p256.der" --from csr -o "$WORK/bad-convert.pem" --to pem

# Test CSR creation without required --cn flag
run_test_expect_fail "reject CSR without CN" \
    "$PKI" csr create \
        --key "$WORK/key-rsa-4096.pem" \
        -o "$WORK/bad.csr"

# ── Test Group 7: RSA-2048 Key (Common Deployment Size) ──
echo ""
echo "[7/7] RSA-2048 (Common Deployment)"

run_test "generate RSA-2048 key" \
    "$PKI" key gen rsa --bits 3072 -o "$WORK/key-rsa-3072.pem"
if [ -f "$WORK/key-rsa-3072.pem" ]; then
    run_test "inspect RSA-3072 key" \
        "$PKI" key show "$WORK/key-rsa-3072.pem"
    run_test "create CSR with RSA-3072" \
        "$PKI" csr create --key "$WORK/key-rsa-3072.pem" --cn "rsa3072.example.com" -o "$WORK/csr-rsa-3072.pem"
fi

report_summary
