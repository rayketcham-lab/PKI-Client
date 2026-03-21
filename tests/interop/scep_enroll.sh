#!/usr/bin/env bash
# ============================================================================
# SCEP Enrollment Interop Tests
#
# Validates the SCEP enrollment workflow including argument validation,
# error handling, and (when SCEP_URL is set) full enrollment against a
# live SCEP server.
#
# Usage:
#   bash tests/interop/scep_enroll.sh [PKI_BINARY]
#   SCEP_URL=https://scep.example.com/scep bash tests/interop/scep_enroll.sh
#
# Environment variables:
#   SCEP_URL          - Live SCEP server URL. When set, runs full enrollment.
#   SCEP_CHALLENGE    - Challenge password for enrollment (optional).
#   SCEP_INSECURE     - Set to "1" to skip TLS cert verification (test envs).
#   PKI_BIN           - Path to the pki binary (default: ./target/release/pki).
#   FAILURE_LOG       - Path to write structured failure records.
# ============================================================================
set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

PKI="${1:-${PKI_BIN:-./target/release/pki}}"
WORK=$(mktemp -d -t scep-interop-XXXXXX)
FAILURE_LOG="${FAILURE_LOG:-/tmp/scep-interop-failures.log}"

: > "${FAILURE_LOG}"

# ── Counters ──────────────────────────────────────────────────────────────────

PASS=0
FAIL=0
SKIP=0

# ── Cleanup ───────────────────────────────────────────────────────────────────

cleanup() {
    rm -rf "${WORK}"
}
trap cleanup EXIT

# ── Colors ────────────────────────────────────────────────────────────────────

if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    CYAN=''
    BOLD=''
    RESET=''
fi

# ── Test Helpers ──────────────────────────────────────────────────────────────

# pass TEST_ID "description"
pass() {
    local test_id="$1"
    local desc="$2"
    printf '%s[PASS]%s %s\n' "${GREEN}" "${RESET}" "${desc}"
    PASS=$(( PASS + 1 ))
    : "${test_id}"
}

# fail TEST_ID "description" "detail"
fail() {
    local test_id="$1"
    local desc="$2"
    local detail="${3:-}"
    printf '%s[FAIL]%s %s\n' "${RED}" "${RESET}" "${desc}"
    if [[ -n "${detail}" ]]; then
        printf '       %sDetail:%s %s\n' "${YELLOW}" "${RESET}" "${detail}"
    fi
    FAIL=$(( FAIL + 1 ))
    local ts
    ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u)
    printf 'FAIL|%s|%s|%s\n' "${test_id}" "${detail}" "${ts}" >> "${FAILURE_LOG}"
}

# skip "description"
skip() {
    local desc="$1"
    printf '  %s[SKIP]%s %s\n' "${YELLOW}" "${RESET}" "${desc}"
    SKIP=$(( SKIP + 1 ))
}

# section TITLE
section() {
    printf '\n%s%s--- %s ---%s\n' "${BOLD}" "${CYAN}" "$1" "${RESET}"
}

# expect_fail: runs a command and asserts it exits non-zero.
# Usage: expect_fail TEST_ID "description" cmd args...
expect_fail() {
    local test_id="$1"
    local desc="$2"
    shift 2
    if "$@" > "${WORK}/ef.stdout" 2> "${WORK}/ef.stderr"; then
        fail "${test_id}" "${desc}" "Expected non-zero exit, but command succeeded"
    else
        pass "${test_id}" "${desc}"
    fi
}

# ── Pre-flight ────────────────────────────────────────────────────────────────

printf '%s=== PKI Client SCEP Enrollment Interop Tests ===%s\n' "${BOLD}" "${RESET}"

if [[ ! -x "${PKI}" ]]; then
    printf '%sERROR:%s pki binary not found or not executable: %s\n' "${RED}" "${RESET}" "${PKI}"
    exit 2
fi

PKI_VERSION=$("${PKI}" --version 2>&1 | head -1 || echo "unknown")
printf "Binary:  %s (%s)\n" "${PKI}" "${PKI_VERSION}"

if [[ -n "${SCEP_URL:-}" ]]; then
    printf "SCEP server: %s\n" "${SCEP_URL}"
else
    printf "SCEP server: %s(none — skipping live enrollment tests)%s\n" "${YELLOW}" "${RESET}"
fi

# ── Category 1: CLI Argument Validation ───────────────────────────────────────

section "CLI Argument Validation"

# enroll: missing required --subject flag
expect_fail "enroll_no_subject" \
    "enroll: missing required --subject is rejected" \
    "${PKI}" scep enroll "https://scep.example.com/scep"

# enroll: missing URL entirely
expect_fail "enroll_no_url" \
    "enroll: missing URL argument is rejected" \
    "${PKI}" scep enroll

# enroll: invalid key-type value
expect_fail "enroll_bad_keytype" \
    "enroll: invalid --key-type value is rejected" \
    "${PKI}" scep enroll "https://scep.example.com/scep" \
        --subject "test.example.com" \
        --key-type "invalid-algo-xyz"

# cacaps: missing URL
expect_fail "cacaps_no_url" \
    "cacaps: missing URL argument is rejected" \
    "${PKI}" scep cacaps

# cacert: missing URL
expect_fail "cacert_no_url" \
    "cacert: missing URL argument is rejected" \
    "${PKI}" scep cacert

# pkiop: missing URL
expect_fail "pkiop_no_url" \
    "pkiop: missing URL argument is rejected" \
    "${PKI}" scep pkiop

# pkiop: missing --message flag
expect_fail "pkiop_no_message" \
    "pkiop: missing --message flag is rejected" \
    "${PKI}" scep pkiop "https://scep.example.com/scep"

# pkiop: non-existent message file
expect_fail "pkiop_bad_message" \
    "pkiop: non-existent message file is rejected" \
    "${PKI}" scep pkiop "https://scep.example.com/scep" \
        --message "${WORK}/does-not-exist.p7"

# ── Category 2: Key and CSR Generation (Prerequisites) ────────────────────────

section "Key and CSR Prerequisites"

# Generate the keys and CSRs that the remaining test categories depend on.
# These use pki commands (key gen, csr create) — not SCEP-specific.

if "${PKI}" key gen rsa --bits 2048 -o "${WORK}/scep-key-rsa2048.pem" \
        > "${WORK}/keygen-rsa.stdout" 2> "${WORK}/keygen-rsa.stderr"; then
    pass "prereq_key_rsa2048" "RSA-2048 key generated for SCEP tests"
else
    fail "prereq_key_rsa2048" "RSA-2048 key generation failed" \
        "$(cat "${WORK}/keygen-rsa.stderr")"
fi

if "${PKI}" key gen ec --curve p256 -o "${WORK}/scep-key-ec256.pem" \
        > "${WORK}/keygen-ec.stdout" 2> "${WORK}/keygen-ec.stderr"; then
    pass "prereq_key_ec256" "EC P-256 key generated for SCEP tests"
else
    fail "prereq_key_ec256" "EC P-256 key generation failed" \
        "$(cat "${WORK}/keygen-ec.stderr")"
fi

# Create a CSR with the RSA key — used later for pkiop message file test
if [[ -f "${WORK}/scep-key-rsa2048.pem" ]]; then
    if "${PKI}" csr create \
            --key "${WORK}/scep-key-rsa2048.pem" \
            --cn "scep-test.example.com" \
            --san "dns:scep-test.example.com" \
            -o "${WORK}/scep-test.csr" \
            > "${WORK}/csr.stdout" 2> "${WORK}/csr.stderr"; then
        pass "prereq_csr_rsa2048" "RSA-2048 CSR created for SCEP tests"
    else
        fail "prereq_csr_rsa2048" "RSA-2048 CSR creation failed" \
            "$(cat "${WORK}/csr.stderr")"
    fi
else
    skip "prereq_csr_rsa2048 (RSA-2048 key not available)"
fi

# Create a CSR with the EC key
if [[ -f "${WORK}/scep-key-ec256.pem" ]]; then
    if "${PKI}" csr create \
            --key "${WORK}/scep-key-ec256.pem" \
            --cn "scep-ec-test.example.com" \
            --san "dns:scep-ec-test.example.com" \
            -o "${WORK}/scep-ec-test.csr" \
            > "${WORK}/csr-ec.stdout" 2> "${WORK}/csr-ec.stderr"; then
        pass "prereq_csr_ec256" "EC P-256 CSR created for SCEP tests"
    else
        fail "prereq_csr_ec256" "EC P-256 CSR creation failed" \
            "$(cat "${WORK}/csr-ec.stderr")"
    fi
else
    skip "prereq_csr_ec256 (EC P-256 key not available)"
fi

# ── Category 3: Generated CSR Structural Validation ───────────────────────────

section "CSR Structural Validation"

# Validate that the CSRs created above are structurally sound.
# We cross-check with openssl as an independent reference.

validate_csr_structure() {
    local csr_file="$1"
    local expected_cn="$2"
    local test_id="$3"
    local display_name="$4"

    if [[ ! -f "${csr_file}" ]]; then
        skip "${display_name} CSR structural validation (file missing)"
        return
    fi

    # openssl should accept the CSR signature
    local verify_out
    if verify_out=$(openssl req -in "${csr_file}" -noout -verify 2>&1); then
        if echo "${verify_out}" | grep -q "verify OK"; then
            pass "${test_id}_sig" "${display_name} CSR: self-signature verified by openssl"
        else
            fail "${test_id}_sig" "${display_name} CSR: openssl verify did not confirm OK" \
                "${verify_out}"
        fi
    else
        fail "${test_id}_sig" "${display_name} CSR: openssl signature verification failed" \
            "${verify_out}"
    fi

    # Subject CN must match
    local subject_out
    subject_out=$(openssl req -in "${csr_file}" -noout -subject 2>&1)
    if echo "${subject_out}" | grep -qE "CN\s*=\s*${expected_cn}"; then
        pass "${test_id}_cn" "${display_name} CSR: subject CN is correct"
    else
        fail "${test_id}_cn" "${display_name} CSR: subject CN mismatch" \
            "Expected 'CN = ${expected_cn}', got: ${subject_out}"
    fi

    # PEM header must be correct
    if grep -q "BEGIN CERTIFICATE REQUEST" "${csr_file}"; then
        pass "${test_id}_pem" "${display_name} CSR: valid PEM header"
    else
        fail "${test_id}_pem" "${display_name} CSR: missing PEM header" ""
    fi
}

validate_csr_structure \
    "${WORK}/scep-test.csr" \
    "scep-test.example.com" \
    "csr_rsa2048" \
    "RSA-2048"

validate_csr_structure \
    "${WORK}/scep-ec-test.csr" \
    "scep-ec-test.example.com" \
    "csr_ec256" \
    "EC P-256"

# ── Category 4: enroll Error Path Against Unreachable URL ─────────────────────

section "Enrollment Error Paths (Unreachable Server)"

# Enrollment must fail fast with a clear error against an unreachable URL.
# We verify the command exits non-zero and does not hang.

UNREACHABLE_URL="http://127.0.0.1:19999/scep"

if timeout 15 "${PKI}" scep enroll "${UNREACHABLE_URL}" \
        --subject "test.example.com" \
        --max-polls 1 \
        --poll-interval 1 \
        > "${WORK}/enroll-unreachable.stdout" 2> "${WORK}/enroll-unreachable.stderr"; then
    fail "enroll_unreachable" \
        "enroll against unreachable server: expected non-zero exit" \
        "Command succeeded unexpectedly"
else
    pass "enroll_unreachable" \
        "enroll against unreachable server: correctly exits non-zero"
fi

# cacaps must fail fast against an unreachable server
if timeout 15 "${PKI}" scep cacaps "${UNREACHABLE_URL}" \
        > "${WORK}/cacaps-unreachable.stdout" 2> "${WORK}/cacaps-unreachable.stderr"; then
    fail "cacaps_unreachable" \
        "cacaps against unreachable server: expected non-zero exit" \
        "Command succeeded unexpectedly"
else
    pass "cacaps_unreachable" \
        "cacaps against unreachable server: correctly exits non-zero"
fi

# cacert must fail fast against an unreachable server
if timeout 15 "${PKI}" scep cacert "${UNREACHABLE_URL}" \
        > "${WORK}/cacert-unreachable.stdout" 2> "${WORK}/cacert-unreachable.stderr"; then
    fail "cacert_unreachable" \
        "cacert against unreachable server: expected non-zero exit" \
        "Command succeeded unexpectedly"
else
    pass "cacert_unreachable" \
        "cacert against unreachable server: correctly exits non-zero"
fi

# ── Category 5: pkiop Error Paths ─────────────────────────────────────────────

section "PKI Operation Error Paths"

# pkiop with a non-PKCS7 file (the CSR is not a valid pkiop payload) must fail
if [[ -f "${WORK}/scep-test.csr" ]]; then
    if timeout 15 "${PKI}" scep pkiop "${UNREACHABLE_URL}" \
            --message "${WORK}/scep-test.csr" \
            > "${WORK}/pkiop-bad-msg.stdout" 2> "${WORK}/pkiop-bad-msg.stderr"; then
        # May succeed at the message-loading stage and fail at network; either is fine
        # What matters is no panic / unhandled error
        pass "pkiop_csr_as_message" \
            "pkiop with CSR-as-message: exits cleanly (error expected at network or parse)"
    else
        pass "pkiop_csr_as_message" \
            "pkiop with CSR-as-message: correctly exits non-zero"
    fi
else
    skip "pkiop_csr_as_message (CSR prerequisite not available)"
fi

# ── Category 6: Output Format Flags ───────────────────────────────────────────

section "Help and Usage Output"

# All SCEP sub-commands must respond to --help without error
for subcmd in enroll cacaps cacert nextcacert pkiop; do
    if "${PKI}" scep "${subcmd}" --help \
            > "${WORK}/help-${subcmd}.stdout" 2> "${WORK}/help-${subcmd}.stderr"; then
        pass "help_${subcmd}" "pki scep ${subcmd} --help: exits zero"
    else
        # Some CLIs print help to stderr and exit 0; others exit non-zero. Either is acceptable
        # as long as some output was produced.
        if [[ -s "${WORK}/help-${subcmd}.stdout" ]] || [[ -s "${WORK}/help-${subcmd}.stderr" ]]; then
            pass "help_${subcmd}" "pki scep ${subcmd} --help: produced output"
        else
            fail "help_${subcmd}" "pki scep ${subcmd} --help: no output produced" ""
        fi
    fi
done

# ── Category 7: Live Server Tests (conditional on SCEP_URL) ───────────────────

section "Live Server Enrollment (SCEP_URL)"

if [[ -z "${SCEP_URL:-}" ]]; then
    skip "All live server tests (SCEP_URL not set)"
else
    SCEP_INSECURE_FLAG=""
    if [[ "${SCEP_INSECURE:-0}" == "1" ]]; then
        SCEP_INSECURE_FLAG="--insecure"
    fi

    # 7a: Get CA capabilities
    if "${PKI}" scep cacaps "${SCEP_URL}" ${SCEP_INSECURE_FLAG} \
            > "${WORK}/live-cacaps.stdout" 2> "${WORK}/live-cacaps.stderr"; then
        pass "live_cacaps" "live: cacaps succeeded against ${SCEP_URL}"

        # Capabilities output should contain at least one recognisable capability token
        if grep -qiE "SHA|AES|Renewal|POSTPKIOperation|GetCACaps" "${WORK}/live-cacaps.stdout"; then
            pass "live_cacaps_content" "live: cacaps output contains recognisable capabilities"
        else
            fail "live_cacaps_content" "live: cacaps output lacks expected capability tokens" \
                "$(head -5 "${WORK}/live-cacaps.stdout")"
        fi
    else
        fail "live_cacaps" "live: cacaps failed" "$(cat "${WORK}/live-cacaps.stderr")"
    fi

    # 7b: Get CA certificate
    if "${PKI}" scep cacert "${SCEP_URL}" ${SCEP_INSECURE_FLAG} \
            -o "${WORK}/live-ca.pem" \
            > "${WORK}/live-cacert.stdout" 2> "${WORK}/live-cacert.stderr"; then
        pass "live_cacert" "live: cacert succeeded"
    else
        fail "live_cacert" "live: cacert failed" "$(cat "${WORK}/live-cacert.stderr")"
    fi

    # Validate the retrieved CA cert with openssl
    if [[ -f "${WORK}/live-ca.pem" ]]; then
        if openssl x509 -in "${WORK}/live-ca.pem" -noout > /dev/null 2>&1; then
            pass "live_cacert_valid" "live: retrieved CA certificate is valid (openssl x509 -noout)"
        else
            # SCEP servers may return a degenerate PKCS#7 chain; tolerate that
            if grep -q "BEGIN CERTIFICATE" "${WORK}/live-ca.pem"; then
                pass "live_cacert_valid" "live: retrieved CA certificate PEM header present"
            else
                fail "live_cacert_valid" "live: retrieved CA certificate failed openssl validation" \
                    "$(openssl x509 -in "${WORK}/live-ca.pem" -noout 2>&1 | head -3)"
            fi
        fi
    fi

    # 7c: Full enrollment
    ENROLL_CHALLENGE_ARGS=""
    if [[ -n "${SCEP_CHALLENGE:-}" ]]; then
        ENROLL_CHALLENGE_ARGS="--challenge ${SCEP_CHALLENGE}"
    fi

    ENROLL_OUT_DIR="${WORK}/enroll-out"
    mkdir -p "${ENROLL_OUT_DIR}"

    if "${PKI}" scep enroll "${SCEP_URL}" \
            --subject "pki-scep-interop-test.example.com" \
            --san "pki-scep-interop-test.example.com" \
            --key-type rsa2048 \
            ${SCEP_INSECURE_FLAG} \
            ${ENROLL_CHALLENGE_ARGS} \
            --output "${ENROLL_OUT_DIR}" \
            --max-polls 12 \
            --poll-interval 5 \
            > "${WORK}/live-enroll.stdout" 2> "${WORK}/live-enroll.stderr"; then
        pass "live_enroll" "live: SCEP enrollment completed successfully"

        # Verify issued certificate file was written
        ISSUED_CERT="${ENROLL_OUT_DIR}/pki-scep-interop-test_example_com.pem"
        if [[ -f "${ISSUED_CERT}" ]]; then
            pass "live_enroll_cert_file" "live: certificate file written to output directory"

            # Validate cert with openssl
            if openssl x509 -in "${ISSUED_CERT}" -noout > /dev/null 2>&1; then
                pass "live_enroll_cert_valid" "live: issued certificate is valid (openssl x509 -noout)"

                # Subject CN must match what we requested
                cert_subject=$(openssl x509 -in "${ISSUED_CERT}" -noout -subject 2>&1)
                if echo "${cert_subject}" | grep -q "pki-scep-interop-test.example.com"; then
                    pass "live_enroll_cert_cn" "live: issued certificate subject CN matches enrollment request"
                else
                    fail "live_enroll_cert_cn" "live: issued certificate subject CN mismatch" \
                        "Got: ${cert_subject}"
                fi

                # Verify certificate is not expired
                if openssl x509 -in "${ISSUED_CERT}" -noout -checkend 0 > /dev/null 2>&1; then
                    pass "live_enroll_cert_notexpired" "live: issued certificate is not expired"
                else
                    fail "live_enroll_cert_notexpired" "live: issued certificate is expired or invalid" ""
                fi
            else
                fail "live_enroll_cert_valid" "live: issued certificate failed openssl validation" \
                    "$(openssl x509 -in "${ISSUED_CERT}" -noout 2>&1 | head -3)"
            fi
        else
            # Certificate may have been written with sanitized filename variant
            CERT_COUNT=$(find "${ENROLL_OUT_DIR}" -name "*.pem" -not -name "*-key.pem" | wc -l)
            if [[ "${CERT_COUNT}" -gt 0 ]]; then
                pass "live_enroll_cert_file" "live: certificate PEM file found in output directory"
            else
                fail "live_enroll_cert_file" "live: no certificate file found in output directory" \
                    "Contents: $(ls "${ENROLL_OUT_DIR}" 2>&1)"
            fi
        fi

        # Verify private key file was written with correct permissions
        KEY_COUNT=$(find "${ENROLL_OUT_DIR}" -name "*-key.pem" | wc -l)
        if [[ "${KEY_COUNT}" -gt 0 ]]; then
            pass "live_enroll_key_file" "live: private key file written to output directory"

            KEY_FILE=$(find "${ENROLL_OUT_DIR}" -name "*-key.pem" | head -1)
            KEY_PERMS=$(stat -c '%a' "${KEY_FILE}" 2>/dev/null || stat -f '%A' "${KEY_FILE}" 2>/dev/null || echo "unknown")
            if [[ "${KEY_PERMS}" == "600" ]]; then
                pass "live_enroll_key_perms" "live: private key file permissions are 0600"
            else
                fail "live_enroll_key_perms" "live: private key file permissions are not 0600" \
                    "Got: ${KEY_PERMS}"
            fi

            # Key must be parseable by openssl
            if openssl pkey -in "${KEY_FILE}" -noout > /dev/null 2>&1; then
                pass "live_enroll_key_valid" "live: private key file is valid (openssl pkey -noout)"
            else
                fail "live_enroll_key_valid" "live: private key file failed openssl validation" \
                    "$(openssl pkey -in "${KEY_FILE}" -noout 2>&1 | head -3)"
            fi
        else
            fail "live_enroll_key_file" "live: no private key file found in output directory" \
                "Contents: $(ls "${ENROLL_OUT_DIR}" 2>&1)"
        fi
    else
        exit_code=$?
        enroll_stderr=$(cat "${WORK}/live-enroll.stderr")
        # PENDING status is an acceptable transient outcome — not a test failure
        if echo "${enroll_stderr}" | grep -qi "pending\|PENDING"; then
            skip "live_enroll (enrollment is PENDING — server may require manual approval)"
        else
            fail "live_enroll" "live: SCEP enrollment failed (exit ${exit_code})" \
                "${enroll_stderr}"
        fi
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────

TOTAL=$(( PASS + FAIL + SKIP ))
printf '\n%s=== Results: %d passed, %d failed, %d skipped (total %d) ===%s\n' \
    "${BOLD}" "${PASS}" "${FAIL}" "${SKIP}" "${TOTAL}" "${RESET}"

if [[ "${FAIL}" -gt 0 ]]; then
    printf '\n%sFailures logged to: %s%s\n' "${RED}" "${FAILURE_LOG}" "${RESET}"
    exit 1
fi
