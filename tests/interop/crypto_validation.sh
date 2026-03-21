#!/usr/bin/env bash
# ============================================================================
# Crypto Validation Test Suite
#
# Generates PKI artifacts with the pki binary and cross-validates
# the actual crypto bytes using an independent reference tool.
#
# Usage: bash tests/interop/crypto_validation.sh [PKI_BINARY]
#   PKI_BINARY defaults to ./target/release/pki
# ============================================================================
set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

PKI="${1:-./target/release/pki}"
WORK=$(mktemp -d -t crypto-validation-XXXXXX)
FAILURE_LOG="${FAILURE_LOG:-/tmp/crypto-validation-failures.log}"

# Clear previous failures log
: > "${FAILURE_LOG}"

# ── Counters ──────────────────────────────────────────────────────────────────

PASS=0
FAIL=0

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
    # Suppress "unused variable" — test_id is reserved for structured output
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

# section TITLE
section() {
    printf '\n%s%s--- %s ---%s\n' "${BOLD}" "${CYAN}" "$1" "${RESET}"
}

# ── Pre-flight ────────────────────────────────────────────────────────────────

printf '%s=== PKI Client Crypto Validation ===%s\n' "${BOLD}" "${RESET}"

# Verify pki binary exists and is executable
if [[ ! -x "${PKI}" ]]; then
    printf '%sERROR:%s pki binary not found or not executable: %s\n' "${RED}" "${RESET}" "${PKI}"
    exit 2
fi

PKI_VERSION=$("${PKI}" --version 2>&1 | head -1 || echo "unknown")
OPENSSL_VERSION=$(openssl version 2>&1 | head -1 || echo "unknown")

printf "Binary:  %s (%s)\n" "${PKI}" "${PKI_VERSION}"
printf "OpenSSL: %s\n" "${OPENSSL_VERSION}"

# Verify openssl is available
if ! command -v openssl > /dev/null 2>&1; then
    printf '%sERROR:%s openssl not found in PATH\n' "${RED}" "${RESET}"
    exit 2
fi

# ── Category 1: Key Generation ────────────────────────────────────────────────

section "Key Generation"

# Helper: generate key, validate with openssl, check permissions
validate_key() {
    local algo="$1"         # e.g., rsa, ec, ed25519
    local extra_args="$2"   # extra pki args e.g., "--bits 2048"
    local key_file="$3"     # output path
    local ossl_pattern="$4" # grep pattern for openssl text output
    local test_prefix="$5"  # prefix for test IDs
    local display_name="$6" # human-readable name for output

    # Generate key
    # shellcheck disable=SC2086
    if "${PKI}" key gen "${algo}" ${extra_args} -o "${key_file}" > "${WORK}/keygen.stdout" 2> "${WORK}/keygen.stderr"; then
        pass "${test_prefix}_gen" "${display_name} key: generated successfully"
    else
        fail "${test_prefix}_gen" "${display_name} key: generation failed" "$(cat "${WORK}/keygen.stderr")"
        return
    fi

    # Validate PEM structure
    if openssl pkey -in "${key_file}" -noout > /dev/null 2>&1; then
        pass "${test_prefix}_pem" "${display_name} key: valid PEM (openssl pkey -noout)"
    else
        fail "${test_prefix}_pem" "${display_name} key: invalid PEM" "$(openssl pkey -in "${key_file}" -noout 2>&1)"
        return
    fi

    # Validate algorithm from openssl text output
    local ossl_text
    ossl_text=$(openssl pkey -in "${key_file}" -text -noout 2>&1)
    if echo "${ossl_text}" | grep -q "${ossl_pattern}"; then
        pass "${test_prefix}_algo" "${display_name} key: correct algorithm (${ossl_pattern})"
    else
        fail "${test_prefix}_algo" "${display_name} key: wrong algorithm" \
            "Expected pattern '${ossl_pattern}', openssl reported: $(echo "${ossl_text}" | head -3)"
    fi

    # Validate file permissions are 0600
    local perms
    perms=$(stat -c '%a' "${key_file}" 2>/dev/null || stat -f '%A' "${key_file}" 2>/dev/null || echo "unknown")
    if [[ "${perms}" == "600" ]]; then
        pass "${test_prefix}_perms" "${display_name} key: file permissions are 0600"
    else
        fail "${test_prefix}_perms" "${display_name} key: wrong file permissions" \
            "Expected 600, got ${perms}"
    fi
}

# RSA-2048
validate_key "rsa" "--bits 2048" \
    "${WORK}/key-rsa2048.pem" \
    "Private-Key: (2048 bit" \
    "key_gen_rsa_2048" \
    "RSA-2048"

# RSA-4096
validate_key "rsa" "--bits 4096" \
    "${WORK}/key-rsa4096.pem" \
    "Private-Key: (4096 bit" \
    "key_gen_rsa_4096" \
    "RSA-4096"

# EC P-256
validate_key "ec" "--curve p256" \
    "${WORK}/key-ec256.pem" \
    "ASN1 OID: prime256v1" \
    "key_gen_ec_p256" \
    "EC P-256"

# EC P-384
validate_key "ec" "--curve p384" \
    "${WORK}/key-ec384.pem" \
    "ASN1 OID: secp384r1" \
    "key_gen_ec_p384" \
    "EC P-384"

# Ed25519 — skip if not supported (spork-core limitation)
if "${PKI}" key gen ed25519 -o "${WORK}/key-ed25519.pem" > /dev/null 2>&1; then
    ossl_text=$(openssl pkey -in "${WORK}/key-ed25519.pem" -text -noout 2>&1)
    if echo "${ossl_text}" | grep -q "ED25519"; then
        pass "key_gen_ed25519" "Ed25519 key: valid, correct algorithm"
    else
        fail "key_gen_ed25519" "Ed25519 key: wrong algorithm" \
            "Expected 'ED25519', openssl reported: $(echo "${ossl_text}" | head -3)"
    fi
    perms=$(stat -c '%a' "${WORK}/key-ed25519.pem" 2>/dev/null || echo "unknown")
    if [[ "${perms}" == "600" ]]; then
        pass "key_gen_ed25519_perms" "Ed25519 key: file permissions are 0600"
    else
        fail "key_gen_ed25519_perms" "Ed25519 key: wrong permissions" "Expected 600, got ${perms}"
    fi
else
    printf "  ${YELLOW}[SKIP]${RESET} Ed25519 key: not yet supported in this build\n"
fi

# ── Category 2: CSR Validation ────────────────────────────────────────────────

section "CSR Validation"

# Helper: create CSR from existing key, validate with openssl
validate_csr() {
    local key_file="$1"
    local cn="$2"
    local san="$3"
    local csr_file="$4"
    local algo_pattern="$5"  # grep pattern in openssl req -text output
    local test_prefix="$6"
    local display_name="$7"

    # Skip if key file does not exist (its generation may have failed)
    if [[ ! -f "${key_file}" ]]; then
        printf "  ${YELLOW}[SKIP]${RESET} %s CSR: key file missing, skipping\n" "${display_name}"
        return
    fi

    # Create CSR
    if "${PKI}" csr create --key "${key_file}" \
        --cn "${cn}" \
        --san "${san}" \
        -o "${csr_file}" > "${WORK}/csr.stdout" 2> "${WORK}/csr.stderr"; then
        pass "${test_prefix}_create" "${display_name} CSR: created"
    else
        fail "${test_prefix}_create" "${display_name} CSR: creation failed" "$(cat "${WORK}/csr.stderr")"
        return
    fi

    # Verify CSR signature with openssl
    local verify_out
    if verify_out=$(openssl req -in "${csr_file}" -noout -verify 2>&1); then
        if echo "${verify_out}" | grep -q "verify OK"; then
            pass "${test_prefix}_verify" "${display_name} CSR: self-signature verified (openssl req -verify)"
        else
            fail "${test_prefix}_verify" "${display_name} CSR: openssl verify did not confirm OK" "${verify_out}"
        fi
    else
        fail "${test_prefix}_verify" "${display_name} CSR: openssl verify failed" "${verify_out}"
    fi

    # Verify subject CN (OpenSSL 3.0 uses "CN = X", 3.2+ uses "CN=X")
    local subject_out
    subject_out=$(openssl req -in "${csr_file}" -noout -subject 2>&1)
    if echo "${subject_out}" | grep -qE "CN\s*=\s*${cn}"; then
        pass "${test_prefix}_cn" "${display_name} CSR: correct subject CN"
    else
        fail "${test_prefix}_cn" "${display_name} CSR: wrong subject CN" \
            "Expected 'CN = ${cn}', got: ${subject_out}"
    fi

    # Verify key algorithm in openssl text
    local text_out
    text_out=$(openssl req -in "${csr_file}" -noout -text 2>&1)
    if echo "${text_out}" | grep -q "${algo_pattern}"; then
        pass "${test_prefix}_keyalgo" "${display_name} CSR: correct key algorithm (${algo_pattern})"
    else
        fail "${test_prefix}_keyalgo" "${display_name} CSR: wrong key algorithm" \
            "Expected '${algo_pattern}' in openssl req text"
    fi
}

validate_csr \
    "${WORK}/key-rsa2048.pem" \
    "Test RSA-2048" \
    "dns:test.example.com" \
    "${WORK}/csr-rsa2048.pem" \
    "rsaEncryption" \
    "csr_rsa2048" \
    "RSA-2048"

validate_csr \
    "${WORK}/key-rsa4096.pem" \
    "Test RSA-4096" \
    "dns:test.example.com" \
    "${WORK}/csr-rsa4096.pem" \
    "rsaEncryption" \
    "csr_rsa4096" \
    "RSA-4096"

validate_csr \
    "${WORK}/key-ec256.pem" \
    "Test EC P-256" \
    "dns:test.example.com" \
    "${WORK}/csr-ec256.pem" \
    "id-ecPublicKey\|EC Public Key\|ecPublicKey\|prime256v1\|Public Key Algorithm: id-ecPublicKey" \
    "csr_ec256" \
    "EC P-256"

validate_csr \
    "${WORK}/key-ec384.pem" \
    "Test EC P-384" \
    "dns:test.example.com" \
    "${WORK}/csr-ec384.pem" \
    "id-ecPublicKey\|EC Public Key\|ecPublicKey\|secp384r1\|Public Key Algorithm: id-ecPublicKey" \
    "csr_ec384" \
    "EC P-384"

# Verify RSA-4096 CSR bit size from openssl text
if [[ -f "${WORK}/csr-rsa4096.pem" ]]; then
    rsa4096_text=$(openssl req -in "${WORK}/csr-rsa4096.pem" -noout -text 2>&1)
    if echo "${rsa4096_text}" | grep -q "Public-Key: (4096 bit)"; then
        pass "csr_rsa4096_bits" "RSA-4096 CSR: correct key size (4096 bit)"
    else
        fail "csr_rsa4096_bits" "RSA-4096 CSR: wrong key size in openssl text" \
            "Expected 'Public-Key: (4096 bit)'"
    fi
fi

# ── Category 3: CA Hierarchy Issuance ─────────────────────────────────────────

section "CA Hierarchy"

HIER_TOML="${WORK}/hierarchy.toml"
HIER_OUT="${WORK}/pki-output"

cat > "${HIER_TOML}" << 'TOMLEOF'
[hierarchy]
name = "crypto-validation-test"
output_dir = "HIER_OUT_PLACEHOLDER"

[hierarchy.defaults]
organization = "Crypto Validation Test"
country = "US"

[[ca]]
id = "root"
type = "root"
algorithm = "rsa-4096"
common_name = "Crypto Validation Root CA"
validity_years = 20
path_length = 2

[[ca]]
id = "intermediate"
type = "intermediate"
parent = "root"
algorithm = "ecdsa-p384"
common_name = "Crypto Validation Intermediate CA"
validity_years = 10
path_length = 1

[[ca]]
id = "issuing"
type = "intermediate"
parent = "intermediate"
algorithm = "ecdsa-p256"
common_name = "Crypto Validation Issuing CA"
validity_years = 5
path_length = 0
TOMLEOF

# Substitute actual output path (sed-safe: use | as delimiter)
sed -i "s|HIER_OUT_PLACEHOLDER|${HIER_OUT}|g" "${HIER_TOML}"

# Build hierarchy
if "${PKI}" pki build "${HIER_TOML}" --force > "${WORK}/hier.stdout" 2> "${WORK}/hier.stderr"; then
    pass "hier_build" "3-tier hierarchy built (Root RSA-4096 -> Intermediate EC P-384 -> Issuing EC P-256)"
else
    fail "hier_build" "3-tier hierarchy build failed" "$(cat "${WORK}/hier.stderr")"
    # Cannot continue hierarchy tests without output
    printf "  ${YELLOW}Skipping all CA hierarchy sub-tests (build failed)${RESET}\n"
fi

# Proceed only if hierarchy output exists
ROOT_CERT="${HIER_OUT}/root/root.cert.pem"
INT_CERT="${HIER_OUT}/intermediate/intermediate.cert.pem"
ISS_CERT="${HIER_OUT}/issuing/issuing.cert.pem"

if [[ -f "${ROOT_CERT}" ]]; then

    # Root cert: self-signed
    root_verify=$(openssl verify -CAfile "${ROOT_CERT}" "${ROOT_CERT}" 2>&1)
    if echo "${root_verify}" | grep -q ": OK"; then
        pass "hier_root_self_signed" "Root cert: verified as self-signed (openssl verify)"
    else
        fail "hier_root_self_signed" "Root cert: failed self-signed verification" "${root_verify}"
    fi

    # Root cert: Basic Constraints CA:TRUE
    root_text=$(openssl x509 -in "${ROOT_CERT}" -noout -text 2>&1)
    if echo "${root_text}" | grep -q "CA:TRUE"; then
        pass "hier_root_ca_true" "Root cert: Basic Constraints CA:TRUE"
    else
        fail "hier_root_ca_true" "Root cert: missing Basic Constraints CA:TRUE" ""
    fi

    # Root cert: RSA signature algorithm
    if echo "${root_text}" | grep -q "sha256WithRSAEncryption\|sha384WithRSAEncryption\|sha512WithRSAEncryption"; then
        pass "hier_root_algo" "Root cert: RSA signature algorithm"
    else
        fail "hier_root_algo" "Root cert: expected RSA signature algorithm" \
            "$(echo "${root_text}" | grep -i "Signature Algorithm" | head -2)"
    fi

    # Root cert: subject contains expected CN
    if echo "${root_text}" | grep -qE "CN\s*=\s*Crypto Validation Root CA"; then
        pass "hier_root_subject" "Root cert: correct subject CN"
    else
        fail "hier_root_subject" "Root cert: wrong subject CN" \
            "$(openssl x509 -in "${ROOT_CERT}" -noout -subject 2>&1)"
    fi

fi

if [[ -f "${INT_CERT}" ]]; then

    # Intermediate chains to root
    int_verify=$(openssl verify -CAfile "${ROOT_CERT}" "${INT_CERT}" 2>&1)
    if echo "${int_verify}" | grep -q ": OK"; then
        pass "hier_int_chains" "Intermediate cert: chains to root (openssl verify)"
    else
        fail "hier_int_chains" "Intermediate cert: chain verification failed" "${int_verify}"
    fi

    # Intermediate: CA:TRUE
    int_text=$(openssl x509 -in "${INT_CERT}" -noout -text 2>&1)
    if echo "${int_text}" | grep -q "CA:TRUE"; then
        pass "hier_int_ca_true" "Intermediate cert: Basic Constraints CA:TRUE"
    else
        fail "hier_int_ca_true" "Intermediate cert: missing Basic Constraints CA:TRUE" ""
    fi

    # Intermediate: pathlen:1
    if echo "${int_text}" | grep -q "pathlen:1"; then
        pass "hier_int_pathlen" "Intermediate cert: pathlen:1"
    else
        fail "hier_int_pathlen" "Intermediate cert: expected pathlen:1" \
            "$(echo "${int_text}" | grep -i "pathlen" | head -2)"
    fi

    # Intermediate: uses EC P-384 public key
    if echo "${int_text}" | grep -q "secp384r1"; then
        pass "hier_int_ec384" "Intermediate cert: public key is EC P-384 (secp384r1)"
    else
        fail "hier_int_ec384" "Intermediate cert: expected EC P-384 (secp384r1)" \
            "$(echo "${int_text}" | grep -i "ASN1 OID\|Public Key Algorithm" | head -3)"
    fi

    # Intermediate: subject contains expected CN
    if echo "${int_text}" | grep -qE "CN\s*=\s*Crypto Validation Intermediate CA"; then
        pass "hier_int_subject" "Intermediate cert: correct subject CN"
    else
        fail "hier_int_subject" "Intermediate cert: wrong subject CN" \
            "$(openssl x509 -in "${INT_CERT}" -noout -subject 2>&1)"
    fi

fi

if [[ -f "${ISS_CERT}" ]]; then

    # Issuing chains through intermediate to root
    iss_verify=$(openssl verify -CAfile "${ROOT_CERT}" -untrusted "${INT_CERT}" "${ISS_CERT}" 2>&1)
    if echo "${iss_verify}" | grep -q ": OK"; then
        pass "hier_iss_chains" "Issuing cert: chains through intermediate to root (openssl verify)"
    else
        fail "hier_iss_chains" "Issuing cert: full chain verification failed" "${iss_verify}"
    fi

    # Issuing: CA:TRUE
    iss_text=$(openssl x509 -in "${ISS_CERT}" -noout -text 2>&1)
    if echo "${iss_text}" | grep -q "CA:TRUE"; then
        pass "hier_iss_ca_true" "Issuing cert: Basic Constraints CA:TRUE"
    else
        fail "hier_iss_ca_true" "Issuing cert: missing Basic Constraints CA:TRUE" ""
    fi

    # Issuing: pathlen:0
    if echo "${iss_text}" | grep -q "pathlen:0"; then
        pass "hier_iss_pathlen" "Issuing cert: pathlen:0"
    else
        fail "hier_iss_pathlen" "Issuing cert: expected pathlen:0" \
            "$(echo "${iss_text}" | grep -i "pathlen" | head -2)"
    fi

    # Issuing: uses EC P-256 public key
    if echo "${iss_text}" | grep -q "prime256v1"; then
        pass "hier_iss_ec256" "Issuing cert: public key is EC P-256 (prime256v1)"
    else
        fail "hier_iss_ec256" "Issuing cert: expected EC P-256 (prime256v1)" \
            "$(echo "${iss_text}" | grep -i "ASN1 OID\|Public Key Algorithm" | head -3)"
    fi

    # Issuing: subject contains expected CN
    if echo "${iss_text}" | grep -qE "CN\s*=\s*Crypto Validation Issuing CA"; then
        pass "hier_iss_subject" "Issuing cert: correct subject CN"
    else
        fail "hier_iss_subject" "Issuing cert: wrong subject CN" \
            "$(openssl x509 -in "${ISS_CERT}" -noout -subject 2>&1)"
    fi

    # Full chain: issuing signed by ecdsa-with-SHA384 (intermediate's algo)
    if echo "${iss_text}" | grep -q "ecdsa-with-SHA384\|ecdsa-with-SHA256"; then
        pass "hier_iss_sig_algo" "Issuing cert: EC-based signature algorithm"
    else
        fail "hier_iss_sig_algo" "Issuing cert: expected EC-based signature algorithm" \
            "$(echo "${iss_text}" | grep -i "Signature Algorithm" | head -2)"
    fi

fi

# ── Category 4: pki show Cross-Validation ─────────────────────────────────────

section "Cross-Validation (pki show vs openssl)"

# Cross-validate key size: pki show must agree with openssl
crossval_key_size() {
    local key_file="$1"
    local expected_bits="$2"
    local test_id="$3"
    local display_name="$4"

    if [[ ! -f "${key_file}" ]]; then
        printf "  ${YELLOW}[SKIP]${RESET} %s: key file missing\n" "${display_name}"
        return
    fi

    # openssl reports key size
    local ossl_text
    ossl_text=$(openssl pkey -in "${key_file}" -text -noout 2>&1)
    local ossl_bits
    ossl_bits=$(echo "${ossl_text}" | grep -oE 'Private-Key: \([0-9]+ bit' | grep -oE '[0-9]+' | head -1 || true)

    # pki show reports key size
    local pki_out
    pki_out=$("${PKI}" show "${key_file}" 2>&1 || true)
    local pki_bits
    pki_bits=$(echo "${pki_out}" | grep -oE '[0-9]+ bits' | grep -oE '[0-9]+' | head -1 || true)

    # Both must agree with the expected size
    if [[ "${ossl_bits}" == "${expected_bits}" ]]; then
        pass "${test_id}_ossl_size" "${display_name}: openssl confirms ${expected_bits}-bit key"
    else
        fail "${test_id}_ossl_size" "${display_name}: openssl key size mismatch" \
            "Expected ${expected_bits}, openssl reported ${ossl_bits}"
    fi

    if [[ "${pki_bits}" == "${expected_bits}" ]]; then
        pass "${test_id}_pki_size" "${display_name}: pki show reports ${expected_bits} bits"
    else
        fail "${test_id}_pki_size" "${display_name}: pki show key size mismatch" \
            "Expected ${expected_bits} bits, pki show reported '${pki_bits}'"
    fi
}

crossval_key_size "${WORK}/key-rsa2048.pem" "2048" "xval_rsa2048" "RSA-2048 key size"
crossval_key_size "${WORK}/key-rsa4096.pem" "4096" "xval_rsa4096" "RSA-4096 key size"

# EC keys: openssl does not report bit size in "Private-Key" line; validate algorithm text instead
crossval_ec_key() {
    local key_file="$1"
    local ossl_pattern="$2"
    local pki_pattern="$3"
    local test_id="$4"
    local display_name="$5"

    if [[ ! -f "${key_file}" ]]; then
        printf "  ${YELLOW}[SKIP]${RESET} %s: key file missing\n" "${display_name}"
        return
    fi

    local ossl_text
    ossl_text=$(openssl pkey -in "${key_file}" -text -noout 2>&1 || true)
    if echo "${ossl_text}" | grep -q "${ossl_pattern}"; then
        pass "${test_id}_ossl" "${display_name}: openssl confirms correct EC curve"
    else
        fail "${test_id}_ossl" "${display_name}: openssl EC curve mismatch" \
            "Expected '${ossl_pattern}' in openssl output"
    fi

    local pki_out
    pki_out=$("${PKI}" show "${key_file}" 2>&1 || true)
    if echo "${pki_out}" | grep -q "${pki_pattern}"; then
        pass "${test_id}_pki" "${display_name}: pki show reports correct algorithm"
    else
        fail "${test_id}_pki" "${display_name}: pki show algorithm mismatch" \
            "Expected '${pki_pattern}' in pki show output"
    fi
}

crossval_ec_key "${WORK}/key-ec256.pem" "prime256v1" "EC P-256" "xval_ec256" "EC P-256 key algo"
crossval_ec_key "${WORK}/key-ec384.pem" "secp384r1" "EC P-384" "xval_ec384" "EC P-384 key algo"

# Cross-validate CA cert subjects: pki show CN must match openssl
crossval_cert_cn() {
    local cert_file="$1"
    local expected_cn="$2"
    local test_id="$3"
    local display_name="$4"

    if [[ ! -f "${cert_file}" ]]; then
        printf "  ${YELLOW}[SKIP]${RESET} %s: cert file missing\n" "${display_name}"
        return
    fi

    # openssl subject
    local ossl_sub
    ossl_sub=$(openssl x509 -in "${cert_file}" -noout -subject 2>&1 || true)
    if echo "${ossl_sub}" | grep -qE "CN\s*=\s*${expected_cn}"; then
        pass "${test_id}_ossl" "${display_name}: openssl confirms subject CN"
    else
        fail "${test_id}_ossl" "${display_name}: openssl subject CN mismatch" \
            "Expected 'CN = ${expected_cn}', got: ${ossl_sub}"
    fi

    # pki show subject
    local pki_out
    pki_out=$("${PKI}" show "${cert_file}" 2>&1 || true)
    if echo "${pki_out}" | grep -q "${expected_cn}"; then
        pass "${test_id}_pki" "${display_name}: pki show reports correct CN"
    else
        fail "${test_id}_pki" "${display_name}: pki show CN mismatch" \
            "Expected '${expected_cn}' in pki show output"
    fi
}

crossval_cert_cn "${ROOT_CERT}" \
    "Crypto Validation Root CA" \
    "xval_root_cn" \
    "Root cert subject CN"

crossval_cert_cn "${INT_CERT}" \
    "Crypto Validation Intermediate CA" \
    "xval_int_cn" \
    "Intermediate cert subject CN"

crossval_cert_cn "${ISS_CERT}" \
    "Crypto Validation Issuing CA" \
    "xval_iss_cn" \
    "Issuing cert subject CN"

# ── Category 5: pki diff Validation ───────────────────────────────────────────

section "pki diff Validation"

# Two different certs must show differences
if [[ -f "${ROOT_CERT}" ]] && [[ -f "${ISS_CERT}" ]]; then
    diff_out=$("${PKI}" diff "${ROOT_CERT}" "${ISS_CERT}" 2>&1 || true)
    if echo "${diff_out}" | grep -q "DIFFERS\|differs\|differ"; then
        pass "diff_different" "pki diff: shows differences between root and issuing certs"
    else
        fail "diff_different" "pki diff: expected DIFFERS between root and issuing certs" \
            "$(echo "${diff_out}" | head -5)"
    fi
else
    printf "  ${YELLOW}[SKIP]${RESET} pki diff (different certs): hierarchy certs missing\n"
fi

# Same cert vs itself must show no differences (all MATCH)
if [[ -f "${ROOT_CERT}" ]]; then
    same_out=$("${PKI}" diff "${ROOT_CERT}" "${ROOT_CERT}" 2>&1 || true)
    # Should NOT contain DIFFERS
    if echo "${same_out}" | grep -q "DIFFERS\|differs\|differ"; then
        fail "diff_same" "pki diff: cert vs itself shows unexpected DIFFERS" \
            "$(echo "${same_out}" | head -5)"
    else
        pass "diff_same" "pki diff: cert vs itself shows no differences"
    fi
else
    printf "  ${YELLOW}[SKIP]${RESET} pki diff (same cert): root cert missing\n"
fi

# CSR diff: two different CSRs should show differences
if [[ -f "${WORK}/csr-rsa4096.pem" ]] && [[ -f "${WORK}/csr-ec256.pem" ]]; then
    csr_diff_out=$("${PKI}" diff "${WORK}/csr-rsa4096.pem" "${WORK}/csr-ec256.pem" 2>&1 || true)
    if echo "${csr_diff_out}" | grep -q "DIFFERS\|differs\|differ"; then
        pass "diff_csr_different" "pki diff: shows differences between RSA and EC CSRs"
    else
        fail "diff_csr_different" "pki diff: expected differences between RSA and EC CSRs" \
            "$(echo "${csr_diff_out}" | head -5)"
    fi
else
    printf "  ${YELLOW}[SKIP]${RESET} pki diff (CSRs): CSR files missing\n"
fi

# ── Category 6: Format Conversion ─────────────────────────────────────────────

section "Format Conversion"

# Convert cert PEM -> DER -> PEM and verify fingerprints match at each step
convert_cert_roundtrip() {
    local cert_file="$1"
    local test_id="$2"
    local display_name="$3"

    if [[ ! -f "${cert_file}" ]]; then
        printf "  ${YELLOW}[SKIP]${RESET} %s format conversion: cert missing\n" "${display_name}"
        return
    fi

    local der_file="${WORK}/${test_id}.der"
    local rt_pem_file="${WORK}/${test_id}-rt.pem"

    # Get original fingerprint
    local orig_fp
    orig_fp=$(openssl x509 -in "${cert_file}" -fingerprint -sha256 -noout 2>&1 \
        | grep -oE 'Fingerprint=[A-F0-9:]+' | cut -d= -f2 || true)

    # Convert PEM -> DER
    if "${PKI}" convert "${cert_file}" --to der -o "${der_file}" > /dev/null 2>&1; then
        pass "${test_id}_to_der" "${display_name}: PEM to DER conversion succeeded"
    else
        fail "${test_id}_to_der" "${display_name}: PEM to DER conversion failed" ""
        return
    fi

    # Verify DER is non-empty and is parseable by openssl
    if openssl x509 -in "${der_file}" -inform DER -noout > /dev/null 2>&1; then
        pass "${test_id}_der_valid" "${display_name}: DER file is valid (openssl x509 -inform DER)"
    else
        fail "${test_id}_der_valid" "${display_name}: DER file not parseable by openssl" ""
        return
    fi

    # DER fingerprint must match original
    local der_fp
    der_fp=$(openssl x509 -in "${der_file}" -inform DER -fingerprint -sha256 -noout 2>&1 \
        | grep -oE 'Fingerprint=[A-F0-9:]+' | cut -d= -f2 || true)
    if [[ "${orig_fp}" == "${der_fp}" ]]; then
        pass "${test_id}_der_fp" "${display_name}: DER fingerprint matches original PEM"
    else
        fail "${test_id}_der_fp" "${display_name}: DER fingerprint mismatch" \
            "PEM: ${orig_fp}  DER: ${der_fp}"
    fi

    # Convert DER -> PEM
    if "${PKI}" convert "${der_file}" --from cert --to pem -o "${rt_pem_file}" > /dev/null 2>&1; then
        pass "${test_id}_to_pem" "${display_name}: DER to PEM round-trip conversion succeeded"
    else
        fail "${test_id}_to_pem" "${display_name}: DER to PEM conversion failed" ""
        return
    fi

    # Round-tripped PEM fingerprint must match original
    local rt_fp
    rt_fp=$(openssl x509 -in "${rt_pem_file}" -fingerprint -sha256 -noout 2>&1 \
        | grep -oE 'Fingerprint=[A-F0-9:]+' | cut -d= -f2 || true)
    if [[ "${orig_fp}" == "${rt_fp}" ]]; then
        pass "${test_id}_rt_fp" "${display_name}: round-tripped PEM fingerprint matches original"
    else
        fail "${test_id}_rt_fp" "${display_name}: round-tripped PEM fingerprint mismatch" \
            "Original: ${orig_fp}  Round-trip: ${rt_fp}"
    fi
}

convert_cert_roundtrip "${ROOT_CERT}" "conv_root" "Root cert"
convert_cert_roundtrip "${INT_CERT}" "conv_int" "Intermediate cert"
convert_cert_roundtrip "${ISS_CERT}" "conv_iss" "Issuing cert"

# ── Category 7: DER CSR Auto-Detection (#24) ─────────────────────────────────

section "DER CSR Auto-Detection"

if [[ -f "${WORK}/csr-rsa2048.pem" ]]; then
    der_csr="${WORK}/csr-rsa2048.der"
    if "${PKI}" convert "${WORK}/csr-rsa2048.pem" --to der -o "${der_csr}" > /dev/null 2>&1; then
        pass "der_csr_convert" "CSR PEM to DER conversion succeeded"

        # pki show should auto-detect DER CSR (regression test for #24)
        show_out=$("${PKI}" show "${der_csr}" 2>&1 || true)
        if echo "${show_out}" | grep -qiE "CSR|Request|Subject"; then
            pass "der_csr_autodetect" "pki show auto-detected DER CSR"
        else
            fail "der_csr_autodetect" "pki show did not auto-detect DER CSR (#24)" \
                "$(echo "${show_out}" | head -3)"
        fi

        # pki csr show must always work for DER CSRs
        explicit_out=$("${PKI}" csr show "${der_csr}" 2>&1 || true)
        if echo "${explicit_out}" | grep -qiE "Subject|CN"; then
            pass "der_csr_explicit" "pki csr show handles DER CSR"
        else
            fail "der_csr_explicit" "pki csr show failed on DER CSR" \
                "$(echo "${explicit_out}" | head -3)"
        fi
    else
        fail "der_csr_convert" "CSR PEM to DER conversion failed" ""
    fi
fi

# ── Category 8: Key Match CSR Handling (#25) ──────────────────────────────────

section "Key Match Error Handling"

if [[ -f "${WORK}/key-rsa2048.pem" ]] && [[ -f "${WORK}/csr-rsa2048.pem" ]]; then
    match_out=$("${PKI}" key match "${WORK}/key-rsa2048.pem" "${WORK}/csr-rsa2048.pem" 2>&1 || true)
    if echo "${match_out}" | grep -q "InvalidAlgorithmIdentifier"; then
        fail "key_match_csr" "key match crashes on CSR with InvalidAlgorithmIdentifier (#25)" \
            "Should give a clear error or support CSR files"
    else
        pass "key_match_csr" "key match handles CSR input without crashing"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────

TOTAL=$(( PASS + FAIL ))
printf "\n${BOLD}=== Results: %d passed, %d failed ===${RESET}\n" "${PASS}" "${FAIL}"

if [[ "${FAIL}" -gt 0 ]]; then
    printf "\n${RED}Failures logged to: %s${RESET}\n" "${FAILURE_LOG}"
    exit 1
fi
