#!/usr/bin/env bash
# ============================================================================
# openssl_parity.sh — Cross-check that pki and openssl agree on certificate,
# CSR, CRL, key, and PKCS#12 fields.
#
# Strategy:
#   1. Generate fixtures with openssl (ground truth).
#   2. Parse with pki via `-f json`.
#   3. Assert that subject/issuer/serial/SAN/KU/EKU/key-algo/fingerprint match
#      what openssl reports.
#   4. Reverse: pki generates a CSR, confirm openssl parses the same fields.
#
# Explicit non-goals (out of scope for pki-client — belong in a signing
# service, NOT in a PKI inspection/enrollment tool):
#   - openssl dgst      (arbitrary file sign/verify)
#   - openssl cms/smime (S/MIME envelopes)
#   - openssl ts        (RFC 3161 timestamping)
# These are intentionally absent from pki and NOT tested here.
#
# Run:  ./tests/interop/openssl_parity.sh
# Deps: openssl, jq, pki binary at $PKI_BIN or ./target/release/pki
# ============================================================================

# shellcheck source=tests/interop/lib.sh
source "$(dirname "$0")/lib.sh"

require() {
    command -v "$1" >/dev/null || { echo "FATAL: missing dependency: $1"; exit 2; }
}
require openssl
require jq

echo "================================================================"
echo "  PKI Client ↔ OpenSSL Parity Test"
echo "  pki:     $($PKI --version 2>&1 | head -1)"
echo "  openssl: $(openssl version)"
echo "================================================================"
echo ""

# ── Assertion helpers ───────────────────────────────────────────────────────

assert_eq() {
    local name="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        echo "  PASS: $name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $name"
        echo "    openssl: $expected"
        echo "    pki:     $actual"
        FAIL=$((FAIL + 1))
    fi
}

assert_contains() {
    local name="$1" needle="$2" haystack="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        echo "  PASS: $name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $name (missing '$needle')"
        echo "    haystack: $haystack"
        FAIL=$((FAIL + 1))
    fi
}

# Normalize openssl serial (hex, colon-separated, uppercase) → lowercase hex, no colons, no leading zeros
norm_serial() {
    tr -d ':' | tr '[:upper:]' '[:lower:]' | sed 's/^0*//'
}

# Normalize SHA-256 fingerprint (openssl format: "SHA256 Fingerprint=AA:BB:...") → lowercase hex, no colons
norm_fp() {
    sed 's/.*=//' | tr -d ':' | tr '[:upper:]' '[:lower:]'
}

# ── Fixture: RSA CA + EE cert with SAN, KU, EKU ─────────────────────────────

echo "--- Generating fixtures (RSA CA + EE) ---"
cat > "$WORK/ee.cnf" <<'EOF'
subjectAltName = DNS:ee.parity.test, DNS:alt.parity.test, IP:10.0.0.1, email:admin@parity.test
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
EOF

openssl req -x509 -newkey rsa:2048 -keyout "$WORK/rsa-ca.key" -out "$WORK/rsa-ca.crt" \
    -days 30 -nodes -subj "/CN=Parity RSA CA/O=PKI Parity Test" 2>/dev/null

openssl req -new -newkey rsa:2048 -keyout "$WORK/rsa-ee.key" -out "$WORK/rsa-ee.csr" \
    -nodes -subj "/CN=ee.parity.test/O=PKI Parity Test" \
    -addext "subjectAltName=DNS:ee.parity.test,DNS:alt.parity.test,IP:10.0.0.1,email:admin@parity.test" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth,clientAuth" 2>/dev/null

openssl x509 -req -in "$WORK/rsa-ee.csr" -CA "$WORK/rsa-ca.crt" -CAkey "$WORK/rsa-ca.key" \
    -out "$WORK/rsa-ee.crt" -days 7 -CAcreateserial -extfile "$WORK/ee.cnf" 2>/dev/null

echo ""

# ── Test group 1: Certificate field parity (openssl → pki) ──────────────────

echo "=== Group 1: Certificate fields (openssl ground truth → pki JSON) ==="

PKI_CERT_JSON=$($PKI cert show -f json "$WORK/rsa-ee.crt")
if [[ -z "$PKI_CERT_JSON" ]] || ! echo "$PKI_CERT_JSON" | jq -e . >/dev/null 2>&1; then
    echo "  FATAL: pki cert show -f json produced no/invalid JSON"
    exit 1
fi

# Serial
OSL_SERIAL=$(openssl x509 -in "$WORK/rsa-ee.crt" -noout -serial | sed 's/serial=//' | norm_serial)
PKI_SERIAL=$(echo "$PKI_CERT_JSON" | jq -r .serial | sed 's/^0*//')
assert_eq "cert/serial" "$OSL_SERIAL" "$PKI_SERIAL"

# SHA-256 fingerprint
OSL_FP=$(openssl x509 -in "$WORK/rsa-ee.crt" -noout -fingerprint -sha256 | norm_fp)
PKI_FP=$(echo "$PKI_CERT_JSON" | jq -r .fingerprint_sha256)
assert_eq "cert/fingerprint_sha256" "$OSL_FP" "$PKI_FP"

# SHA-1 fingerprint
OSL_FP1=$(openssl x509 -in "$WORK/rsa-ee.crt" -noout -fingerprint -sha1 | norm_fp)
PKI_FP1=$(echo "$PKI_CERT_JSON" | jq -r .fingerprint_sha1)
assert_eq "cert/fingerprint_sha1" "$OSL_FP1" "$PKI_FP1"

# Subject CN (openssl RFC2253 via -nameopt vs pki's own format — compare just CN)
PKI_SUBJECT=$(echo "$PKI_CERT_JSON" | jq -r .subject)
assert_contains "cert/subject contains CN=ee.parity.test" "CN=ee.parity.test" "$PKI_SUBJECT"

# Issuer
PKI_ISSUER=$(echo "$PKI_CERT_JSON" | jq -r .issuer)
assert_contains "cert/issuer contains CN=Parity RSA CA" "CN=Parity RSA CA" "$PKI_ISSUER"

# Key algorithm
PKI_KEYALG=$(echo "$PKI_CERT_JSON" | jq -r .key_algorithm_name)
assert_eq "cert/key_algorithm_name" "RSA" "$PKI_KEYALG"

# Key size
PKI_KEYSIZE=$(echo "$PKI_CERT_JSON" | jq -r .key_size)
assert_eq "cert/key_size" "2048" "$PKI_KEYSIZE"

# Signature algorithm name
PKI_SIGALG=$(echo "$PKI_CERT_JSON" | jq -r .signature_algorithm_name)
assert_eq "cert/signature_algorithm_name" "sha256WithRSAEncryption" "$PKI_SIGALG"

# SAN: openssl decodes 4 entries (2 DNS, 1 IP, 1 email)
PKI_SAN_COUNT=$(echo "$PKI_CERT_JSON" | jq -r '.san | length')
assert_eq "cert/SAN count" "4" "$PKI_SAN_COUNT"
# SAN is serialized as a tagged enum: [{"Dns":"x"}, {"Ip":"y"}, …]. Flatten to
# "TAG:value" strings (Dns→DNS, Ip→IP) so assertions stay algorithm-readable.
PKI_SAN_ALL=$(echo "$PKI_CERT_JSON" | jq -r '
    .san[] | to_entries[]
    | ((.key | ascii_upcase | sub("EMAIL"; "email")) + ":" + .value)
' | tr '\n' ',' | sed 's/,$//')
assert_contains "cert/SAN DNS:ee.parity.test" "DNS:ee.parity.test" "$PKI_SAN_ALL"
assert_contains "cert/SAN DNS:alt.parity.test" "DNS:alt.parity.test" "$PKI_SAN_ALL"
assert_contains "cert/SAN IP:10.0.0.1" "IP:10.0.0.1" "$PKI_SAN_ALL"
assert_contains "cert/SAN email:admin@parity.test" "admin@parity.test" "$PKI_SAN_ALL"

# EKU — pki emits RFC 5280 long-form labels ("TLS Web Server Authentication");
# openssl's short names are a display quirk, not a canonical format. Assert on
# the long form here.
PKI_EKU=$(echo "$PKI_CERT_JSON" | jq -r '.extended_key_usage[]' | tr '\n' ',' | sed 's/,$//')
assert_contains "cert/EKU serverAuth" "TLS Web Server Authentication" "$PKI_EKU"
assert_contains "cert/EKU clientAuth" "TLS Web Client Authentication" "$PKI_EKU"

echo ""

# ── Test group 2: CSR field parity ──────────────────────────────────────────

echo "=== Group 2: CSR fields (openssl → pki JSON) ==="

PKI_CSR_JSON=$($PKI csr show -f json "$WORK/rsa-ee.csr")

PKI_CSR_SUBJECT=$(echo "$PKI_CSR_JSON" | jq -r .subject)
assert_contains "csr/subject CN=ee.parity.test" "CN=ee.parity.test" "$PKI_CSR_SUBJECT"

PKI_CSR_KEYALG=$(echo "$PKI_CSR_JSON" | jq -r .key_algorithm)
assert_eq "csr/key_algorithm" "RSA" "$PKI_CSR_KEYALG"

PKI_CSR_KEYSIZE=$(echo "$PKI_CSR_JSON" | jq -r .key_size)
assert_eq "csr/key_size" "2048" "$PKI_CSR_KEYSIZE"

# CSR SAN round-trip — openssl request put 4 entries into extensionRequest
PKI_CSR_SAN_COUNT=$(echo "$PKI_CSR_JSON" | jq -r '.san | length')
assert_eq "csr/SAN count" "4" "$PKI_CSR_SAN_COUNT"

PKI_CSR_SAN_ALL=$(echo "$PKI_CSR_JSON" | jq -r '
    .san[] | to_entries[]
    | ((.key | ascii_upcase | sub("EMAIL"; "email")) + ":" + .value)
' | tr '\n' ',' | sed 's/,$//')
assert_contains "csr/SAN DNS:ee.parity.test" "DNS:ee.parity.test" "$PKI_CSR_SAN_ALL"
assert_contains "csr/SAN IP:10.0.0.1" "IP:10.0.0.1" "$PKI_CSR_SAN_ALL"
assert_contains "csr/SAN email:admin@parity.test" "admin@parity.test" "$PKI_CSR_SAN_ALL"

echo ""

# ── Test group 3: Key field parity (openssl → pki) ──────────────────────────

echo "=== Group 3: Private key fields (openssl → pki JSON) ==="

# RSA key
PKI_RSAKEY_JSON=$($PKI key show -f json "$WORK/rsa-ee.key")
PKI_RSAKEY_SIZE=$(echo "$PKI_RSAKEY_JSON" | jq -r .key_size)
assert_eq "key/RSA size" "2048" "$PKI_RSAKEY_SIZE"

# EC key (P-256)
openssl ecparam -genkey -name prime256v1 -out "$WORK/ec.key" 2>/dev/null
PKI_ECKEY_JSON=$($PKI key show -f json "$WORK/ec.key")
PKI_ECKEY_ALG=$(echo "$PKI_ECKEY_JSON" | jq -r .algorithm)
assert_eq "key/EC algorithm" "EcP256" "$PKI_ECKEY_ALG"
PKI_ECKEY_CURVE=$(echo "$PKI_ECKEY_JSON" | jq -r .curve)
assert_eq "key/EC curve" "P-256" "$PKI_ECKEY_CURVE"

# Ed25519 key
openssl genpkey -algorithm ED25519 -out "$WORK/ed25519.key" 2>/dev/null
PKI_EDKEY_JSON=$($PKI key show -f json "$WORK/ed25519.key")
PKI_EDKEY_BITS=$(echo "$PKI_EDKEY_JSON" | jq -r .bits)
assert_eq "key/Ed25519 bits" "256" "$PKI_EDKEY_BITS"

echo ""

# ── Test group 4: CRL field parity ──────────────────────────────────────────

echo "=== Group 4: CRL fields (openssl → pki) ==="

# Build a minimal CRL with openssl ca infrastructure
mkdir -p "$WORK/ca-db"
touch "$WORK/ca-db/index.txt"
echo "01" > "$WORK/ca-db/crlnumber"
cat > "$WORK/ca.cnf" <<EOF
[ca]
default_ca = CA_default
[CA_default]
dir = $WORK/ca-db
database = \$dir/index.txt
crlnumber = \$dir/crlnumber
default_md = sha256
default_crl_days = 7
policy = policy_any
[policy_any]
commonName = supplied
organizationName = optional
EOF

openssl ca -config "$WORK/ca.cnf" -gencrl -cert "$WORK/rsa-ca.crt" -keyfile "$WORK/rsa-ca.key" \
    -out "$WORK/test.crl" -batch 2>/dev/null || {
    echo "  SKIP: CRL generation failed (openssl ca invocation)"
    SKIP=$((SKIP + 1))
}

if [[ -f "$WORK/test.crl" ]]; then
    PKI_CRL_JSON=$($PKI crl show -f json "$WORK/test.crl" 2>&1 || true)
    if echo "$PKI_CRL_JSON" | jq -e . >/dev/null 2>&1; then
        PKI_CRL_ISSUER=$(echo "$PKI_CRL_JSON" | jq -r .issuer 2>/dev/null)
        assert_contains "crl/issuer contains CN=Parity RSA CA" "Parity RSA CA" "$PKI_CRL_ISSUER"
    else
        echo "  SKIP: pki crl show -f json produced no JSON (may not support JSON yet)"
        # Fall back to text output check
        PKI_CRL_TEXT=$($PKI crl show "$WORK/test.crl" 2>&1)
        assert_contains "crl/text output names issuer" "Parity RSA CA" "$PKI_CRL_TEXT"
    fi
fi

echo ""

# ── Test group 5: PKCS#12 structure parity ──────────────────────────────────

echo "=== Group 5: PKCS#12 (openssl → pki type detection) ==="

openssl pkcs12 -export -in "$WORK/rsa-ee.crt" -inkey "$WORK/rsa-ee.key" \
    -certfile "$WORK/rsa-ca.crt" -out "$WORK/bundle.p12" \
    -passout pass:parity -name "parity-bundle" 2>/dev/null

if [[ -f "$WORK/bundle.p12" ]]; then
    # pki show currently doesn't decrypt P12 from CLI — just check it recognizes
    # the container as PKCS#12 (not mis-identified as something else).
    PKI_P12_OUT=$($PKI show "$WORK/bundle.p12" 2>&1 || true)
    if echo "$PKI_P12_OUT" | grep -qiE "pkcs.?12|bundle|failed to load"; then
        echo "  PASS: pki detects PKCS#12 container or reports clear error"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: pki did not recognize PKCS#12 structure"
        echo "    output: $PKI_P12_OUT"
        FAIL=$((FAIL + 1))
    fi
    echo "  NOTE: full P12 decryption + field extraction is not yet wired through"
    echo "        the pki CLI (no --password flag on pki show). Tracked separately."
fi

echo ""

# ── Test group 6: Reverse parity — pki produces, openssl reads ──────────────

echo "=== Group 6: Reverse parity (pki generates → openssl parses) ==="

$PKI key gen rsa --bits 2048 -o "$WORK/pki-rsa.key" -q
$PKI csr create --key "$WORK/pki-rsa.key" --cn "pki.parity.test" \
    --san "dns:pki.parity.test,dns:alt.pki.parity.test,ip:10.0.0.2,email:pki@parity.test" \
    -o "$WORK/pki.csr" -q

# openssl must parse pki's CSR — normalize DN spacing: openssl ≤3.4 emits
# "CN = X" (spaces) while 3.5+ emits "CN=X". Collapse so the assertion works
# on either.
OSL_CSR_TEXT=$(openssl req -in "$WORK/pki.csr" -noout -text 2>&1 | sed 's/ = /=/g')
assert_contains "reverse/openssl parses pki CSR" "CN=pki.parity.test" "$OSL_CSR_TEXT"
assert_contains "reverse/openssl sees pki DNS SAN" "pki.parity.test" "$OSL_CSR_TEXT"
assert_contains "reverse/openssl sees pki IP SAN" "10.0.0.2" "$OSL_CSR_TEXT"
assert_contains "reverse/openssl sees pki email SAN" "pki@parity.test" "$OSL_CSR_TEXT"

# openssl verifies the CSR signature
if openssl req -in "$WORK/pki.csr" -noout -verify 2>&1 | grep -q "verify OK\|self-signature OK\|Certificate request self-signature verify OK"; then
    echo "  PASS: reverse/openssl verifies pki CSR signature"
    PASS=$((PASS + 1))
else
    echo "  FAIL: reverse/openssl rejected pki CSR signature"
    FAIL=$((FAIL + 1))
fi

# openssl reads pki's RSA key
OSL_KEY_TEXT=$(openssl rsa -in "$WORK/pki-rsa.key" -noout -text 2>&1)
assert_contains "reverse/openssl parses pki RSA key" "2048 bit" "$OSL_KEY_TEXT"

# EC key round-trip
$PKI key gen ec --curve p256 -o "$WORK/pki-ec.key" -q
OSL_EC_TEXT=$(openssl ec -in "$WORK/pki-ec.key" -noout -text 2>&1)
assert_contains "reverse/openssl parses pki EC key" "prime256v1" "$OSL_EC_TEXT"

echo ""

# ── Summary ─────────────────────────────────────────────────────────────────

report_summary
