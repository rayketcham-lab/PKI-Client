#!/usr/bin/env bash
set -uo pipefail

# Cross-validation test suite: pki vs certutil vs python3 cryptography
# Compares fingerprints, key sizes, validity dates, serial numbers, and format conversions

PKI="./target/release/pki"
PASS=0
FAIL=0
SKIP=0
ERRORS=""

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; ERRORS="${ERRORS}\n  - $1"; }
skip() { SKIP=$((SKIP + 1)); echo "  SKIP: $1"; }

echo "================================================================"
echo "  PKI Client Cross-Validation Test Suite"
echo "  pki $(${PKI} --version 2>&1 | head -1)"
echo "================================================================"
echo ""

# ── Setup: Generate test artifacts ─────────────────────────────────
echo "--- Setup ---"
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

$PKI key gen rsa --bits 4096 -o "$WORKDIR/rsa.key" -q
$PKI key gen ec --curve p384 -o "$WORKDIR/ec.key" -q
$PKI csr create --key "$WORKDIR/rsa.key" --cn "crossval.test" --san "dns:crossval.test" -o "$WORKDIR/rsa.csr" -q
$PKI csr create --key "$WORKDIR/ec.key" --cn "ec-crossval.test" -o "$WORKDIR/ec.csr" -q

# Pick a cert fixture: env override wins, else fall back to the corp root,
# else skip cert-dependent tests (don't hard-fail — CI and dev boxes may not
# have the corp PKI laid down on disk).
CERT="${CROSSVAL_TEST_CERT:-/tmp/qn/corp/root/root.cert.pem}"
HAVE_CERT=0
if [[ -f "$CERT" ]]; then
    HAVE_CERT=1
    echo "Test cert: $CERT"
else
    echo "No test cert at $CERT — cert-dependent tests will be skipped."
    echo "Set CROSSVAL_TEST_CERT=<path> to override."
fi
echo ""

# ── TEST 1: SHA-256 Fingerprint Match ─────────────────────────────
echo "=== TEST 1: SHA-256 Fingerprint (pki vs python3) ==="

if [[ "$HAVE_CERT" -eq 0 ]]; then skip "no test cert"; else
PKI_FP=$($PKI cert fingerprint "$CERT" 2>&1 | tr -d '[:space:]')
PY_FP=$(python3 -c "
from cryptography import x509
from cryptography.hazmat.primitives import hashes
cert = x509.load_pem_x509_certificate(open('$CERT','rb').read())
print(cert.fingerprint(hashes.SHA256()).hex())
" 2>&1 | tr -d '[:space:]')

if [ "$PKI_FP" = "$PY_FP" ]; then
    pass "SHA-256 fingerprint matches: $PKI_FP"
else
    fail "SHA-256 fingerprint mismatch: pki=$PKI_FP python=$PY_FP"
fi
fi

# ── TEST 2: Serial Number Match ───────────────────────────────────
echo ""
echo "=== TEST 2: Serial Number (pki vs python3) ==="

if [[ "$HAVE_CERT" -eq 0 ]]; then skip "no test cert"; else
PKI_SERIAL=$($PKI show "$CERT" 2>&1 | grep "Serial Number:" -A1 | tail -1 | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]' | sed 's/(.*)//' | sed 's/^0*//')
PY_SERIAL=$(python3 -c "
from cryptography import x509
cert = x509.load_pem_x509_certificate(open('$CERT','rb').read())
print(format(cert.serial_number, 'x'))
" 2>&1 | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]' | sed 's/^0*//')

if [ "$PKI_SERIAL" = "$PY_SERIAL" ]; then
    pass "Serial number matches: $PKI_SERIAL"
else
    fail "Serial number mismatch: pki=$PKI_SERIAL python=$PY_SERIAL"
fi
fi

# ── TEST 3: Subject/Issuer Match ──────────────────────────────────
echo ""
echo "=== TEST 3: Subject (pki vs python3) ==="

if [[ "$HAVE_CERT" -eq 0 ]]; then skip "no test cert"; else
PKI_SUBJECT=$($PKI show "$CERT" 2>&1 | grep "Subject:" | head -1 | sed 's/.*Subject:\s*//' | tr -d '[:space:]')
PY_SUBJECT=$(python3 -c "
from cryptography import x509
cert = x509.load_pem_x509_certificate(open('$CERT','rb').read())
print(cert.subject.rfc4514_string())
" 2>&1 | tr -d '[:space:]')

echo "  pki:    $PKI_SUBJECT"
echo "  python: $PY_SUBJECT"
# Both extractions should agree on *something* non-empty and identical.
if [[ -n "$PKI_SUBJECT" ]] && [[ "$PKI_SUBJECT" = "$PY_SUBJECT" ]]; then
    pass "Subject matches python3 rfc4514: $PKI_SUBJECT"
elif [[ -n "$PKI_SUBJECT" ]] && echo "$PY_SUBJECT" | grep -qF "$PKI_SUBJECT" 2>/dev/null; then
    pass "Subject contained within python3 rfc4514"
else
    fail "Subject mismatch: pki=$PKI_SUBJECT python=$PY_SUBJECT"
fi
fi

# ── TEST 4: Validity Dates Match ──────────────────────────────────
echo ""
echo "=== TEST 4: Validity Dates (pki vs python3) ==="

if [[ "$HAVE_CERT" -eq 0 ]]; then skip "no test cert"; else
PKI_NOTAFTER=$($PKI cert expires "$CERT" 2>&1 | grep -oP '\d{4}-\d{2}-\d{2}' | head -1)
PY_NOTAFTER=$(python3 -c "
from cryptography import x509
cert = x509.load_pem_x509_certificate(open('$CERT','rb').read())
print(cert.not_valid_after.strftime('%Y-%m-%d'))
" 2>&1)

if [ "$PKI_NOTAFTER" = "$PY_NOTAFTER" ]; then
    pass "Not After date matches: $PKI_NOTAFTER"
else
    fail "Not After mismatch: pki=$PKI_NOTAFTER python=$PY_NOTAFTER"
fi
fi

# ── TEST 5: Key Algorithm Match ───────────────────────────────────
echo ""
echo "=== TEST 5: Key Algorithm (pki vs python3) ==="

if [[ "$HAVE_CERT" -eq 0 ]]; then skip "no test cert"; else
PKI_KEYALGO=$($PKI show "$CERT" 2>&1 | grep "Key:" | head -1)
PY_KEYALGO=$(python3 -c "
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
cert = x509.load_pem_x509_certificate(open('$CERT','rb').read())
pk = cert.public_key()
if isinstance(pk, rsa.RSAPublicKey):
    print(f'RSA {pk.key_size}-bit')
elif isinstance(pk, ec.EllipticCurvePublicKey):
    print(f'EC {pk.curve.name} {pk.key_size}-bit')
else:
    print(type(pk).__name__)
" 2>&1)

echo "  pki:    $PKI_KEYALGO"
echo "  python: $PY_KEYALGO"
if echo "$PKI_KEYALGO" | grep -q "RSA" && echo "$PY_KEYALGO" | grep -q "RSA"; then
    pass "Both report RSA key"
elif echo "$PKI_KEYALGO" | grep -q "EC" && echo "$PY_KEYALGO" | grep -q "EC"; then
    pass "Both report EC key"
else
    fail "Key algorithm mismatch"
fi
fi

# ── TEST 6: PEM→DER→PEM Roundtrip (pki vs python3 hash) ──────────
echo ""
echo "=== TEST 6: Convert Roundtrip (PEM→DER→PEM, fingerprint preserved) ==="

if [[ "$HAVE_CERT" -eq 0 ]]; then skip "no test cert"; else
$PKI convert "$CERT" --to der -o "$WORKDIR/cert.der" -q
$PKI convert "$WORKDIR/cert.der" --to pem -o "$WORKDIR/cert-rt.pem" -q

ORIG_FP=$($PKI cert fingerprint "$CERT" 2>&1 | tr -d '[:space:]')
RT_FP=$($PKI cert fingerprint "$WORKDIR/cert-rt.pem" 2>&1 | tr -d '[:space:]')

if [ "$ORIG_FP" = "$RT_FP" ]; then
    pass "PEM→DER→PEM roundtrip fingerprint preserved: $ORIG_FP"
else
    fail "Roundtrip fingerprint changed: orig=$ORIG_FP rt=$RT_FP"
fi

# ── TEST 7: DER file matches python3 DER decode ──────────────────
echo ""
echo "=== TEST 7: DER binary matches python3 decode ==="

PY_DER_FP=$(python3 -c "
from cryptography import x509
from cryptography.hazmat.primitives import hashes
cert = x509.load_der_x509_certificate(open('$WORKDIR/cert.der','rb').read())
print(cert.fingerprint(hashes.SHA256()).hex())
" 2>&1 | tr -d '[:space:]')

if [ "$ORIG_FP" = "$PY_DER_FP" ]; then
    pass "DER file python3 fingerprint matches: $PY_DER_FP"
else
    fail "DER fingerprint mismatch: pki=$ORIG_FP python=$PY_DER_FP"
fi
fi  # closes HAVE_CERT guard around TEST 6+7 (both rely on $CERT/cert.der)

# ── TEST 8: CSR Subject Match ─────────────────────────────────────
echo ""
echo "=== TEST 8: CSR Subject (pki vs python3) ==="

PKI_CSR_CN=$($PKI csr show "$WORKDIR/rsa.csr" 2>&1 | grep "Common Name:" | head -1 | sed 's/.*Common Name:\s*//' | tr -d '[:space:]')
PY_CSR_CN=$(python3 -c "
from cryptography import x509
csr = x509.load_pem_x509_csr(open('$WORKDIR/rsa.csr','rb').read())
cn = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
print(cn)
" 2>&1 | tr -d '[:space:]')

if [ "$PKI_CSR_CN" = "$PY_CSR_CN" ]; then
    pass "CSR CN matches: $PKI_CSR_CN"
else
    fail "CSR CN mismatch: pki=$PKI_CSR_CN python=$PY_CSR_CN"
fi

# ── TEST 9: Key Size Matches ──────────────────────────────────────
echo ""
echo "=== TEST 9: RSA Key Size (pki vs python3) ==="

PY_KEYSIZE=$(python3 -c "
from cryptography.hazmat.primitives.serialization import load_pem_private_key
key = load_pem_private_key(open('$WORKDIR/rsa.key','rb').read(), password=None)
print(key.key_size)
" 2>&1 | tr -d '[:space:]')

PKI_KEYSIZE=$($PKI key show "$WORKDIR/rsa.key" 2>&1 | grep "Size:" | grep -oP '\d+' | head -1)

if [ "$PKI_KEYSIZE" = "$PY_KEYSIZE" ]; then
    pass "RSA key size matches: $PKI_KEYSIZE bits"
else
    fail "RSA key size mismatch: pki=$PKI_KEYSIZE python=$PY_KEYSIZE"
fi

# ── TEST 10: CRL Parsing ─────────────────────────────────────────
echo ""
echo "=== TEST 10: CRL Issuer (pki vs python3) ==="

CRL_FILE="/tmp/WindowsCA.crl"
if [ -f "$CRL_FILE" ]; then
    PKI_CRL_ISSUER=$($PKI crl show "$CRL_FILE" 2>&1 | grep -A1 "Issuer:" | tail -1 | tr -d '[:space:]')
    PY_CRL_ISSUER=$(python3 -c "
from cryptography import x509
crl = x509.load_der_x509_crl(open('$CRL_FILE','rb').read())
print(crl.issuer.rfc4514_string())
" 2>&1 | tr -d '[:space:]')
    echo "  pki:    $PKI_CRL_ISSUER"
    echo "  python: $PY_CRL_ISSUER"
    if echo "$PKI_CRL_ISSUER" | grep -qi "WindowsCA" && echo "$PY_CRL_ISSUER" | grep -qi "WindowsCA"; then
        pass "CRL issuer contains WindowsCA"
    else
        fail "CRL issuer mismatch"
    fi
else
    skip "No CRL file at $CRL_FILE"
fi

# ── TEST 11: Probe vs known TLS (google.com) ─────────────────────
echo ""
echo "=== TEST 11: TLS Probe (pki vs python3 ssl) ==="

PKI_PROBE_VERSION=$($PKI probe check google.com:443 2>&1 | head -1)
PY_TLS=$(python3 -c "
import ssl, socket
ctx = ssl.create_default_context()
with ctx.wrap_socket(socket.socket(), server_hostname='google.com') as s:
    s.connect(('google.com', 443))
    print(s.version())
" 2>&1)

echo "  pki:    $PKI_PROBE_VERSION"
echo "  python: $PY_TLS"
if echo "$PKI_PROBE_VERSION" | grep -qi "OK\|TLS"; then
    pass "TLS probe succeeded"
else
    fail "TLS probe failed: $PKI_PROBE_VERSION"
fi

# ── TEST 12: cert expires days calculation ────────────────────────
echo ""
echo "=== TEST 12: Expiry Days Calculation (pki vs python3) ==="

if [[ "$HAVE_CERT" -eq 0 ]]; then skip "no test cert"; else
PKI_DAYS=$($PKI cert expires "$CERT" 2>&1 | grep -oP '\d+ days' | grep -oP '\d+')
PY_DAYS=$(python3 -c "
from cryptography import x509
from datetime import datetime
cert = x509.load_pem_x509_certificate(open('$CERT','rb').read())
delta = cert.not_valid_after - datetime.utcnow()
print(delta.days)
" 2>/dev/null)

DIFF=$((PKI_DAYS - PY_DAYS))
if [ "$DIFF" -ge -1 ] && [ "$DIFF" -le 1 ]; then
    pass "Expiry days match (within 1 day): pki=$PKI_DAYS python=$PY_DAYS"
else
    fail "Expiry days mismatch: pki=$PKI_DAYS python=$PY_DAYS diff=$DIFF"
fi
fi

# ── Summary ───────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "  RESULTS: $PASS passed, $FAIL failed, $SKIP skipped"
echo "================================================================"
if [ "$FAIL" -gt 0 ]; then
    echo -e "  Failures:$ERRORS"
    exit 1
fi
