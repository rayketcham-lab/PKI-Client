#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

cd "$(mktemp -d)"

note "Fetch google.com's certificate chain with pki probe fetch"
run "$PKI_BIN" probe fetch google.com:443 --output chain.pem

note "Quick view — auto-detects PEM type"
run "$PKI_BIN" show chain.pem

note "Certificate details — text format"
run "$PKI_BIN" cert show chain.pem

note "Same cert, OpenSSL-compatible output (--format openssl)"
run_sh "\"$PKI_BIN\" cert show chain.pem -f openssl 2>/dev/null | head -30"

note "Forensic mode — every field, hex dumps, security notes"
run_sh "\"$PKI_BIN\" cert show chain.pem -f forensic 2>/dev/null | head -40"

sleep 1
