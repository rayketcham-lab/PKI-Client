#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

cd "$(mktemp -d)"

note "Generate an EC P-256 private key (PKCS#8 PEM, mode 0600)"
run "$PKI_BIN" key gen ec --curve p256 -o server.key

note "Inspect the key"
run "$PKI_BIN" key show server.key

note "Create a CSR with SANs for example.com"
run "$PKI_BIN" csr create -k server.key --cn example.com --san example.com --san www.example.com -o server.csr

note "Show CSR details"
run "$PKI_BIN" csr show server.csr

note "Also try a post-quantum key — ML-DSA-65 (FIPS 204, NIST Level 3)"
run "$PKI_BIN" key gen ml-dsa-65 -o pqc.key

sleep 1
