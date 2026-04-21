#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

note "Quick TLS sanity check"
run "$PKI_BIN" probe check google.com:443

note "Full TLS configuration — protocol, cipher, chain, PQC hybrid KEX"
run_sh "\"$PKI_BIN\" probe server google.com:443 2>&1 | head -25"

note "Compact JSON output for scripting"
run_sh "\"$PKI_BIN\" probe server google.com:443 -f json 2>&1 | head -15"

note "Fetch the chain + lint the fetched certificates for issues"
cd "$(mktemp -d)"
run "$PKI_BIN" probe fetch google.com:443 --output chain.pem
run_sh "\"$PKI_BIN\" probe lint chain.pem 2>&1 | head -20"

sleep 1
