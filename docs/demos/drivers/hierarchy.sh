#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

WORK="$(mktemp -d)"
cd "$WORK"

cat > hierarchy.toml << 'EOF'
[hierarchy]
name = "acme-pki"
output_dir = "./pki-output"

[hierarchy.defaults]
country = "US"
organization = "ACME Corp"

[[ca]]
id = "root"
type = "root"
algorithm = "ecdsa-p384"
common_name = "ACME Root CA"
validity_years = 20

[[ca]]
id = "issuing"
type = "intermediate"
parent = "root"
algorithm = "ecdsa-p256"
common_name = "ACME Issuing CA"
validity_years = 10
path_length = 0
EOF

note "Declarative PKI hierarchy — 2 CAs described in TOML"
run cat hierarchy.toml

note "Validate the config"
run "$PKI_BIN" pki validate hierarchy.toml

note "Preview the hierarchy as a tree (no files written)"
run "$PKI_BIN" pki preview hierarchy.toml

note "Build it — generates keys + certs in topological order"
run "$PKI_BIN" pki build hierarchy.toml

note "See what landed on disk"
run_sh "find pki-output -type f | sort"

note "Inspect the root CA certificate"
run_sh "\"$PKI_BIN\" cert show pki-output/root/root.cert.pem 2>&1 | head -20"

sleep 1
