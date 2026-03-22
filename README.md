# PKI-Client

**Modern PKI CLI tool** — certificate inspection, key management, TLS probing, and enrollment protocols.

Pure Rust. No OpenSSL dependency. Human-friendly output.

---

### Project Health

<!-- CI / Testing Pipeline -->
[![CI](https://github.com/rayketcham-lab/PKI-Client/actions/workflows/ci.yml/badge.svg)](https://github.com/rayketcham-lab/PKI-Client/actions/workflows/ci.yml)
[![Daily Health Check](https://github.com/rayketcham-lab/PKI-Client/actions/workflows/daily-check.yml/badge.svg)](https://github.com/rayketcham-lab/PKI-Client/actions/workflows/daily-check.yml)
[![Interop Tests](https://github.com/rayketcham-lab/PKI-Client/actions/workflows/interop.yml/badge.svg)](https://github.com/rayketcham-lab/PKI-Client/actions/workflows/interop.yml)

<!-- Security & Compliance -->
[![Security Audit](https://img.shields.io/badge/cargo--audit-passing-brightgreen?logo=hackthebox&logoColor=white)](https://rustsec.org/)
[![Supply Chain](https://img.shields.io/badge/cargo--deny-passing-brightgreen?logo=checkmarx&logoColor=white)](https://embarkstudios.github.io/cargo-deny/)
[![License Scan](https://img.shields.io/badge/license%20scan-clean-brightgreen?logo=opensourceinitiative&logoColor=white)](https://embarkstudios.github.io/cargo-deny/)
[![No Unsafe](https://img.shields.io/badge/unsafe-zero-brightgreen?logo=rust&logoColor=white)](https://github.com/rayketcham-lab/PKI-Client)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-not%20required-brightgreen?logo=openssl&logoColor=white)](https://github.com/rayketcham-lab/PKI-Client)

<!-- Project Info -->
[![Version](https://img.shields.io/badge/version-0.5.0--beta.1-blue?logo=semver&logoColor=white)](https://github.com/rayketcham-lab/PKI-Client/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green?logo=apache&logoColor=white)](LICENSE)
[![Rust](https://img.shields.io/badge/language-Rust-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![MSRV](https://img.shields.io/badge/MSRV-1.88.0-orange?logo=rust&logoColor=white)](https://blog.rust-lang.org/)

<!-- Build & Quality -->
[![Clippy](https://img.shields.io/badge/clippy--D%20warnings-passing-brightgreen?logo=rust&logoColor=white)](https://github.com/rayketcham-lab/PKI-Client/actions/workflows/ci.yml)
[![Formatting](https://img.shields.io/badge/rustfmt-checked-brightgreen?logo=rust&logoColor=white)](https://github.com/rayketcham-lab/PKI-Client/actions/workflows/ci.yml)
[![PQC](https://img.shields.io/badge/post--quantum-supported-blueviolet?logo=quantcast&logoColor=white)](https://github.com/rayketcham-lab/PKI-Client)
[![FIPS](https://img.shields.io/badge/FIPS%20140--3-optional-blue?logo=nist&logoColor=white)](https://github.com/rayketcham-lab/PKI-Client)
[![Static Binary](https://img.shields.io/badge/static%20binary-musl-blue?logo=linux&logoColor=white)](https://github.com/rayketcham-lab/PKI-Client/releases)

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Commands](#commands)
- [Features](#features)
- [Output Formats](#output-formats)
- [Architecture](#architecture)
- [Install](#install)
- [Building from Source](#building-from-source)
- [Interop Testing](#interop-testing)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

## Overview

`pki` is a single binary that replaces a scattered toolbox of `openssl`, `certutil`, `step`, and custom scripts for PKI operations. It provides:

- **`pki show`** — auto-detect and display any PKI file (cert, key, CSR, CRL, PKCS#12)
- **`pki probe`** — inspect any TLS server's handshake, cipher suite, chain, and security posture
- **`pki acme`** — full ACME client (Let's Encrypt) with certbot-like `certonly` workflow
- **`pki est`** / **`pki scep`** — enterprise CA enrollment protocols (RFC 7030, RFC 8894)
- **`pki compliance`** — validate against FIPS 140-3, NIST SP 800-57, and Federal Bridge policies
- **`pki dane`** — generate and verify DANE/TLSA records (RFC 6698)

All commands support four output formats: **text** (human), **json** (scripting), **compact** (dashboards), **forensic** (deep-dive with hex dumps and security grades).

## Quick Start

```bash
# Inspect any PKI file (auto-detects type)
pki show server.pem

# Deep forensic analysis with hex dumps and security grades
pki cert show server.pem --format forensic

# Check which certs expire within 30 days
pki cert expires *.pem --within 30d

# Probe a TLS server — version, cipher, chain, security lint
pki probe server example.com:443

# Generate a key pair and CSR
pki key gen ec --curve p256 -o server.key
pki csr create --key server.key --cn example.com --san dns:www.example.com -o server.csr

# Get a Let's Encrypt certificate
pki acme certonly -d example.com --email admin@example.com

# Build and verify a certificate chain
pki chain build server.pem

# Compare two certificates side-by-side
pki diff old-cert.pem new-cert.pem

# Interactive shell mode
pki
```

## Commands

| Command | Description | RFC / Standard |
|---|---|---|
| **`show`** | Auto-detect and display any PKI file | — |
| **`cert`** | Certificate inspection, fingerprint, expiry | X.509 (RFC 5280) |
| **`key`** | Key generation (RSA, EC, Ed25519) and inspection | PKCS#8 (RFC 5958) |
| **`chain`** | Certificate chain building and verification | RFC 5280 path validation |
| **`csr`** | CSR creation and inspection | PKCS#10 (RFC 2986) |
| **`crl`** | CRL viewing and revocation checking | RFC 5280 |
| **`revoke`** | OCSP and CRL revocation status | OCSP (RFC 6960) |
| **`probe`** | TLS server inspection and security linting | TLS 1.3 (RFC 8446) |
| **`acme`** | Let's Encrypt / ACME certificate enrollment | RFC 8555 |
| **`est`** | Enrollment over Secure Transport | RFC 7030 |
| **`scep`** | SCEP CA discovery and capabilities | RFC 8894 |
| **`compliance`** | FIPS 140-3, NIST, Federal Bridge validation | NIST SP 800-57 |
| **`dane`** | TLSA record generation and verification | RFC 6698 |
| **`diff`** | Side-by-side certificate comparison | — |
| **`convert`** | Format conversion (PEM / DER / PKCS#12) | — |
| **`pki`** | Declarative PKI hierarchy builder | — |
| **`completions`** | Shell completion scripts (bash, zsh, fish) | — |
| **`manpages`** | Generate man pages | — |
| **`shell`** | Interactive REPL session | — |

## Features

### Certificate & Key Management
- Decode, verify, fingerprint, and expiry-check X.509 certificates
- Generate RSA (2048–4096), ECDSA (P-256, P-384), and Ed25519 keys
- Create and inspect Certificate Signing Requests (CSRs)
- View CRLs and check revocation status via OCSP and CRL
- Convert between PEM, DER, PKCS#12, and Base64

### TLS & Network
- Full TLS server inspection — protocol version, cipher suite, key exchange
- Certificate chain linting with security grades
- Certificate chain building with AIA chasing
- DANE/TLSA record generation and verification

### Enrollment Protocols
- **ACME** — full RFC 8555 client with HTTP-01 and DNS-01 challenges, auto-renewal, server deployment
- **EST** — RFC 7030 enrollment, re-enrollment, server keygen, CSR attributes
- **SCEP** — RFC 8894 CA capabilities and certificate discovery; full enrollment planned ([#1](https://github.com/rayketcham-lab/PKI-Client/issues/1))

### Compliance & Security
- **FIPS 140-3 mode** — restrict all operations to approved algorithms with `--fips`
- **Post-quantum cryptography** — ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) with `--features pqc`
- **Compliance validation** — check CA configurations against NIST, FIPS, and Federal Bridge policies
- **Static binaries** — musl builds with zero runtime dependencies

### Developer Experience
- **Four output formats** — text (human), JSON (scripting), compact (dashboards), forensic (deep-dive)
- **Interactive shell** — run `pki` with no arguments for a REPL session
- **Shell completions** — bash, zsh, fish
- **Man pages** — generated from CLI definitions

## Output Formats

| Format | Flag | Use case |
|---|---|---|
| `text` | `--format text` (default) | Human-readable with colors |
| `json` | `--format json` | Scripting and automation |
| `compact` | `--format compact` | One-line-per-cert dashboards |
| `forensic` | `--format forensic` | Deep-dive: every field, hex dumps, security grades |

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     pki (binary)                          │
│              19 subcommands + interactive shell            │
├───────────┬───────────────┬──────────────────────────────┤
│           │               │                              │
│ pki-client-output         │  pki-probe                   │
│ Formatting, OID           │  TLS inspection              │
│ registry, display         │  & linting                   │
│           │               │                              │
│           │  pki-hierarchy                               │
│           │  Declarative PKI                             │
│           │  hierarchy builder                           │
│           │               │                              │
├───────────┴───────────────┴──────────────────────────────┤
│              spork-core (vendored CA engine)               │
│        Crypto primitives, signing, certificates            │
└──────────────────────────────────────────────────────────┘
```

| Crate | Role |
|---|---|
| `pki-client` | Binary — CLI entry point, 19 subcommands + shell |
| `pki-client-output` | Library — formatting, OID registry |
| `pki-probe` | Library — TLS inspection and linting |
| `pki-hierarchy` | Library — declarative PKI hierarchy builder |
| `spork-core` | Vendored — CA crypto engine (key generation, signing, certificate building) |

## Install

### Pre-built binaries (recommended)

Download a static binary — no Rust, no build tools, no dependencies:

**Install:**
```bash
curl -fsSL https://raw.githubusercontent.com/rayketcham-lab/PKI-Client/main/install.sh | bash
```

**Upgrade:**
```bash
curl -fsSL https://raw.githubusercontent.com/rayketcham-lab/PKI-Client/main/install.sh | bash -s -- upgrade
```

**Uninstall:**
```bash
curl -fsSL https://raw.githubusercontent.com/rayketcham-lab/PKI-Client/main/install.sh | bash -s -- uninstall
```

**Pin to a specific version:**
```bash
curl -fsSL https://raw.githubusercontent.com/rayketcham-lab/PKI-Client/main/install.sh | bash -s -- v0.5.0-beta.4
```

Or download manually from [GitHub Releases](https://github.com/rayketcham-lab/PKI-Client/releases):

```bash
curl -fSL -o pki.tar.gz https://github.com/rayketcham-lab/PKI-Client/releases/latest/download/pki-v0.5.0-beta.4-x86_64-linux.tar.gz
tar xzf pki.tar.gz
sudo mv pki /usr/local/bin/
```

**Platform:** x86_64 Linux. The binary is statically linked (musl) — zero runtime dependencies.

### Verify release integrity

Every release includes SHA256 checksums, [SLSA build provenance](https://slsa.dev/), and [Sigstore](https://www.sigstore.dev/) cosign signatures. All artifacts are built by GitHub Actions from source — no human touches the binary.

**SHA256 checksum:**
```bash
curl -fSL -o SHA256SUMS.txt https://github.com/rayketcham-lab/PKI-Client/releases/latest/download/SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt
```

**GitHub attestation (SLSA provenance):**
```bash
gh attestation verify pki-v0.5.0-beta.4-x86_64-linux.tar.gz --repo rayketcham-lab/PKI-Client
```

**Cosign signature (Sigstore):**
```bash
curl -fSL -o pki.tar.gz.bundle https://github.com/rayketcham-lab/PKI-Client/releases/latest/download/pki-v0.5.0-beta.4-x86_64-linux.tar.gz.bundle
cosign verify-blob \
  --bundle pki-v0.5.0-beta.4-x86_64-linux.tar.gz.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/rayketcham-lab/PKI-Client" \
  pki-v0.5.0-beta.4-x86_64-linux.tar.gz
```

### Shell completions

```bash
# Bash
pki completions bash > /etc/bash_completion.d/pki

# Zsh
pki completions zsh > ~/.zfunc/_pki

# Fish
pki completions fish > ~/.config/fish/completions/pki.fish
```

## Building from Source

### Prerequisites

The TLS stack (`rustls` + `aws-lc-rs`) compiles native crypto from C source. You need:

| Tool | Why | Install (Debian/Ubuntu) |
|------|-----|------------------------|
| C compiler | aws-lc-sys, ring | `sudo apt install build-essential` |
| CMake | aws-lc-sys | `sudo apt install cmake` |
| Perl | aws-lc-sys build scripts | Usually pre-installed |

Most users should use the [pre-built binary](#pre-built-binaries-recommended) instead of building from source.

### Build

```bash
git clone https://github.com/rayketcham-lab/PKI-Client.git
cd PKI-Client
cargo build --release
# Binary at target/release/pki
```

The binary links dynamically to `libc` only — no OpenSSL, no system crypto libs. TLS root certificates are bundled (Mozilla WebPKI roots) with system cert store as primary.

**Static musl binary** (zero runtime dependencies):

```bash
sudo apt install musl-tools  # provides musl-gcc
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

**Post-quantum support** (ML-DSA, SLH-DSA) — pure Rust, no extra deps:

```bash
cargo build --release --features pqc
```

**FIPS 140-3 mode** — restricts algorithms to FIPS-approved set at the application level:

```bash
pki --fips cert show server.pem
```

> **Note:** `--fips` restricts algorithm selection but does not use a FIPS-validated cryptographic module. For true FIPS 140-3 validation, the `aws-lc-fips-sys` crate (requiring a Go compiler) would be needed — this is not currently implemented.

## Interop Testing

PKI-Client runs automated interop tests against real protocol implementations:

| Test Suite | Target | What It Validates |
|---|---|---|
| **ACME vs Pebble** | [Pebble](https://github.com/letsencrypt/pebble) (Let's Encrypt test CA) | Account registration, order creation, certificate issuance |
| **TLS Probe** | google.com, cloudflare.com, github.com | TLS version detection, chain fetch, certificate inspection |
| **Cert Round-Trip** | Local key/CSR generation | Key gen, CSR creation, PEM/DER conversion, format consistency |

Interop tests run daily and on PRs that touch protocol code. Run locally:

```bash
cargo build --release
bash tests/interop/cert_roundtrip.sh
bash tests/interop/tls_probe.sh
```

## Security

- **No OpenSSL dependency** — pure Rust crypto stack (`rustls`, `ring`, `aws-lc-rs`) eliminates C memory-safety vulnerabilities
- **No unsafe code** in application logic — only in vetted dependencies
- **Constant-time comparisons** for cryptographic material via underlying libraries
- **No secret logging** — keys and private material are never written to stdout or logs
- **Static binaries** — musl builds eliminate shared-library supply-chain risk
- **FIPS 140-3 mode** — restrict all operations to approved algorithms
- **Input validation** — all file parsing uses safe, bounds-checked Rust decoders
- **Dependency auditing** — `cargo audit` and `cargo deny` run in CI with zero-tolerance policy
- **Signed releases** — every binary is signed with [Sigstore cosign](https://www.sigstore.dev/) (keyless) and includes [SLSA provenance](https://slsa.dev/) attestations via GitHub Actions
- **Vendored dependencies** — all crate dependencies are vendored and verified against `Cargo.lock` in CI; no git dependencies allowed

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Contributing

We welcome contributions. Please see the CI checks before submitting a PR:

```bash
cargo fmt --all --check        # Format
cargo clippy -- -D warnings    # Lint (zero warnings)
cargo test --all               # Tests
```

All commits follow [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `ci:`, `security:`.

## License

Apache-2.0 — see [LICENSE](LICENSE).
