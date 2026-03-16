# PKI-Client

[![Version](https://img.shields.io/badge/version-0.3.0--beta.3-blue)](https://github.com/rayketcham-lab/PKI-Client/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-pure-orange)](https://www.rust-lang.org/)
[![No OpenSSL](https://img.shields.io/badge/OpenSSL-not%20required-brightgreen)]()
[![CI](https://github.com/rayketcham-lab/PKI-Client/actions/workflows/ci.yml/badge.svg)](https://github.com/rayketcham-lab/PKI-Client/actions/workflows/ci.yml)

Modern PKI CLI tool — certificate inspection, key management, TLS probing, and enrollment protocols.

Pure Rust. No OpenSSL dependency. Human-friendly output.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Output Formats](#output-formats)
- [Commands](#commands)
- [Architecture](#architecture)
- [Install](#install)
- [Shell Completions](#shell-completions)
- [Building from Source](#building-from-source)
- [Security](#security)
- [License](#license)

## Features

- **Certificate inspection** — decode, verify, fingerprint, and expiry checks for X.509 certs
- **Key management** — generate RSA, ECDSA, Ed25519 key pairs
- **TLS probing** — connect to any TLS server, inspect the handshake, lint the configuration
- **Chain building** — construct and verify certificate chains from loose files
- **CSR / CRL** — create and inspect certificate signing requests and revocation lists
- **Revocation checking** — OCSP and CRL-based revocation status
- **ACME enrollment** — automated Let's Encrypt certificate issuance and renewal
- **EST enrollment** — Enrollment over Secure Transport for enterprise CAs
- **SCEP transport** — CA discovery and capabilities; full enrollment planned ([#1](https://github.com/rayketcham-lab/PKI-Client/issues/1))
- **Compliance validation** — FIPS 140-3, NIST, and Federal Bridge policy checks
- **DANE / TLSA** — generate and verify TLSA DNS records for DANE
- **Post-quantum cryptography** — ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) with `--features pqc`
- **FIPS mode** — restrict operations to FIPS 140-3 approved algorithms with `--fips`
- **Four output formats** — text, JSON, compact, forensic (deep-dive with hex dumps and security grades)
- **Interactive shell** — run `pki` with no arguments for a REPL session
- **Static binaries** — musl builds with zero runtime dependencies

## Quick Start

```bash
# Inspect any PKI file (auto-detects type)
pki show server.pem

# Deep forensic analysis
pki cert show server.pem --format forensic

# Check which certs expire within 30 days
pki cert expires *.pem --within 30d

# Probe a TLS server
pki probe example.com:443

# Generate a key pair
pki key gen ec --curve P-256

# Build and verify a certificate chain
pki chain build server.pem

# Enter interactive shell
pki
```

## Output Formats

| Format     | Flag                      | Use case                                          |
|------------|---------------------------|---------------------------------------------------|
| `text`     | `--format text` (default) | Human-readable with colors                        |
| `json`     | `--format json`           | Scripting and automation                          |
| `compact`  | `--format compact`        | One-line-per-cert dashboards                      |
| `forensic` | `--format forensic`       | Deep-dive analysis, hex dumps, security grades    |

## Commands

| Command       | Description                                              |
|---------------|----------------------------------------------------------|
| `show`        | Auto-detect and display any PKI file                     |
| `cert`        | Certificate operations (show, verify, fingerprint, expires) |
| `key`         | Key generation and inspection                            |
| `chain`       | Certificate chain building and verification              |
| `csr`         | CSR creation and inspection                              |
| `crl`         | CRL viewing and revocation checking                      |
| `revoke`      | OCSP and CRL revocation status                           |
| `probe`       | TLS server inspection and linting                        |
| `acme`        | Automated Let's Encrypt certificate enrollment           |
| `est`         | EST enrollment for enterprise CAs                        |
| `scep`        | SCEP CA discovery and capabilities                       |
| `compliance`  | FIPS 140-3, NIST, and Federal Bridge validation          |
| `dane`        | TLSA record generation and verification                  |
| `diff`        | Certificate comparison                                   |
| `convert`     | Format conversion (PEM / DER / PKCS#12)                  |
| `completions` | Shell completion scripts                                 |
| `manpages`    | Generate man pages                                       |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    pki (binary)                      │
│              17 subcommands + shell                  │
├──────────┬──────────────┬───────────────────────────┤
│          │              │                           │
│  pki-client-output      │  pki-probe                │
│  Formatting, OID        │  TLS inspection           │
│  registry, display      │  & linting                │
│          │              │                           │
│          │   pki-hierarchy                          │
│          │   Declarative PKI                        │
│          │   hierarchy builder                      │
│          │              │                           │
├──────────┴──────────────┴───────────────────────────┤
│              spork-core (CA engine)                  │
│        Crypto primitives, signing, certs             │
└─────────────────────────────────────────────────────┘
```

| Crate              | Role                                        |
|---------------------|---------------------------------------------|
| `pki-client`        | Binary — CLI entry point, 17 subcommands    |
| `pki-client-output` | Library — formatting, OID registry          |
| `pki-probe`         | Library — TLS inspection and linting        |
| `pki-hierarchy`     | Library — declarative PKI hierarchy builder |
| `spork-core`        | External — CA crypto engine (git dependency)|

## Install

### From source

```bash
cargo install --git https://github.com/rayketcham-lab/PKI-Client.git
```

### Pre-built binaries

Pre-built static Linux binaries will be published to [GitHub Releases](https://github.com/rayketcham-lab/PKI-Client/releases) starting with the first stable release.

## Shell Completions

```bash
# Bash
pki completions bash > /etc/bash_completion.d/pki

# Zsh
pki completions zsh > ~/.zfunc/_pki

# Fish
pki completions fish > ~/.config/fish/completions/pki.fish
```

## Building from Source

```bash
git clone https://github.com/rayketcham-lab/PKI-Client.git
cd PKI-Client
cargo build --release
# Binary at target/release/pki
```

Static musl binary (no runtime dependencies):

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

Post-quantum support:

```bash
cargo build --release --features pqc
```

FIPS mode:

```bash
pki --fips cert show server.pem
```

## Security

- **No OpenSSL dependency** — pure Rust crypto stack eliminates an entire class of C memory-safety vulnerabilities
- **No unsafe code** in application logic — only in vetted dependencies (`ring`, `rustls`)
- **Constant-time comparisons** for cryptographic material via underlying libraries
- **No secret logging** — keys and private material are never written to stdout or logs
- **Static binaries** — musl builds eliminate shared-library supply-chain risk
- **FIPS 140-3 mode** — restrict all operations to approved algorithms when compliance is required
- **Input validation** — all file parsing uses safe, bounds-checked Rust decoders

To report a security vulnerability, please open a private security advisory on the [GitHub repository](https://github.com/rayketcham-lab/PKI-Client/security/advisories).

## License

MIT — see [LICENSE](LICENSE).
