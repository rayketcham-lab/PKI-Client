# PKI-Client

**Modern PKI CLI tool** — certificate inspection, key management, TLS probing, and enrollment protocols.

Pure Rust. No OpenSSL dependency. Human-friendly output. One binary, zero dependencies.

[![Watch Demo](https://img.shields.io/badge/▶_Watch_Demo-in_browser-d40000?style=for-the-badge&logo=asciinema)](https://rayketcham-lab.github.io/PKI-Client/demo.html)

### Demos

| Scenario | Description |
|----------|-------------|
| [Tacoo Tuesday](https://rayketcham-lab.github.io/PKI-Client/demo.html?demo=taco-tuesday) | A taco shop goes full post-quantum — 3-tier all-PQC hierarchy with ML-DSA |
| [Enterprise PKI](https://rayketcham-lab.github.io/PKI-Client/demo.html?demo=enterprise) | 3-tier corporate PKI (RSA-4096) vs PQC (ML-DSA-87) — build, inspect, diff, verify |
| [The Vision](https://rayketcham-lab.github.io/PKI-Client/demo.html?demo=vision) | From MD5 to ML-DSA-87 to 2050 — the past, present, and future of PKI |
| [Signing Service](https://rayketcham-lab.github.io/PKI-Client/demo.html?demo=signing) | Enterprise signing — PE/Authenticode, detached CMS, PowerShell, RFC 3161 TSA |
| [Quantum Ops](https://rayketcham-lab.github.io/PKI-Client/demo.html?demo=quantum-ops) | End-to-end PKI operations: cert inspection, key gen, CSR, and ML-DSA-87 hierarchy |

---

### Project Health

<!-- CI / Testing Pipeline -->
[![CI](https://github.com/rayketcham-lab/PKI-Client/actions/workflows/ci.yml/badge.svg)](https://github.com/rayketcham-lab/PKI-Client/actions/workflows/ci.yml)
[![Daily Health Check](https://github.com/rayketcham-lab/PKI-Client/actions/workflows/daily-check.yml/badge.svg)](https://github.com/rayketcham-lab/PKI-Client/actions/workflows/daily-check.yml)
[![Interop Tests](https://github.com/rayketcham-lab/PKI-Client/actions/workflows/interop.yml/badge.svg)](https://github.com/rayketcham-lab/PKI-Client/actions/workflows/interop.yml)
[![Crypto Validation](https://github.com/rayketcham-lab/PKI-Client/actions/workflows/crypto-validation.yml/badge.svg)](https://github.com/rayketcham-lab/PKI-Client/actions/workflows/crypto-validation.yml)
[![SCEP Interop](https://github.com/rayketcham-lab/PKI-Client/actions/workflows/scep-interop.yml/badge.svg)](https://github.com/rayketcham-lab/PKI-Client/actions/workflows/scep-interop.yml)

<!-- Security & Compliance -->
[![Security Audit](https://img.shields.io/badge/cargo--audit-passing-brightgreen?logo=hackthebox&logoColor=white)](https://rustsec.org/)
[![Supply Chain](https://img.shields.io/badge/cargo--deny-passing-brightgreen?logo=checkmarx&logoColor=white)](https://embarkstudios.github.io/cargo-deny/)
[![License Scan](https://img.shields.io/badge/license%20scan-clean-brightgreen?logo=opensourceinitiative&logoColor=white)](https://embarkstudios.github.io/cargo-deny/)
[![No Unsafe](https://img.shields.io/badge/unsafe-zero-brightgreen?logo=rust&logoColor=white)](https://github.com/rayketcham-lab/PKI-Client)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-not%20required-brightgreen?logo=openssl&logoColor=white)](https://github.com/rayketcham-lab/PKI-Client)

<!-- Project Info -->
[![Version](https://img.shields.io/badge/version-0.8.0-blue?logo=semver&logoColor=white)](https://github.com/rayketcham-lab/PKI-Client/releases)
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

Certificate inspection (`pki show`, `pki cert`) supports five output formats: **text** (human), **json** (scripting), **compact** (dashboards), **forensic** (deep-dive with hex dumps and security grades), **openssl** (matches `openssl x509 -text` with colors and lifetime bars). Network/protocol subcommands (`probe`, `acme`, `est`, `scep`) render text for all formats except `json`.

## Quick Start

```bash
# Inspect any PKI file (auto-detects type)
pki show server.pem

# OpenSSL-style output with colors and lifetime bars
pki cert show server.pem --format openssl

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
pki acme certonly -d example.com --email admin@example.com \
    --server https://acme-v02.api.letsencrypt.org/directory

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
| **`key`** | Key generation (RSA, EC, Ed25519, ML-DSA, SLH-DSA) and inspection | PKCS#8 (RFC 5958) |
| **`chain`** | Certificate chain building and verification | RFC 5280 path validation |
| **`csr`** | CSR creation and inspection | PKCS#10 (RFC 2986) |
| **`crl`** | CRL viewing and revocation checking | RFC 5280 |
| **`revoke`** | OCSP and CRL revocation status | OCSP (RFC 6960) |
| **`probe`** | TLS server inspection and security linting | TLS 1.3 (RFC 8446) |
| **`acme`** | Let's Encrypt / ACME certificate enrollment | RFC 8555 |
| **`est`** | Enrollment over Secure Transport | RFC 7030 |
| **`scep`** | SCEP enrollment, CA discovery and capabilities | RFC 8894 |
| **`compliance`** | FIPS 140-3, NIST, Federal Bridge validation | NIST SP 800-57 |
| **`dane`** | TLSA record generation and verification | RFC 6698 |
| **`diff`** | Side-by-side certificate comparison | — |
| **`convert`** | Format conversion (PEM / DER / PKCS#12) | — |
| **`pki`** | Declarative PKI hierarchy builder | — |
| **`completions`** | Shell completion scripts (bash, zsh, fish) | — |
| **`manpages`** | Generate man pages | — |
| **`shell`** | Interactive REPL session | — |
| **`batch`** | Run commands from a script file (batch mode) | — |

## Features

### Certificate & Key Management
- Decode, verify, fingerprint, and expiry-check X.509 certificates
- Generate RSA (3072–4096), ECDSA (P-256, P-384), Ed25519, and post-quantum keys (ML-DSA, SLH-DSA)
- Create and inspect Certificate Signing Requests (CSRs), including PQC CSRs
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
- **SCEP** — RFC 8894 enrollment, CA capabilities, and certificate discovery

### Compliance & Security
- **FIPS 140-3 mode** — restrict all operations to approved algorithms with `--fips`
- **Post-quantum cryptography** — ML-DSA (FIPS 204 algorithm) and SLH-DSA (FIPS 205 algorithm) key generation, CSR creation, and certificate inspection with `--features pqc`. Uses RustCrypto pre-release crates (`ml-dsa`, `slh-dsa`); these are FIPS 204/205 _algorithm_ implementations, not FIPS 140-3 validated modules.
- **Compliance validation** — check CA configurations against NIST, FIPS, and Federal Bridge policies
- **Static binaries** — musl builds with zero runtime dependencies

### Developer Experience
- **Five output formats** on certificate inspection — text (human), JSON (scripting), compact (dashboards), forensic (deep-dive), openssl (familiar `x509 -text` layout with PKI extensions). Protocol/network subcommands use text or JSON.
- **Interactive shell** — run `pki` with no arguments for a REPL session
- **Shell completions** — bash, zsh, fish
- **Man pages** — generated from CLI definitions

## Output Formats

| Format | Flag | Alias | Use case |
|---|---|---|---|
| `text` | `--format text` (default) | `-f t` | Human-readable with colors and security grades |
| `json` | `--format json` | `-f j` | Scripting and automation |
| `compact` | `--format compact` | `-f c` | One-line-per-cert dashboards |
| `forensic` | `--format forensic` | `-f f` | Deep-dive: every field, hex dumps, security grades |
| `openssl` | `--format openssl` | `-f os` | Matches `openssl x509 -text -noout` with colors + lifetime/trust extensions |

The **openssl** format reproduces the exact layout engineers expect from `openssl x509 -text -noout`, then adds PKI Client extensions:

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            04:3A:2B:...
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, O = Let's Encrypt, CN = R3
        Validity
            Not Before: Jan  1 00:00:00 2025 GMT
            Not After : Apr  1 00:00:00 2025 GMT
        Subject: CN = example.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                ASN1 OID: p-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            ...
    Signature Algorithm: sha256WithRSAEncryption
         ab:cd:ef:...

--- PKI Client Extensions ---
    Lifetime:  [████████████░░░░░░░░] 60% (54/90 days)
    Trust:     example.com <- R3
```

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     pki (binary)                          │
│        20 subcommands incl. interactive `shell`            │
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
| `pki-client` | Binary — CLI entry point, 20 subcommands incl. interactive `shell` |
| `pki-client-output` | Library — formatting, OID registry |
| `pki-probe` | Library — TLS inspection and linting |
| `pki-hierarchy` | Library — declarative PKI hierarchy builder |
| `spork-core` | Vendored — CA crypto engine (key generation, signing, certificate building) |

## Install

### Pre-built binaries (recommended)

Download a static binary — no Rust, no build tools, no dependencies:

**Install** (requires sudo for `/usr/local/bin`):
```bash
curl -fsSL https://raw.githubusercontent.com/rayketcham-lab/PKI-Client/main/install.sh | sudo bash
```

**Upgrade:**
```bash
curl -fsSL https://raw.githubusercontent.com/rayketcham-lab/PKI-Client/main/install.sh | sudo bash -s -- upgrade
```

**Uninstall:**
```bash
curl -fsSL https://raw.githubusercontent.com/rayketcham-lab/PKI-Client/main/install.sh | sudo bash -s -- uninstall
```

**Pin to a specific version:**
```bash
curl -fsSL https://raw.githubusercontent.com/rayketcham-lab/PKI-Client/main/install.sh | sudo bash -s -- v0.8.0
```

> **Note:** `sudo` must be on `bash`, not `curl`. To install without sudo, set a writable directory: `INSTALL_DIR=~/.local/bin ... | bash`

Or download manually from [GitHub Releases](https://github.com/rayketcham-lab/PKI-Client/releases):

```bash
curl -fSL -o pki.tar.gz https://github.com/rayketcham-lab/PKI-Client/releases/latest/download/pki-v0.8.0-x86_64-linux.tar.gz
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
gh attestation verify pki-v0.8.0-x86_64-linux.tar.gz --repo rayketcham-lab/PKI-Client
```

**Cosign signature (Sigstore):**
```bash
curl -fSL -o pki.tar.gz.bundle https://github.com/rayketcham-lab/PKI-Client/releases/latest/download/pki-v0.8.0-x86_64-linux.tar.gz.bundle
cosign verify-blob \
  --bundle pki-v0.8.0-x86_64-linux.tar.gz.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/rayketcham-lab/PKI-Client" \
  pki-v0.8.0-x86_64-linux.tar.gz
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
| **Cross-Validate** | Reference tools (GnuTLS, etc.) | DANE TLSA output matches reference implementations byte-for-byte |
| **Crypto Validation** | Key gen + signature algorithms | Algorithm correctness across RSA, EC, Ed25519, and PQC |
| **SCEP Enrollment** | SCEP CA server | SCEP enrollment, CA discovery, certificate retrieval |
| **OpenSSL Parity** | OpenSSL 3.x as ground truth | Cert/CSR/CRL/key/PKCS#12 field coverage and JSON schema alignment |

Interop tests run daily and on PRs that touch protocol code. Run locally:

```bash
cargo build --release
bash tests/interop/cert_roundtrip.sh
bash tests/interop/tls_probe.sh
bash tests/interop/openssl_parity.sh   # requires openssl 3.x + jq
```

### Scope boundary

`pki` is a PKI client: certificates, keys, enrollment, chain validation, revocation. It deliberately does **not** replicate the non-PKI surface of `openssl`:

- **`dgst`** — arbitrary file signing/verification (use a general-purpose signing tool)
- **`cms` / `smime`** — S/MIME message envelopes (belongs in the signing service)
- **`ts`** — RFC 3161 timestamping (belongs in the signing service)

CMS/PKCS#7 primitives are used *internally* where protocols require them (SCEP, EST), but are not exposed as top-level subcommands.

## Security

- **No OpenSSL dependency** — pure Rust crypto stack (`rustls`, `ring`, `aws-lc-rs`) eliminates C memory-safety vulnerabilities
- **No unsafe code** in application logic — only in vetted dependencies
- **Constant-time comparisons** for cryptographic material via underlying libraries (`ring`, `aws-lc-rs`)
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
