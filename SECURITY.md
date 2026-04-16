# Security Policy

## Supported versions

| Version       | Supported |
|---------------|-----------|
| 0.8.x         | Yes       |
| 0.7.x         | No        |
| < 0.7         | No        |

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Email security reports to: **ray@rayketcham.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Impact assessment (if known)

You should receive an acknowledgment within 48 hours. We aim to release a fix within 7 days for critical issues.

## Supply chain security

Every release binary is built, signed, and published by GitHub Actions — no human touches the artifact.

| Protection | Tool | How to verify |
|---|---|---|
| **Checksum** | SHA-256 | `sha256sum -c SHA256SUMS.txt` |
| **Build provenance** | [SLSA](https://slsa.dev/) via GitHub Attestations | `gh attestation verify <file> --repo rayketcham-lab/PKI-Client` |
| **Artifact signing** | [Sigstore cosign](https://www.sigstore.dev/) (keyless) | `cosign verify-blob --bundle <file>.bundle ...` |
| **Dependency vendoring** | Cargo vendor | CI enforces vendored deps match `Cargo.lock`; zero git dependencies |
| **Dependency audit** | `cargo-audit` + `cargo-deny` | Runs on every commit; zero-tolerance policy |
| **Action pinning** | SHA-pinned GitHub Actions | Org-enforced full commit SHA pins on all CI actions |

### Verifying a release

```bash
# 1. SHA256 checksum
curl -fSL -o SHA256SUMS.txt https://github.com/rayketcham-lab/PKI-Client/releases/latest/download/SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt

# 2. GitHub attestation (proves binary was built from this repo by CI)
gh attestation verify pki-*.tar.gz --repo rayketcham-lab/PKI-Client

# 3. Cosign signature (Sigstore — independent of GitHub)
cosign verify-blob \
  --bundle pki-*.tar.gz.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/rayketcham-lab/PKI-Client" \
  pki-*.tar.gz
```

## Security design

- **No OpenSSL dependency** — pure Rust TLS/crypto stack (`rustls`, `ring`, `aws-lc-rs`)
- **No unsafe code** in application or library crates
- **Zero warnings** policy enforced in CI (`clippy -D warnings`)
- **Dependency auditing** via `cargo-audit` and `cargo-deny` on every commit
- **Input validation** at all trust boundaries (file parsing, network input, CLI args)
- **SSRF protection** on URL inputs (protocol and host validation)
- **No secret logging** — keys and private material are never written to stdout/stderr in plaintext

## Cryptographic standards

- RSA: minimum 2048-bit keys enforced in FIPS mode
- EC: P-256, P-384, P-521 (NIST curves)
- Post-quantum: ML-DSA (FIPS 204 algorithm) and SLH-DSA (FIPS 205 algorithm) behind `pqc` feature flag via RustCrypto pre-release crates (`ml-dsa`, `slh-dsa`); not a FIPS-validated module
- Hash algorithms: SHA-256 minimum; SHA-1 flagged as weak in output
