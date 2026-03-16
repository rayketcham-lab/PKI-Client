# Security Policy

## Supported versions

| Version       | Supported |
|---------------|-----------|
| 0.3.x (beta)  | Yes       |
| < 0.3         | No        |

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Email security reports to: **ray@rayketcham.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Impact assessment (if known)

You should receive an acknowledgment within 48 hours. We aim to release a fix within 7 days for critical issues.

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
- Post-quantum: ML-DSA (FIPS 204), SLH-DSA (FIPS 205) behind `pqc` feature flag
- Hash algorithms: SHA-256 minimum; SHA-1 flagged as weak in output
