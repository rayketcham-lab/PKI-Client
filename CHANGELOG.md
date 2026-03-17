# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Daily health checker workflow — feature matrix (6 permutations), MSRV check, security audit, doc build, binary size tracking, dependency freshness ([#6](https://github.com/rayketcham-lab/PKI-Client/issues/6))
- Interop test suite — ACME vs Pebble, TLS probe against public endpoints, certificate round-trip tests (49 tests total) ([#7](https://github.com/rayketcham-lab/PKI-Client/issues/7))
- Self-contained build check in CI — rejects git dependencies, gates entire pipeline ([#5](https://github.com/rayketcham-lab/PKI-Client/issues/5))
- README redesign with health dashboard, badge system, and interop section ([#8](https://github.com/rayketcham-lab/PKI-Client/issues/8))

### Changed
- Vendored `spork-core` as local path dependency — eliminates private git repo requirement ([#5](https://github.com/rayketcham-lab/PKI-Client/issues/5))
- Removed `cross-repo-token` plumbing from all CI workflows and rust-setup action ([#9](https://github.com/rayketcham-lab/PKI-Client/issues/9))
- Updated `deny.toml` to reject all git sources (`allow-git = []`)

## [0.3.0-beta.3] - 2026-03-15

### Fixed
- CI: composite `rust-setup` action replaces third-party actions
- CI: cross-repo auth for git dependencies
- Team review findings: test gaps, panic risk in forensic header, RSA security label

## [0.3.0-beta.2] - 2026-03-13

### Added
- Forensic output mode (`--format forensic`) — deep certificate analysis with hex dumps, security grades, and RFC references
- 55 certificate decode integration tests covering diverse cert types (EC, RSA, Ed25519, multi-SAN, wildcard, CA, code signing, etc.)
- Expired certificate integration test with forensic output validation
- Compact format tests (6 new tests)
- OutputFormat parsing tests including aliases (`f`, `deep`, `verbose`, `c`, `t`, `j`)

### Fixed
- EKU display bug: standard extended key usages (serverAuth, clientAuth, etc.) were silently dropped — now properly extracted and shown
- Forensic section header: use `saturating_sub` to prevent panic on titles longer than 68 characters

## [0.3.0-beta.1] - 2026-03-10

### Added
- 17 CLI subcommands: `show`, `cert`, `key`, `chain`, `csr`, `crl`, `revoke`, `probe`, `acme`, `est`, `scep`, `pki`, `compliance`, `dane`, `diff`, `convert`, `completions`
- Interactive shell mode (`pki` with no args or `pki shell`)
- Four output formats: text, json, compact, forensic
- FIPS 140-3 mode (`--fips` flag)
- Post-quantum cryptography support (`--features pqc`) for ML-DSA and SLH-DSA
- TLS server probing with security linting
- ACME, EST, and SCEP enrollment protocol clients
- Compliance checking for NIST, FIPS 140-3, and Federal Bridge policies
- DANE/TLSA record generation (RFC 6698)
- Certificate comparison (`diff`) command
- Format conversion (PEM, DER, PKCS#12)
- Shell completion generation (bash, zsh, fish)
- Man page generation
- Certificate grading system (A through F)
- CA vendor detection (Let's Encrypt, DigiCert, Sectigo, Google, Amazon, etc.)
- Validation type detection (EV, OV, DV, IV)
- CI pipeline: fmt, clippy, test, build, musl static linking, security audit, cargo-deny

### Changed
- Extracted from spork-ca monorepo into standalone project

## [0.1.0] - 2026-03-01

### Added
- Initial extraction from spork-ca-engine as standalone PKI client
