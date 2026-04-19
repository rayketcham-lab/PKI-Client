# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.1] - 2026-04-19

### Changed

- **Release artifacts are now native Linux installers (`.deb` + `.rpm`)** instead of raw `tar.gz` tarballs. Installers ship the statically-linked musl binary, register with the host package manager (`dpkg`/`rpm`), and install `pki` to `/usr/bin/pki`. `apt remove pki-client` / `dnf remove pki-client` now work cleanly.
- `install.sh` detects the host package format (`dpkg` or `rpm`) and installs the matching installer via the native package manager.
- `README.md` install section rewritten to document the new `.deb`/`.rpm` flow.
- `.github/workflows/release.yml` rewritten to build both installers via `cargo-deb` and `cargo-generate-rpm`, smoke-test them with `dpkg-deb`/`rpm -qip`, and sign each package artifact with Sigstore cosign + SLSA provenance.

### Added

- `[package.metadata.deb]` and `[package.metadata.generate-rpm]` sections on `crates/pki-client/Cargo.toml` — drive installer generation with full license-file, extended-description, and doc-file packaging.

### Notes

- v0.9.1 is a **packaging-only** release on top of v0.9.0. No code changes; the binary inside the installer is byte-identical to the `v0.9.0` musl build.
- If you prefer a raw static binary, extract it from the installer: `dpkg-deb -x pki-client_0.9.1_amd64.deb out/` or `rpm2cpio pki-client-0.9.1-1.x86_64.rpm | cpio -idmv`.

## [0.9.0] - 2026-04-19

### BREAKING CHANGES

- **Removed `pki acme` subcommand** (RFC 8555 ACME client) — enrollment is out of scope for this tool
- **Removed `pki est` subcommand** (RFC 7030 EST client) — enrollment is out of scope for this tool
- **Removed `pki scep` subcommand** (RFC 8894 SCEP client) — enrollment is out of scope for this tool

`pki` v0.9.0 is repositioned as an **openssl-replacement** for local PKI primitives: certificate inspection, key management, TLS probing, compliance validation, DANE, and chain building. Enrollment protocols will live in a separate `pki-enroll` tool. To continue using enrollment functionality, pin to v0.8.1.

**Full rebuild required.** The subcommand surface, shell completions, man pages, and install scripts have all changed. Regenerate completions after upgrading:

```bash
pki completions bash > /etc/bash_completion.d/pki
pki completions zsh > ~/.zfunc/_pki
pki completions fish > ~/.config/fish/completions/pki.fish
```

### Removed

- `crates/pki-client/src/acme/` — ACME client module (JWS, account management, order/challenge flows)
- `crates/pki-client/src/commands/acme/` — `pki acme` subcommand implementation
- `crates/pki-client/src/commands/est.rs` — `pki est` subcommand implementation
- `crates/pki-client/src/commands/scep.rs` — `pki scep` subcommand implementation
- `crates/pki-client/src/deployer/` — Web server deployer (Apache, Nginx, IIS) used exclusively by `pki acme install`
- `crates/pki-client/src/standalone.rs` — ACME HTTP-01 standalone challenge server
- `tests/interop/acme_pebble.sh` — ACME vs Pebble interop test
- `tests/interop/scep_enroll.sh` — SCEP enrollment interop test
- `.github/workflows/scep-interop.yml` — SCEP interop CI workflow
- `ACME vs Pebble` job from `.github/workflows/interop.yml`
- Enrollment-only crate dependencies: `aes`, `cbc`, `p256` (JWS signing), `p12` (IIS deployment), `tracing`, `zeroize`, `idna`

### Changed

- Version bumped to 0.9.0
- Subcommand count: 20 → 17
- `pki --help` no longer lists `acme`, `est`, or `scep`
- Interactive shell help text updated — enrollment command examples removed
- Shell tab-completion no longer suggests `acme`, `est`, `scep` subcommands
- README rewritten: tagline, Quick Start, Commands table, Features section, Interop table, and Scope boundary all updated for v0.9.0 scope
- CLAUDE.md updated to v0.9.0

## [0.8.0] - 2026-04-16

### Added
- Post-quantum key generation and CSR creation (FIPS 204 / FIPS 205 algorithms — ML-DSA-44/65/87, SLH-DSA-128s/192s/256s) via RustCrypto pre-release crates; gated behind `--features pqc` and `--algorithm` flag
- `--format openssl` (`-f os`) output — reproduces `openssl x509 -text -noout` layout with PKI Client lifetime/trust extensions
- FIPS gate in PR CI pipeline — clippy and test jobs for `--features fips` feature set
- Cross-validation interop test suite — fingerprint, serial, validity, key size, PEM round-trip checks against a reference tool
- Enterprise PKI, Tacoo Tuesday, Signing Service, Vision, and Quantum Ops asciinema demo casts

### Changed
- README hardened — dead demo links removed, demo tabs are clickable shareable URLs, version/count badges fixed, HSM roadmap noted, wild "zero C deps" claims toned down
- All first-party crates enforce `#![forbid(unsafe_code)]` at source level
- ML-DSA key display shows NIST Level instead of "0 bit"
- `pki cert` text-mode output truncates RSA modulus; forensic mode still shows full hex

### Fixed
- **Security (TOCTOU)**: sensitive file writes now set 0600 permissions atomically via `OpenOptions::mode` (no `fs::write` + `set_permissions` race). Applies to private keys, passphrases, PFX buffers in ACME, EST, SCEP, and hierarchy export
- Shell subcommand correctly parses flags before positional args ([#47](https://github.com/rayketcham-lab/PKI-Client/issues/47))
- `pki convert` auto-detects DER-encoded private keys ([#59](https://github.com/rayketcham-lab/PKI-Client/issues/59))
- `pki probe` respects `host:port` target string ([#50](https://github.com/rayketcham-lab/PKI-Client/issues/50))
- SCEP RSA-2048 test guarded against runtime FIPS mode
- Daily Health Check CI failures across feature combos resolved
- Integration tests hardened against FIPS feature and remaining race guards
- `unused_mut` clippy warning suppressed in `--no-default-features` build
- Cross-repo-token plumbing removed from all CI workflows

### Security
- SecOps review findings addressed for v0.7.0 posture
- `deny.toml` rejects all git sources (`allow-git = []`); advisory review cadence documented
- API surface hardened around sensitive file I/O

## [0.7.0] - 2026-04-01

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
