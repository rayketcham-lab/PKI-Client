# PKI Client

Modern PKI CLI tool -- certificate inspection, key management, TLS probing, and enrollment protocols.

**Version:** 0.3.0-beta.3 | **Binary:** `pki` | **License:** Apache-2.0

---

## MANDATORY Rules

### Bash Commands: NO CHAINING (CRITICAL)

- **NEVER** use `&&`, `||`, or `;` to chain commands in Bash tool calls
- Claude Code's permission system blocks compound commands
- Use separate Bash tool calls, or flags like `cargo --manifest-path`

### Code Provenance

- **ALL code is original** -- written from scratch
- **NEVER** copy code from GitHub, Stack Overflow, or other projects
- Dependencies (crates.io) are OK

---

## Architecture (4 crates + 1 tool)

```
crates/
  pki-client/          # Binary: pki (17 subcommands + interactive shell)
  pki-client-output/   # Library: formatting, OID registry
  pki-probe/           # Library: TLS inspection + linting
  pki-hierarchy/       # Library: declarative PKI hierarchy builder

tools/
  gen-signing-certs/   # Test cert generator (PQC + classical -> PFX)
```

## Dependencies

- `spork-core` -- CA crypto engine (git dep from rayketcham-lab/spork-ca-engine)

## Features

- `pqc` -- Post-quantum algorithms
- `fips` -- FIPS 140-3 mode

## Quick Reference

```bash
# Build
cargo build --release

# Test
cargo test --all

# Lint
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings

# Build with PQC
cargo build --release --features pqc
```
