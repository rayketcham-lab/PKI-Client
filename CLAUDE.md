# PKI Client

Modern PKI CLI tool -- certificate inspection, key management, TLS probing, and enrollment protocols.

**Version:** 0.6.7 | **Binary:** `pki` | **License:** Apache-2.0

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

## Architecture (4 crates + 1 vendored + 1 tool)

```
crates/
  pki-client/          # Binary: pki (19 subcommands + interactive shell)
  pki-client-output/   # Library: formatting, OID registry
  pki-probe/           # Library: TLS inspection + linting
  pki-hierarchy/       # Library: declarative PKI hierarchy builder

vendor/
  spork-core/          # Vendored CA crypto engine (from spork-ca-engine)

tools/
  gen-signing-certs/   # Test cert generator (PQC + classical -> PFX)

tests/
  interop/             # Interop test scripts (ACME/Pebble, TLS probe, cert round-trip)
```

## Dependencies

- `spork-core` -- CA crypto engine (vendored under vendor/spork-core/)
- **No git dependencies** -- all deps are vendored or from crates.io (enforced by CI)

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
