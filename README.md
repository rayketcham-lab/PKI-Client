# pki

Modern PKI CLI tool — certificate inspection, key management, TLS probing, and enrollment protocols.

Pure Rust. No OpenSSL dependency. Human-friendly output.

## Install

### From source

```bash
cargo install --git https://github.com/rayketcham-lab/pki-client.git
```

### Pre-built binaries

Download from [GitHub Releases](https://github.com/rayketcham-lab/pki-client/releases).

Static Linux binaries (musl) are available — no runtime dependencies.

## Quick start

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

## Output formats

| Format     | Flag                 | Use case                        |
|------------|----------------------|---------------------------------|
| `text`     | `--format text` (default) | Human-readable with colors |
| `json`     | `--format json`      | Scripting and automation        |
| `compact`  | `--format compact`   | One-line-per-cert dashboards    |
| `forensic` | `--format forensic`  | Deep-dive analysis, hex dumps, security grades |

## Commands

| Command      | Description                                      |
|--------------|--------------------------------------------------|
| `show`       | Auto-detect and display any PKI file             |
| `cert`       | Certificate operations (show, verify, fingerprint, expires) |
| `key`        | Key generation and inspection                    |
| `chain`      | Certificate chain building and verification      |
| `csr`        | CSR creation and inspection                      |
| `crl`        | CRL viewing and revocation checking              |
| `revoke`     | OCSP and CRL revocation status                   |
| `probe`      | TLS server inspection and linting                |
| `acme`       | ACME/Let's Encrypt certificate enrollment        |
| `est`        | EST protocol enrollment (RFC 7030)               |
| `scep`       | SCEP protocol enrollment (RFC 8894)              |
| `compliance` | FIPS 140-3, NIST, and Federal Bridge validation  |
| `dane`       | TLSA record generation (RFC 6698)                |
| `diff`       | Certificate comparison                           |
| `convert`    | Format conversion (PEM/DER/PKCS#12)              |
| `completions`| Shell completion scripts                         |
| `manpages`   | Generate man pages                               |

## Features

### Post-quantum cryptography

Build with `--features pqc` to enable ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) support.

```bash
cargo build --release --features pqc
```

### FIPS mode

Run with `--fips` to restrict operations to FIPS 140-3 approved algorithms.

```bash
pki --fips cert show server.pem
```

## Shell completions

```bash
# Bash
pki completions bash > /etc/bash_completion.d/pki

# Zsh
pki completions zsh > ~/.zfunc/_pki

# Fish
pki completions fish > ~/.config/fish/completions/pki.fish
```

## Building from source

```bash
git clone https://github.com/rayketcham-lab/pki-client.git
cd pki-client
cargo build --release
# Binary at target/release/pki
```

Static musl binary (no runtime dependencies):

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## License

MIT — see [LICENSE](LICENSE).
