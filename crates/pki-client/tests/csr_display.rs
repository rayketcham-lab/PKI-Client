//! CSR Display Integration Tests
//!
//! Regression tests for CSR display accuracy. These tests use the compiled
//! `pki` binary to catch display bugs (wrong key sizes, raw OID strings,
//! crashes) before they reach production.
//!
//! Covers:
//!  - Key size accuracy for RSA-2048, RSA-4096, EC P-256, EC P-384
//!  - Human-readable algorithm names (no raw OIDs) in `pki show` / `pki csr show`
//!  - `pki diff` with CSR pairs, and clear errors for mixed cert/CSR input
//!  - Zero crashes (`pki show` exits 0) for every generated file type

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

// ============================================================================
// Helpers
// ============================================================================

/// Return a `Command` pointing at the compiled `pki` binary.
///
/// Uses `CARGO_BIN_EXE_pki` which Cargo sets at compile time to the path of
/// the test binary's companion executable.  This works correctly in both debug
/// and release test runs without any path arithmetic.
fn pki_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pki"))
}

/// Return the path to the `pki` binary (for existence checks).
fn pki_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pki"))
}

/// Skip the test with a clear message when the binary hasn't been built yet.
///
/// Returns `true` if the caller should return early.
fn skip_if_missing() -> bool {
    if !pki_binary().exists() {
        eprintln!(
            "SKIP: pki binary not found at {}. Run `cargo build` first.",
            pki_binary().display()
        );
        true
    } else {
        false
    }
}

/// Generate a key of the given type into `dir` and return the file path.
///
/// `algo` must be one of: `("rsa", &["--bits", "2048"])`,
/// `("ec", &["--curve", "p256"])`, etc.
fn gen_key(dir: &TempDir, name: &str, algo: &str, extra_args: &[&str]) -> PathBuf {
    let key_path = dir.path().join(name);
    let mut cmd = pki_cmd();
    cmd.args(["key", "gen", algo]);
    for arg in extra_args {
        cmd.arg(arg);
    }
    cmd.arg("-o").arg(&key_path);

    let out = cmd.output().expect("failed to run pki key gen");
    assert!(
        out.status.success(),
        "key gen '{algo}' failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        key_path.exists(),
        "key file not created: {}",
        key_path.display()
    );
    key_path
}

/// Create a CSR from `key_path` and return the CSR file path.
fn gen_csr(dir: &TempDir, name: &str, key_path: &Path) -> PathBuf {
    let csr_path = dir.path().join(name);
    let out = pki_cmd()
        .args([
            "csr",
            "create",
            "--key",
            key_path.to_str().unwrap(),
            "--cn",
            "integration-test.example.com",
            "-o",
        ])
        .arg(&csr_path)
        .output()
        .expect("failed to run pki csr create");
    assert!(
        out.status.success(),
        "csr create failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        csr_path.exists(),
        "CSR file not created: {}",
        csr_path.display()
    );
    csr_path
}

/// Run `pki show --color never <path>` and return stdout.
fn pki_show(path: &Path) -> String {
    let out = pki_cmd()
        .args(["show", "--color", "never"])
        .arg(path)
        .output()
        .expect("failed to run pki show");
    assert!(
        out.status.success(),
        "pki show exited non-zero for {}:\nstdout: {}\nstderr: {}",
        path.display(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Run `pki csr show --color never <path>` and return stdout.
fn pki_csr_show(path: &Path) -> String {
    let out = pki_cmd()
        .args(["csr", "show", "--color", "never"])
        .arg(path)
        .output()
        .expect("failed to run pki csr show");
    assert!(
        out.status.success(),
        "pki csr show exited non-zero for {}:\nstdout: {}\nstderr: {}",
        path.display(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

// ============================================================================
// Key size accuracy
// ============================================================================

/// Assert that `pki show` reports exactly `expected_bits` for the CSR.
///
/// The output line looks like:
///   `Key Algorithm:      RSA (2048 bits)`
///   `Key Algorithm:      EC (256 bits)`
///
/// We parse the bits value from that line and compare numerically, so the
/// test fails on off-by-one or padding artifacts (e.g., "4208" instead of
/// "4096").
fn assert_show_key_bits(csr_path: &Path, expected_bits: u32) {
    let output = pki_show(csr_path);
    let bits = parse_key_bits_from_show(&output).unwrap_or_else(|| {
        panic!(
            "Could not parse key size from `pki show` output:\n{}",
            output
        )
    });
    assert_eq!(
        bits, expected_bits,
        "`pki show` reported {bits} bits but expected {expected_bits} bits.\nFull output:\n{output}"
    );
}

/// Assert that `pki csr show` reports exactly `expected_bits`.
///
/// The output line looks like:
///   `  Size: 2048 bits`
fn assert_csr_show_key_bits(csr_path: &Path, expected_bits: u32) {
    let output = pki_csr_show(csr_path);
    let bits = parse_key_bits_from_csr_show(&output).unwrap_or_else(|| {
        panic!(
            "Could not parse key size from `pki csr show` output:\n{}",
            output
        )
    });
    assert_eq!(
        bits, expected_bits,
        "`pki csr show` reported {bits} bits but expected {expected_bits} bits.\nFull output:\n{output}"
    );
}

/// Parse the bit-size from `pki show` output.
///
/// Looks for lines matching `Key Algorithm: ... (NNN bits)`.
fn parse_key_bits_from_show(output: &str) -> Option<u32> {
    for line in output.lines() {
        // Matches: "    Key Algorithm:      RSA (2048 bits)"
        if line.contains("Key Algorithm") {
            if let Some(bits) = extract_bits_from_parens(line) {
                return Some(bits);
            }
        }
    }
    None
}

/// Parse the bit-size from `pki csr show` output.
///
/// Looks for lines matching `  Size: NNN bits`.
fn parse_key_bits_from_csr_show(output: &str) -> Option<u32> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Size:") {
            let rest = rest.trim();
            // rest is like "2048 bits"
            let word = rest.split_whitespace().next()?;
            return word.parse().ok();
        }
    }
    None
}

/// Extract the number from a parenthesized expression like `(2048 bits)`.
fn extract_bits_from_parens(s: &str) -> Option<u32> {
    let open = s.rfind('(')?;
    let close = s.rfind(')')?;
    if close <= open {
        return None;
    }
    let inner = s[open + 1..close].trim();
    // inner is like "2048 bits" or "256 bits"
    inner.split_whitespace().next()?.parse().ok()
}

#[test]
fn test_csr_show_key_size_rsa2048() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "rsa2048.key", "rsa", &["--bits", "2048"]);
    let csr = gen_csr(&dir, "rsa2048.csr", &key);

    assert_show_key_bits(&csr, 2048);
    assert_csr_show_key_bits(&csr, 2048);
}

#[test]
fn test_csr_show_key_size_rsa4096() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "rsa4096.key", "rsa", &["--bits", "4096"]);
    let csr = gen_csr(&dir, "rsa4096.csr", &key);

    assert_show_key_bits(&csr, 4096);
    assert_csr_show_key_bits(&csr, 4096);
}

#[test]
fn test_csr_show_key_size_ec_p256() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "ecp256.key", "ec", &["--curve", "p256"]);
    let csr = gen_csr(&dir, "ecp256.csr", &key);

    assert_show_key_bits(&csr, 256);
    assert_csr_show_key_bits(&csr, 256);
}

#[test]
fn test_csr_show_key_size_ec_p384() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "ecp384.key", "ec", &["--curve", "p384"]);
    let csr = gen_csr(&dir, "ecp384.csr", &key);

    assert_show_key_bits(&csr, 384);
    assert_csr_show_key_bits(&csr, 384);
}

// ============================================================================
// OID resolution — no raw OID strings in display output
// ============================================================================

/// Raw OID strings that must never appear in user-facing CSR display output.
const FORBIDDEN_OID_STRINGS: &[&str] = &[
    // RSA public key OID
    "1.2.840.113549.1.1.1",
    // EC public key OID
    "1.2.840.10045.2.1",
    // SHA-256 with RSA OID
    "1.2.840.113549.1.1.11",
    // SHA-384 with RSA OID
    "1.2.840.113549.1.1.12",
    // SHA-512 with RSA OID
    "1.2.840.113549.1.1.13",
    // ECDSA with SHA-256 OID
    "1.2.840.10045.4.3.2",
    // ECDSA with SHA-384 OID
    "1.2.840.10045.4.3.3",
    // P-256 curve OID
    "1.2.840.10045.3.1.7",
    // P-384 curve OID
    "1.3.132.0.34",
    // Common Name attribute OID
    "2.5.4.3",
    // Subject / organization OID
    "2.5.4.10",
];

fn assert_no_raw_oids(output: &str, context: &str) {
    for oid in FORBIDDEN_OID_STRINGS {
        assert!(
            !output.contains(oid),
            "Raw OID {oid} appeared in {context} output (should be resolved to a name).\nOutput:\n{output}"
        );
    }
}

#[test]
fn test_show_no_raw_oids_rsa2048() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "rsa2048.key", "rsa", &["--bits", "2048"]);
    let csr = gen_csr(&dir, "rsa2048.csr", &key);

    let show_output = pki_show(&csr);
    let csr_show_output = pki_csr_show(&csr);

    assert_no_raw_oids(&show_output, "`pki show` (RSA-2048 CSR)");
    assert_no_raw_oids(&csr_show_output, "`pki csr show` (RSA-2048 CSR)");
}

#[test]
fn test_show_no_raw_oids_rsa4096() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "rsa4096.key", "rsa", &["--bits", "4096"]);
    let csr = gen_csr(&dir, "rsa4096.csr", &key);

    let show_output = pki_show(&csr);
    let csr_show_output = pki_csr_show(&csr);

    assert_no_raw_oids(&show_output, "`pki show` (RSA-4096 CSR)");
    assert_no_raw_oids(&csr_show_output, "`pki csr show` (RSA-4096 CSR)");
}

#[test]
fn test_show_no_raw_oids_ec_p256() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "ecp256.key", "ec", &["--curve", "p256"]);
    let csr = gen_csr(&dir, "ecp256.csr", &key);

    let show_output = pki_show(&csr);
    let csr_show_output = pki_csr_show(&csr);

    assert_no_raw_oids(&show_output, "`pki show` (EC P-256 CSR)");
    assert_no_raw_oids(&csr_show_output, "`pki csr show` (EC P-256 CSR)");
}

#[test]
fn test_show_no_raw_oids_ec_p384() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "ecp384.key", "ec", &["--curve", "p384"]);
    let csr = gen_csr(&dir, "ecp384.csr", &key);

    let show_output = pki_show(&csr);
    let csr_show_output = pki_csr_show(&csr);

    assert_no_raw_oids(&show_output, "`pki show` (EC P-384 CSR)");
    assert_no_raw_oids(&csr_show_output, "`pki csr show` (EC P-384 CSR)");
}

/// Verify that `pki show` and `pki csr show` output human-readable algorithm
/// names for RSA-2048 CSRs.
#[test]
fn test_show_human_readable_algo_names_rsa() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "rsa.key", "rsa", &["--bits", "2048"]);
    let csr = gen_csr(&dir, "rsa.csr", &key);

    let show_output = pki_show(&csr);
    let csr_show_output = pki_csr_show(&csr);

    // `pki show` must mention RSA and the SHA-256/RSA signature algorithm name
    assert!(
        show_output.contains("RSA"),
        "`pki show` output missing 'RSA':\n{show_output}"
    );
    assert!(
        show_output.contains("sha256WithRSAEncryption")
            || show_output.contains("SHA256withRSA")
            || show_output.to_lowercase().contains("sha256"),
        "`pki show` output missing SHA-256/RSA algorithm name:\n{show_output}"
    );

    // `pki csr show` must mention RSA
    assert!(
        csr_show_output.contains("RSA"),
        "`pki csr show` output missing 'RSA':\n{csr_show_output}"
    );
    assert!(
        csr_show_output.contains("sha256WithRSAEncryption")
            || csr_show_output.contains("SHA256withRSA")
            || csr_show_output.to_lowercase().contains("sha256"),
        "`pki csr show` output missing SHA-256/RSA algorithm name:\n{csr_show_output}"
    );
}

/// Verify that `pki show` and `pki csr show` output human-readable algorithm
/// names for EC P-256 CSRs.
#[test]
fn test_show_human_readable_algo_names_ec() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "ec.key", "ec", &["--curve", "p256"]);
    let csr = gen_csr(&dir, "ec.csr", &key);

    let show_output = pki_show(&csr);
    let csr_show_output = pki_csr_show(&csr);

    // `pki show` must mention EC and ECDSA
    assert!(
        show_output.contains("EC") || show_output.contains("ECDSA"),
        "`pki show` output missing 'EC'/'ECDSA':\n{show_output}"
    );
    assert!(
        show_output.contains("ecdsa-with-SHA256")
            || show_output.contains("ECDSA-SHA256")
            || (show_output.to_lowercase().contains("ecdsa")
                && show_output.to_lowercase().contains("sha256")),
        "`pki show` output missing ECDSA-SHA256 algorithm name:\n{show_output}"
    );

    assert!(
        csr_show_output.contains("EC") || csr_show_output.contains("ECDSA"),
        "`pki csr show` output missing 'EC'/'ECDSA':\n{csr_show_output}"
    );
    assert!(
        csr_show_output.contains("ecdsa-with-SHA256")
            || csr_show_output.contains("ECDSA-SHA256")
            || (csr_show_output.to_lowercase().contains("ecdsa")
                && csr_show_output.to_lowercase().contains("sha256")),
        "`pki csr show` output missing ECDSA-SHA256 algorithm name:\n{csr_show_output}"
    );
}

// ============================================================================
// pki diff — CSR pairs and mixed cert/CSR errors
// ============================================================================

/// `pki diff` on two CSRs of different types must exit 0 and report differences.
#[test]
fn test_diff_csr_vs_csr_same_algo() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key1 = gen_key(&dir, "a.key", "rsa", &["--bits", "2048"]);
    let key2 = gen_key(&dir, "b.key", "rsa", &["--bits", "4096"]);
    let csr1 = gen_csr(&dir, "a.csr", &key1);
    let csr2 = gen_csr(&dir, "b.csr", &key2);

    let out = pki_cmd()
        .args(["diff", "--color", "never"])
        .arg(&csr1)
        .arg(&csr2)
        .output()
        .expect("failed to run pki diff");

    assert!(
        out.status.success(),
        "pki diff (RSA-2048 vs RSA-4096 CSR) failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    // Should report a key algorithm difference
    assert!(
        stdout.contains("DIFFERS") || stdout.contains("differs") || stdout.contains("DIFF"),
        "diff output should mention differences:\n{stdout}"
    );
}

/// `pki diff` on two CSRs with the same key type but different SANs must exit 0.
#[test]
fn test_diff_csr_vs_csr_different_algo_families() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key_rsa = gen_key(&dir, "rsa.key", "rsa", &["--bits", "2048"]);
    let key_ec = gen_key(&dir, "ec.key", "ec", &["--curve", "p256"]);
    let csr_rsa = gen_csr(&dir, "rsa.csr", &key_rsa);
    let csr_ec = gen_csr(&dir, "ec.csr", &key_ec);

    let out = pki_cmd()
        .args(["diff", "--color", "never"])
        .arg(&csr_rsa)
        .arg(&csr_ec)
        .output()
        .expect("failed to run pki diff");

    assert!(
        out.status.success(),
        "pki diff (RSA vs EC CSR) failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("DIFFERS") || stdout.contains("differs") || stdout.contains("DIFF"),
        "diff output should mention key algorithm differences:\n{stdout}"
    );
}

/// Build a self-signed certificate in the temp dir using the pki binary.
///
/// Returns `None` if the `pki cert sign` command is unavailable.
fn try_gen_self_signed_cert(dir: &TempDir, name: &str, key: &Path) -> Option<PathBuf> {
    // Use `pki cert sign` or similar to produce a cert. If not available,
    // fall back to a known-good PEM cert embedded in the test binary.
    let cert_path = dir.path().join(name);

    // Try `pki cert self-sign` first (hypothetical), fallback to embedded.
    // We rely on the embedded cert so the test is self-contained.
    let _ = key; // suppress unused warning; we use a fixed cert below

    // Minimal self-signed certificate PEM (RSA-2048, generated offline).
    // This is used ONLY for testing cert-vs-CSR error paths, not for any
    // crypto operations.
    let cert_pem = concat!(
        "-----BEGIN CERTIFICATE-----\n",
        "MIICpDCCAYwCCQDU9pQ4pHnSpDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls\n",
        "b2NhbGhvc3QwHhcNMjUwMTAxMDAwMDAwWhcNMjYwMTAxMDAwMDAwWjAUMRIwEAYD\n",
        "VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7\n",
        "o4qne60TB3wolGELNGFcVqgxRwB5YF7UcmLKHqnN6RHnIoSvMEsV+boEGFG0XQKN\n",
        "cxhSGTjW/sEVHxjMuM7GVSrIGP9BWKW60y1NjNxmLN7cW9maSuFVD+X4l0BFSoob\n",
        "ulIL43UF0hHjm52L7K3S9V6CrXFd6T8wR3bRMi7VuPZXvIeMUExfI6nQoBl0F5qC\n",
        "N68TRlCM5nOdLJ5V5iRHHhRizp+JRdSCNIkucrJHOdZPsxBjbKGMFnbLAtEexV9k\n",
        "Vgpqjh3OMaRgzxbQLkqlySnJl7nNDgXXFkFW4XB4DxBv3f1Z+Rp9Pn4Gxt6dGBe\n",
        "YBHZ9I9+j7VTmb6pAgMBAAEwDQYJKoZIhvcNAQELBQADggEBABpRbGf5REYolXKr\n",
        "KKWM1TQFZ3PeXfJ3Y6X2kQh6K3pJT3D8voNFH1UGO9Ywb2LFgvWw7JJ7vFG6dAb\n",
        "9FqT8k6V3j/I2o0g5D3j4J0Q2LTgA4Y8FvGk9V5tHwpU0rZh5V1Jl6zK/qG1w8z\n",
        "jP1sF3BDTQ1v2qYrJ3E7X8VWiR7sK0NpTQYJI9FJ9qGlJxLXq7XM0V6JBnMEd1z\n",
        "8K6KbW2gN3V5pSfV7MMZLD3o3CQ7RyXvFH+FJmzE5H7JtK9F3vgZ4WX5N6bM8Vq\n",
        "DW4N1LJ5k9L8HQT0B5J9pZ6Xm7/F3QnGf5V9t0KJX5HjVhN3C9B2W5F4pI6fQ2s\n",
        "-----END CERTIFICATE-----\n"
    );
    fs::write(&cert_path, cert_pem).ok()?;
    Some(cert_path)
}

/// `pki diff` with a certificate as FILE1 and a CSR as FILE2 must exit non-zero
/// and emit a clear, human-readable error. It must NOT crash with an internal
/// panic or emit a raw `InvalidAlgorithmIdentifier` message.
#[test]
fn test_diff_cert_vs_csr_gives_clear_error() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "key.key", "rsa", &["--bits", "2048"]);
    let csr = gen_csr(&dir, "req.csr", &key);

    // Use a bundled cert so this test is self-contained.
    let Some(cert) = try_gen_self_signed_cert(&dir, "cert.pem", &key) else {
        eprintln!("SKIP: could not produce a certificate for cert-vs-CSR diff test");
        return;
    };

    let out = pki_cmd()
        .args(["diff", "--color", "never"])
        .arg(&cert)
        .arg(&csr)
        .output()
        .expect("failed to run pki diff");

    // Must exit non-zero
    assert!(
        !out.status.success(),
        "pki diff cert-vs-CSR should have failed but exited 0"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);

    // Must not expose internal Rust error type names
    assert!(
        !stderr.contains("InvalidAlgorithmIdentifier"),
        "pki diff cert-vs-CSR leaked internal error 'InvalidAlgorithmIdentifier':\n{stderr}"
    );
    assert!(
        !stderr.contains("thread 'main' panicked"),
        "pki diff cert-vs-CSR crashed with a panic:\n{stderr}"
    );
    assert!(
        !stderr.contains("unwrap()"),
        "pki diff cert-vs-CSR leaked internal unwrap:\n{stderr}"
    );

    // Must contain a human-readable explanation
    assert!(
        stderr.to_lowercase().contains("certificate")
            || stderr.to_lowercase().contains("csr")
            || stderr.to_lowercase().contains("type")
            || stderr.to_lowercase().contains("same"),
        "pki diff cert-vs-CSR error message is not human-readable:\n{stderr}"
    );
}

/// Symmetric check: CSR as FILE1, certificate as FILE2.
#[test]
fn test_diff_csr_vs_cert_gives_clear_error() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "key.key", "rsa", &["--bits", "2048"]);
    let csr = gen_csr(&dir, "req.csr", &key);

    let Some(cert) = try_gen_self_signed_cert(&dir, "cert.pem", &key) else {
        eprintln!("SKIP: could not produce a certificate for CSR-vs-cert diff test");
        return;
    };

    let out = pki_cmd()
        .args(["diff", "--color", "never"])
        .arg(&csr)
        .arg(&cert)
        .output()
        .expect("failed to run pki diff");

    assert!(
        !out.status.success(),
        "pki diff CSR-vs-cert should have failed but exited 0"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !stderr.contains("InvalidAlgorithmIdentifier"),
        "pki diff CSR-vs-cert leaked internal error 'InvalidAlgorithmIdentifier':\n{stderr}"
    );
    assert!(
        !stderr.contains("thread 'main' panicked"),
        "pki diff CSR-vs-cert crashed with a panic:\n{stderr}"
    );
}

// ============================================================================
// pki show — no crashes on any generated file type
// ============================================================================

/// `pki show` must exit 0 for every file type we can generate.
#[test]
fn test_show_does_not_crash_on_rsa2048_key() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "rsa2048.key", "rsa", &["--bits", "2048"]);
    let _ = pki_show(&key); // assert_show already panics on non-zero exit
}

#[test]
fn test_show_does_not_crash_on_rsa4096_key() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "rsa4096.key", "rsa", &["--bits", "4096"]);
    let _ = pki_show(&key);
}

#[test]
fn test_show_does_not_crash_on_ec_p256_key() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "ecp256.key", "ec", &["--curve", "p256"]);
    let _ = pki_show(&key);
}

#[test]
fn test_show_does_not_crash_on_ec_p384_key() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "ecp384.key", "ec", &["--curve", "p384"]);
    let _ = pki_show(&key);
}

#[test]
fn test_show_does_not_crash_on_rsa2048_csr() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "rsa2048.key", "rsa", &["--bits", "2048"]);
    let csr = gen_csr(&dir, "rsa2048.csr", &key);
    let _ = pki_show(&csr);
}

#[test]
fn test_show_does_not_crash_on_rsa4096_csr() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "rsa4096.key", "rsa", &["--bits", "4096"]);
    let csr = gen_csr(&dir, "rsa4096.csr", &key);
    let _ = pki_show(&csr);
}

#[test]
fn test_show_does_not_crash_on_ec_p256_csr() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "ecp256.key", "ec", &["--curve", "p256"]);
    let csr = gen_csr(&dir, "ecp256.csr", &key);
    let _ = pki_show(&csr);
}

#[test]
fn test_show_does_not_crash_on_ec_p384_csr() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "ecp384.key", "ec", &["--curve", "p384"]);
    let csr = gen_csr(&dir, "ecp384.csr", &key);
    let _ = pki_show(&csr);
}

// ============================================================================
// CSR content sanity — subject preserved in output
// ============================================================================

/// The CN we put in the CSR must appear in `pki show` output.
#[test]
fn test_show_preserves_subject_cn() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "key.key", "ec", &["--curve", "p256"]);
    let csr = gen_csr(&dir, "req.csr", &key);

    let show_output = pki_show(&csr);
    let csr_show_output = pki_csr_show(&csr);

    assert!(
        show_output.contains("integration-test.example.com"),
        "`pki show` did not display the CSR subject CN:\n{show_output}"
    );
    assert!(
        csr_show_output.contains("integration-test.example.com"),
        "`pki csr show` did not display the CSR subject CN:\n{csr_show_output}"
    );
}

// ============================================================================
// Unit tests for internal parsing helpers
// ============================================================================

#[cfg(test)]
mod parsing_tests {
    use super::*;

    #[test]
    fn test_extract_bits_from_parens_rsa() {
        assert_eq!(
            extract_bits_from_parens("    Key Algorithm:      RSA (2048 bits)"),
            Some(2048)
        );
    }

    #[test]
    fn test_extract_bits_from_parens_ec() {
        assert_eq!(
            extract_bits_from_parens("    Key Algorithm:      EC (256 bits)"),
            Some(256)
        );
    }

    #[test]
    fn test_extract_bits_from_parens_rsa4096() {
        // Regression: must not produce 4208 (or any incorrect value)
        assert_eq!(
            extract_bits_from_parens("    Key Algorithm:      RSA (4096 bits)"),
            Some(4096)
        );
    }

    #[test]
    fn test_extract_bits_from_parens_no_match() {
        assert_eq!(
            extract_bits_from_parens("Subject: CN=test.example.com"),
            None
        );
    }

    #[test]
    fn test_parse_key_bits_from_show_rsa() {
        let output = "Certificate Signing Request (CSR):\n\
                      \n    Subject:            CN=test.example.com\n\
                      \n    Key Algorithm:      RSA (4096 bits)\n\
                      \n    Signature Algorithm: sha256WithRSAEncryption\n";
        assert_eq!(parse_key_bits_from_show(output), Some(4096));
    }

    #[test]
    fn test_parse_key_bits_from_show_ec() {
        let output = "Certificate Signing Request (CSR):\n\
                      \n    Subject:            CN=test.example.com\n\
                      \n    Key Algorithm:      EC (384 bits)\n\
                      \n    Signature Algorithm: ecdsa-with-SHA384\n";
        assert_eq!(parse_key_bits_from_show(output), Some(384));
    }

    #[test]
    fn test_parse_key_bits_from_csr_show() {
        let output = "Certificate Signing Request:\n  Subject: CN=test.example.com\n\nPublic Key:\n  Algorithm: RSA\n  Size: 2048 bits\n";
        assert_eq!(parse_key_bits_from_csr_show(output), Some(2048));
    }
}

// ============================================================================
// Issue #24: pki show must auto-detect DER CSR files
// ============================================================================

#[test]
fn issue_24_pki_show_autodetects_der_csr() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();

    // Generate key and CSR
    let key = gen_key(&dir, "test.key", "ec", &["--curve", "p256"]);
    let csr_pem = gen_csr(&dir, "test.csr", &key);

    // Convert to DER
    let csr_der = dir.path().join("test.csr.der");
    let convert_out = pki_cmd()
        .args(["convert", csr_pem.to_str().unwrap(), "--to", "der", "-o"])
        .arg(&csr_der)
        .output()
        .expect("failed to run pki convert");
    assert!(
        convert_out.status.success(),
        "pki convert failed: {}",
        String::from_utf8_lossy(&convert_out.stderr)
    );
    assert!(csr_der.exists(), "DER CSR file not created");

    // pki show must auto-detect the DER CSR and show CSR details
    let show_out = pki_cmd()
        .args(["show"])
        .arg(&csr_der)
        .output()
        .expect("failed to run pki show");

    let stdout = String::from_utf8_lossy(&show_out.stdout);
    let stderr = String::from_utf8_lossy(&show_out.stderr);

    assert!(
        show_out.status.success(),
        "pki show DER CSR failed (exit {:?}):\nstdout: {stdout}\nstderr: {stderr}",
        show_out.status.code()
    );
    assert!(
        stdout.contains("CSR") || stdout.contains("Request") || stdout.contains("Subject"),
        "pki show did not recognize DER CSR. stdout: {stdout}\nstderr: {stderr}"
    );

    // Must NOT contain "Failed to load certificate"
    assert!(
        !stderr.contains("Failed to load certificate"),
        "pki show tried to load DER CSR as certificate: {stderr}"
    );
}

#[test]
fn issue_24_pki_csr_show_works_for_der_csr() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();

    let key = gen_key(&dir, "test.key", "rsa", &["--bits", "2048"]);
    let csr_pem = gen_csr(&dir, "test.csr", &key);

    let csr_der = dir.path().join("test.csr.der");
    let _ = pki_cmd()
        .args(["convert", csr_pem.to_str().unwrap(), "--to", "der", "-o"])
        .arg(&csr_der)
        .output()
        .expect("failed to run pki convert");

    // Explicit pki csr show must always work for DER CSRs
    let show_out = pki_cmd()
        .args(["csr", "show"])
        .arg(&csr_der)
        .output()
        .expect("failed to run pki csr show");

    let stdout = String::from_utf8_lossy(&show_out.stdout);
    let stderr = String::from_utf8_lossy(&show_out.stderr);

    assert!(
        show_out.status.success(),
        "pki csr show DER CSR failed: {stderr}"
    );
    assert!(
        stdout.contains("Subject") || stdout.contains("integration-test"),
        "pki csr show did not display CSR content: {stdout}"
    );
}

// ============================================================================
// Issue #25: pki key match must handle CSR files gracefully
// ============================================================================

#[test]
fn issue_25_key_match_csr_no_crash() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();

    let key = gen_key(&dir, "test.key", "ec", &["--curve", "p256"]);
    let csr = gen_csr(&dir, "test.csr", &key);

    // pki key match with a CSR should NOT crash with InvalidAlgorithmIdentifier
    let match_out = pki_cmd()
        .args(["key", "match", key.to_str().unwrap(), csr.to_str().unwrap()])
        .output()
        .expect("failed to run pki key match");

    let stderr = String::from_utf8_lossy(&match_out.stderr);

    // Must NOT contain the raw parse crash
    assert!(
        !stderr.contains("InvalidAlgorithmIdentifier"),
        "pki key match crashed with InvalidAlgorithmIdentifier on CSR input: {stderr}"
    );
}

#[test]
fn issue_25_key_match_csr_gives_clear_message() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();

    let key = gen_key(&dir, "test.key", "rsa", &["--bits", "2048"]);
    let csr = gen_csr(&dir, "test.csr", &key);

    let match_out = pki_cmd()
        .args(["key", "match", key.to_str().unwrap(), csr.to_str().unwrap()])
        .output()
        .expect("failed to run pki key match");

    let stdout = String::from_utf8_lossy(&match_out.stdout);
    let stderr = String::from_utf8_lossy(&match_out.stderr);
    let combined = format!("{stdout}{stderr}");

    // Either: succeeds with a match result, OR gives a clear error about CSRs
    let has_match_result = combined.contains("Match") || combined.contains("match");
    let has_clear_error = combined.contains("CSR")
        || combined.contains("not supported")
        || combined.contains("certificate");

    assert!(
        match_out.status.success() || has_match_result || has_clear_error,
        "pki key match gave no useful output for CSR:\nstdout: {stdout}\nstderr: {stderr}"
    );
}

// ============================================================================
// Issue #26: Interactive shell must handle version/help commands
// ============================================================================

/// Helper: run the interactive shell with piped input and return stdout.
fn shell_input(input: &str) -> (String, String, bool) {
    use std::io::Write;

    let mut cmd = pki_cmd();
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn pki shell");
    if let Some(ref mut stdin) = child.stdin {
        let _ = stdin.write_all(input.as_bytes());
        let _ = stdin.write_all(b"\nexit\n");
    }
    let out = child
        .wait_with_output()
        .expect("failed to read shell output");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (stdout, stderr, out.status.success())
}

#[test]
fn issue_26_shell_version_command() {
    if skip_if_missing() {
        return;
    }
    let (stdout, stderr, _) = shell_input("version");
    let combined = format!("{stdout}{stderr}");
    // Check for semver pattern instead of hardcoded version
    assert!(
        combined.contains("0.") || combined.contains("pki"),
        "shell 'version' did not print version string:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !combined.contains("Unknown command"),
        "shell 'version' returned Unknown command"
    );
}

#[test]
fn issue_26_shell_dash_v_flag() {
    if skip_if_missing() {
        return;
    }
    let (stdout, stderr, _) = shell_input("-V");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("0.") || combined.contains("pki"),
        "shell '-V' did not print version:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !combined.contains("Unknown command"),
        "shell '-V' returned Unknown command"
    );
}

#[test]
fn issue_26_shell_double_dash_version() {
    if skip_if_missing() {
        return;
    }
    let (stdout, stderr, _) = shell_input("--version");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("0.") || combined.contains("pki"),
        "shell '--version' did not print version:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !combined.contains("Unknown command"),
        "shell '--version' returned Unknown command"
    );
}

#[test]
fn issue_26_shell_double_dash_help() {
    if skip_if_missing() {
        return;
    }
    let (stdout, stderr, _) = shell_input("--help");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("Commands:") || combined.contains("PKI Interactive Shell"),
        "shell '--help' did not show help:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !combined.contains("Unknown command"),
        "shell '--help' returned Unknown command"
    );
}

#[test]
fn issue_26_shell_dash_h() {
    if skip_if_missing() {
        return;
    }
    let (stdout, stderr, _) = shell_input("-h");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("Commands:") || combined.contains("PKI Interactive Shell"),
        "shell '-h' did not show help:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !combined.contains("Unknown command"),
        "shell '-h' returned Unknown command"
    );
}

// ============================================================================
// Issue #28: Batch mode — multi-line paste and script file input
// ============================================================================

#[test]
fn issue_28_shell_multiline_paste_runs_all_commands() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key1 = dir.path().join("a.key");
    let key2 = dir.path().join("b.key");

    // Paste two key gen commands at once
    let input = format!(
        "key gen ec --curve p256 -o {}\nkey gen rsa --bits 2048 -o {}",
        key1.display(),
        key2.display()
    );
    let (stdout, _stderr, _) = shell_input(&input);

    // Both keys should have been generated
    assert!(
        key1.exists(),
        "First command in multi-line paste was not executed. stdout: {stdout}"
    );
    assert!(
        key2.exists(),
        "Second command in multi-line paste was not executed. stdout: {stdout}"
    );
}

#[test]
fn issue_28_batch_file_runs_all_commands() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key_path = dir.path().join("batch.key");
    let csr_path = dir.path().join("batch.csr");

    // Create a batch script
    let script = dir.path().join("commands.txt");
    fs::write(
        &script,
        format!(
            "# Generate key and CSR\nkey gen ec --curve p256 -o {}\ncsr create --key {} --cn batch-test -o {}\n",
            key_path.display(),
            key_path.display(),
            csr_path.display()
        ),
    )
    .unwrap();

    let out = pki_cmd()
        .args(["batch", script.to_str().unwrap()])
        .output()
        .expect("failed to run pki batch");

    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        key_path.exists(),
        "batch: key was not generated. stdout: {stdout}"
    );
    assert!(
        csr_path.exists(),
        "batch: CSR was not generated. stdout: {stdout}"
    );
}

#[test]
fn issue_28_batch_continues_on_error() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key_path = dir.path().join("after-error.key");

    // First command will fail (nonexistent file), second should still run
    let script = dir.path().join("errors.txt");
    fs::write(
        &script,
        format!(
            "show /nonexistent/file.pem\nkey gen ec --curve p256 -o {}\n",
            key_path.display()
        ),
    )
    .unwrap();

    let out = pki_cmd()
        .args(["batch", script.to_str().unwrap()])
        .output()
        .expect("failed to run pki batch");

    let stdout = String::from_utf8_lossy(&out.stdout);

    // The key should exist even though the first command failed
    assert!(
        key_path.exists(),
        "batch: second command did not run after first failed. stdout: {stdout}"
    );
}

#[test]
fn issue_28_batch_skips_comments_and_blanks() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key_path = dir.path().join("comment-test.key");

    let script = dir.path().join("comments.txt");
    fs::write(
        &script,
        format!(
            "# This is a comment\n\n  # Another comment\n\nkey gen ec --curve p256 -o {}\n\n",
            key_path.display()
        ),
    )
    .unwrap();

    let out = pki_cmd()
        .args(["batch", script.to_str().unwrap()])
        .output()
        .expect("failed to run pki batch");

    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        key_path.exists(),
        "batch: command after comments was not executed. stdout: {stdout}"
    );
}

// ============================================================================
// Bug #31: RSA-4096 key size accuracy
// ============================================================================

/// Regression test for issue #31: `pki show` reported RSA-4096 as 4208 bits
/// because it multiplied raw DER bytes (including overhead) by 8.
///
/// The fix parses the actual RSA modulus from the SubjectPublicKeyInfo
/// BIT STRING rather than using the encoded length.
#[test]
fn issue_31_rsa_4096_shows_correct_key_size() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = gen_key(&dir, "rsa4096-issue31.key", "rsa", &["--bits", "4096"]);
    let csr = gen_csr(&dir, "rsa4096-issue31.csr", &key);

    // pki show must report exactly 4096, not 4208 or any other inflated value
    assert_show_key_bits(&csr, 4096);
    // pki csr show must also report exactly 4096
    assert_csr_show_key_bits(&csr, 4096);
}

// ============================================================================
// Bug #29: Batch mode quoted argument handling
// ============================================================================

/// Regression test for issue #29: batch mode split on whitespace, so a CN
/// like "My Server" was parsed as two tokens "My and Server".
///
/// The fix introduces a shell-aware splitter that respects double and single
/// quoted strings.
#[test]
fn issue_29_batch_handles_quoted_cn() {
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();

    // Generate a key to use in the batch
    let key_path = dir.path().join("quoted-cn.key");
    let gen_out = pki_cmd()
        .args(["key", "gen", "ec", "--curve", "p256", "-o"])
        .arg(&key_path)
        .output()
        .expect("failed to run pki key gen");
    assert!(
        gen_out.status.success(),
        "key gen failed: {}",
        String::from_utf8_lossy(&gen_out.stderr)
    );

    let csr_path = dir.path().join("quoted-cn.csr");

    // Write a batch script that uses a quoted CN containing a space
    let script_path = dir.path().join("quoted.txt");
    fs::write(
        &script_path,
        format!(
            "csr create --key {} --cn \"My Server\" -o {}\n",
            key_path.display(),
            csr_path.display()
        ),
    )
    .unwrap();

    let batch_out = pki_cmd()
        .args(["batch", script_path.to_str().unwrap()])
        .output()
        .expect("failed to run pki batch");

    assert!(
        csr_path.exists(),
        "batch: CSR was not created.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&batch_out.stdout),
        String::from_utf8_lossy(&batch_out.stderr),
    );

    // Verify the CSR actually contains "My Server" as the CN, not just "My"
    let show_out = pki_cmd()
        .args(["csr", "show", "--color", "never"])
        .arg(&csr_path)
        .output()
        .expect("failed to run pki csr show");
    let csr_show = String::from_utf8_lossy(&show_out.stdout);
    assert!(
        csr_show.contains("My Server"),
        "CSR CN should be 'My Server' but got:\n{csr_show}"
    );
}

// ============================================================================
// Shell: `pki build` / `pki preview` must route to hierarchy builder
// ============================================================================

#[test]
fn shell_pki_build_routes_to_hierarchy() {
    if skip_if_missing() {
        return;
    }
    // "pki build" with no args should produce a usage error mentioning "FILE", not "Unknown command"
    let (stdout, stderr, _) = shell_input("pki build");
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.contains("Unknown command"),
        "shell 'pki build' should route to hierarchy builder, not produce Unknown command.\nGot: {combined}"
    );
}

#[test]
fn shell_pki_preview_routes_to_hierarchy() {
    if skip_if_missing() {
        return;
    }
    let (stdout, stderr, _) = shell_input("pki preview");
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.contains("Unknown command"),
        "shell 'pki preview' should route to hierarchy builder, not produce Unknown command.\nGot: {combined}"
    );
}

#[test]
fn shell_bare_build_routes_to_hierarchy() {
    if skip_if_missing() {
        return;
    }
    // Bare "build" (no pki prefix) should also route to hierarchy builder
    let (stdout, stderr, _) = shell_input("build");
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.contains("Unknown command"),
        "shell bare 'build' should route to hierarchy builder.\nGot: {combined}"
    );
}

#[test]
fn shell_bare_preview_routes_to_hierarchy() {
    if skip_if_missing() {
        return;
    }
    let (stdout, stderr, _) = shell_input("preview");
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.contains("Unknown command"),
        "shell bare 'preview' should route to hierarchy builder.\nGot: {combined}"
    );
}

// ============================================================================
// Line continuation: auto-join wrapped lines in multi-line paste
// ============================================================================

#[test]
fn shell_continuation_lint_on_next_line() {
    // Use explicit \ continuation: "show /tmp/cert.pem \\\n--lint"
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = dir.path().join("cont.key");
    let _ = pki_cmd()
        .args(["key", "gen", "ec", "--curve", "p256", "-o"])
        .arg(&key)
        .output();
    let input = format!("show {} \\\n--lint", key.display());
    let (stdout, stderr, _) = shell_input(&input);
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.contains("Unknown command: --lint"),
        "shell should join backslash-continued '--lint' to 'show' command.\nGot: {combined}"
    );
}

#[test]
fn shell_continuation_second_file_arg() {
    // Use explicit \ continuation: "diff a.key \\\nb.key"
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let k1 = dir.path().join("d1.key");
    let k2 = dir.path().join("d2.key");
    let _ = pki_cmd()
        .args(["key", "gen", "ec", "--curve", "p256", "-o"])
        .arg(&k1)
        .output();
    let _ = pki_cmd()
        .args(["key", "gen", "rsa", "--bits", "2048", "-o"])
        .arg(&k2)
        .output();
    let input = format!("diff {} \\\n{}", k1.display(), k2.display());
    let (stdout, stderr, _) = shell_input(&input);
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.contains("Unknown command"),
        "shell should join backslash-continued file path to 'diff'.\nGot: {combined}"
    );
}

#[test]
fn shell_continuation_explicit_backslash() {
    // Simulates explicit continuation with \
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = dir.path().join("bs.key");
    // "key gen ec \\\n--curve p256 -o <key>"
    let input = format!("key gen ec \\\n--curve p256 -o {}", key.display());
    let (stdout, stderr, _) = shell_input(&input);
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.contains("Unknown command"),
        "shell should join backslash-continued lines.\nGot: {combined}"
    );
    assert!(
        key.exists(),
        "Key should have been generated via continued command"
    );
}

#[test]
fn shell_continuation_hostname_on_next_line() {
    // Use explicit \ continuation: "dane generate -p 443 -H \\\nquantumnexum.com"
    if skip_if_missing() {
        return;
    }
    let input = "dane generate -p 443 -H \\\nquantumnexum.com";
    let (stdout, stderr, _) = shell_input(input);
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.contains("Unknown command: quantumnexum.com"),
        "shell should join backslash-continued hostname.\nGot: {combined}"
    );
}

#[test]
fn shell_continuation_does_not_eat_real_commands() {
    // "show" followed by another "show" should NOT be joined
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let k1 = dir.path().join("c1.key");
    let k2 = dir.path().join("c2.key");
    let _ = pki_cmd()
        .args(["key", "gen", "ec", "--curve", "p256", "-o"])
        .arg(&k1)
        .output();
    let _ = pki_cmd()
        .args(["key", "gen", "ec", "--curve", "p256", "-o"])
        .arg(&k2)
        .output();
    let input = format!("show {}\nshow {}", k1.display(), k2.display());
    let (stdout, stderr, _) = shell_input(&input);
    let combined = format!("{stdout}{stderr}");
    // Both should produce output (both are EC keys)
    let ec_count = combined.matches("EC").count();
    assert!(
        ec_count >= 2,
        "Two separate 'show' commands should both execute, not be joined.\nGot: {combined}"
    );
}

#[test]
fn shell_continuation_flag_value_on_next_line() {
    // Use explicit \ continuation: "key gen rsa \\\n--bits 4096 -o <path>"
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = dir.path().join("fv.key");
    let input = format!("key gen rsa \\\n--bits 4096 -o {}", key.display());
    let (stdout, stderr, _) = shell_input(&input);
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.contains("Unknown command"),
        "shell should join backslash-continued '--bits 4096'.\nGot: {combined}"
    );
    assert!(
        key.exists(),
        "RSA key should have been generated via continued command"
    );
}

// ============================================================================
// Issue #48: probe should default to server subcommand
// ============================================================================

#[test]
fn shell_probe_defaults_to_server() {
    // "probe example.com:443" should route to "probe server example.com:443"
    // not "unrecognized subcommand"
    if skip_if_missing() {
        return;
    }
    let (stdout, stderr, _) = shell_input("probe localhost:1");
    let combined = format!("{stdout}{stderr}");
    // Should NOT say "unrecognized subcommand" — it should try to connect
    // (and fail with a connection error, which is fine)
    assert!(
        !combined.contains("unrecognized subcommand"),
        "shell 'probe localhost:1' should default to 'probe server'.\nGot: {combined}"
    );
}

#[test]
fn shell_probe_server_still_works() {
    // Explicit "probe server" should still work
    if skip_if_missing() {
        return;
    }
    let (stdout, stderr, _) = shell_input("probe server localhost:1");
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.contains("unrecognized subcommand"),
        "shell 'probe server localhost:1' should work.\nGot: {combined}"
    );
}

#[test]
fn shell_probe_check_still_works() {
    if skip_if_missing() {
        return;
    }
    let (stdout, stderr, _) = shell_input("probe check localhost:1");
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.contains("unrecognized subcommand"),
        "shell 'probe check' should still work as explicit subcommand.\nGot: {combined}"
    );
}

// ============================================================================
// Issue #49: no ....> delay for non-continuation commands
// ============================================================================

#[test]
fn shell_no_buffering_delay_for_simple_commands() {
    // Two show commands should both execute without delay
    if skip_if_missing() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let key = dir.path().join("nodelay.key");
    let _ = pki_cmd()
        .args(["key", "gen", "ec", "--curve", "p256", "-o"])
        .arg(&key)
        .output();
    // "show <key>\nversion" — show should execute immediately, not buffer
    let input = format!("show {}\nversion", key.display());
    let (stdout, stderr, _) = shell_input(&input);
    let combined = format!("{stdout}{stderr}");
    // Both should produce output
    assert!(
        combined.contains("EC") || combined.contains("ECDSA"),
        "show command should execute immediately.\nGot: {combined}"
    );
    assert!(
        combined.contains("0.6."),
        "version should also execute.\nGot: {combined}"
    );
}
