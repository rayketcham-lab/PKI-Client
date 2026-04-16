//! CLI Integration Tests
//!
//! End-to-end tests for the pki CLI tool.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// Get path to the pki binary
fn pki_binary() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push("debug");
    path.push("pki");
    path
}

/// Check if pki binary exists (skip tests if not built)
fn binary_exists() -> bool {
    pki_binary().exists()
}

// ============================================================================
// Key Generation Tests
// ============================================================================

#[test]
fn test_key_gen_ec_p256() {
    if !binary_exists() {
        eprintln!("Skipping test: pki binary not built");
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("ec-p256.key");

    let output = Command::new(pki_binary())
        .args(["key", "gen", "ec", "--curve", "p256", "-o"])
        .arg(&key_path)
        .output()
        .expect("Failed to execute pki");

    assert!(
        output.status.success(),
        "Key generation failed: {:?}",
        output
    );
    assert!(key_path.exists(), "Key file not created");

    let content = fs::read_to_string(&key_path).unwrap();
    assert!(content.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(content.contains("-----END PRIVATE KEY-----"));
}

#[test]
fn test_key_gen_ec_p384() {
    if !binary_exists() {
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("ec-p384.key");

    let output = Command::new(pki_binary())
        .args(["key", "gen", "ec", "--curve", "p384", "-o"])
        .arg(&key_path)
        .output()
        .expect("Failed to execute pki");

    assert!(output.status.success());
    assert!(key_path.exists());
}

#[test]
fn test_key_gen_rsa() {
    if !binary_exists() {
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("rsa.key");

    let output = Command::new(pki_binary())
        .args(["key", "gen", "rsa", "--bits", "4096", "-o"])
        .arg(&key_path)
        .output()
        .expect("Failed to execute pki");

    assert!(output.status.success());
    assert!(key_path.exists());
}

#[test]
fn test_key_gen_ed25519() {
    if !binary_exists() {
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("ed25519.key");

    let output = Command::new(pki_binary())
        .args(["key", "gen", "ed25519", "-o"])
        .arg(&key_path)
        .output()
        .expect("Failed to execute pki");

    // Ed25519 may not be implemented - skip if not supported
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("not supported")
            || stderr.contains("not implemented")
            || stderr.contains("not yet supported")
        {
            eprintln!("Skipping: Ed25519 not yet supported");
            return;
        }
        panic!("Ed25519 failed unexpectedly: {}", stderr);
    }
    assert!(key_path.exists());
}

// ============================================================================
// CSR Generation Tests
// ============================================================================

#[test]
fn test_csr_create() {
    if !binary_exists() {
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("key.pem");
    let csr_path = temp_dir.path().join("csr.pem");

    // First generate a key
    let _ = Command::new(pki_binary())
        .args(["key", "gen", "ec", "--curve", "p256", "-o"])
        .arg(&key_path)
        .output()
        .expect("Failed to generate key");

    // Then create CSR
    let output = Command::new(pki_binary())
        .args([
            "csr",
            "create",
            "--key",
            key_path.to_str().unwrap(),
            "--cn",
            "test.example.com",
            "-o",
        ])
        .arg(&csr_path)
        .output()
        .expect("Failed to execute pki");

    // CSR creation may not be implemented yet - skip if so
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("not yet implemented") || stderr.contains("not implemented") {
            eprintln!("Skipping: CSR creation not yet implemented");
            return;
        }
    }

    assert!(output.status.success(), "CSR creation failed: {:?}", output);
    assert!(csr_path.exists(), "CSR file not created");

    let content = fs::read_to_string(&csr_path).unwrap();
    assert!(content.contains("-----BEGIN CERTIFICATE REQUEST-----"));
}

#[test]
fn test_csr_create_with_san() {
    if !binary_exists() {
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("key.pem");
    let csr_path = temp_dir.path().join("csr.pem");

    // Generate key
    let _ = Command::new(pki_binary())
        .args(["key", "gen", "ec", "--curve", "p256", "-o"])
        .arg(&key_path)
        .output()
        .unwrap();

    // Create CSR with SANs
    let output = Command::new(pki_binary())
        .args([
            "csr",
            "create",
            "--key",
            key_path.to_str().unwrap(),
            "--cn",
            "test.example.com",
            "--san",
            "dns:www.example.com",
            "--san",
            "dns:api.example.com",
            "-o",
        ])
        .arg(&csr_path)
        .output()
        .expect("Failed to execute pki");

    // Skip if CSR creation not implemented
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("not yet implemented") || stderr.contains("not implemented") {
            eprintln!("Skipping: CSR creation not yet implemented");
            return;
        }
    }

    assert!(output.status.success());
    assert!(csr_path.exists());

    // Regression for #19/#20: SANs must actually land in the CSR, not just
    // silently collected and dropped. `pki csr show` parses the CSR and prints
    // each SAN value; both --san flags must survive round-trip.
    let show = Command::new(pki_binary())
        .args(["csr", "show"])
        .arg(&csr_path)
        .output()
        .expect("Failed to execute pki csr show");
    assert!(show.status.success(), "pki csr show failed: {show:?}");
    let stdout = String::from_utf8_lossy(&show.stdout);
    assert!(
        stdout.contains("www.example.com"),
        "SAN dns:www.example.com missing from CSR (SAN drop regression): {stdout}"
    );
    assert!(
        stdout.contains("api.example.com"),
        "SAN dns:api.example.com missing from CSR (SAN drop regression): {stdout}"
    );
}

#[test]
fn test_csr_create_email_san_roundtrip() {
    // Regression for S/MIME SAN bug: --san email:<addr> must emit an
    // rfc822Name entry that pki csr show can read back. CN is a non-hostname
    // (a person's name) so the auto-DNS-SAN heuristic must NOT inject
    // "DNS:Ray Ketcham" — this is the S/MIME case that triggered the fix.
    if !binary_exists() {
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("smime.key");
    let csr_path = temp_dir.path().join("smime.csr");

    let _ = Command::new(pki_binary())
        .args(["key", "gen", "ec", "--curve", "p256", "-o"])
        .arg(&key_path)
        .output()
        .unwrap();

    let output = Command::new(pki_binary())
        .args([
            "csr",
            "create",
            "--key",
            key_path.to_str().unwrap(),
            "--cn",
            "Ray Ketcham",
            "--san",
            "email:rayketcham@example.com",
            "-o",
        ])
        .arg(&csr_path)
        .output()
        .expect("Failed to execute pki");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("not yet implemented") {
            return;
        }
    }
    assert!(output.status.success(), "CSR creation failed: {output:?}");

    let show = Command::new(pki_binary())
        .args(["csr", "show"])
        .arg(&csr_path)
        .output()
        .expect("Failed to execute pki csr show");
    assert!(show.status.success());
    let stdout = String::from_utf8_lossy(&show.stdout);

    assert!(
        stdout.contains("rayketcham@example.com"),
        "email SAN missing from S/MIME CSR: {stdout}"
    );
    assert!(
        !stdout.contains("DNS:Ray Ketcham"),
        "non-hostname CN must not be auto-injected as DNS SAN: {stdout}"
    );
}

// ============================================================================
// Format Conversion Tests
// ============================================================================

#[test]
fn test_convert_pem_to_der() {
    if !binary_exists() {
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let pem_path = temp_dir.path().join("key.pem");
    let der_path = temp_dir.path().join("key.der");

    // Generate PEM key
    let _ = Command::new(pki_binary())
        .args(["key", "gen", "ec", "--curve", "p256", "-o"])
        .arg(&pem_path)
        .output()
        .unwrap();

    // Convert to DER
    let output = Command::new(pki_binary())
        .args(["convert", pem_path.to_str().unwrap(), "-t", "der", "-o"])
        .arg(&der_path)
        .output()
        .expect("Failed to convert");

    assert!(output.status.success());
    assert!(der_path.exists());

    // DER files should not contain PEM markers
    let content = fs::read(&der_path).unwrap();
    assert!(!content.starts_with(b"-----BEGIN"));
}

#[test]
fn test_convert_der_to_pem() {
    if !binary_exists() {
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let pem_path = temp_dir.path().join("key.pem");
    let der_path = temp_dir.path().join("key.der");
    let pem2_path = temp_dir.path().join("key2.pem");

    // Generate PEM key
    let gen_output = Command::new(pki_binary())
        .args(["key", "gen", "ec", "--curve", "p256", "-o"])
        .arg(&pem_path)
        .output()
        .unwrap();

    if !gen_output.status.success() {
        eprintln!("Skipping: key generation failed");
        return;
    }

    // Convert to DER
    let der_output = Command::new(pki_binary())
        .args(["convert", pem_path.to_str().unwrap(), "-t", "der", "-o"])
        .arg(&der_path)
        .output()
        .unwrap();

    if !der_output.status.success() {
        let stderr = String::from_utf8_lossy(&der_output.stderr);
        eprintln!("Skipping: DER conversion not supported: {}", stderr);
        return;
    }

    // Convert back to PEM
    let output = Command::new(pki_binary())
        .args(["convert", der_path.to_str().unwrap(), "-t", "pem", "-o"])
        .arg(&pem2_path)
        .output()
        .expect("Failed to convert");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("Skipping: PEM conversion not supported: {}", stderr);
        return;
    }

    assert!(pem2_path.exists());
    let content = fs::read_to_string(&pem2_path).unwrap();
    assert!(content.contains("-----BEGIN"));
}

// ============================================================================
// Show Command Tests
// ============================================================================

#[test]
fn test_show_key() {
    if !binary_exists() {
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("key.pem");

    // Generate key
    let _ = Command::new(pki_binary())
        .args(["key", "gen", "ec", "--curve", "p256", "-o"])
        .arg(&key_path)
        .output()
        .unwrap();

    // Show key info
    let output = Command::new(pki_binary())
        .args(["show"])
        .arg(&key_path)
        .output()
        .expect("Failed to execute pki");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Private Key") || stdout.contains("EC"));
}

#[test]
fn test_show_csr() {
    if !binary_exists() {
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("key.pem");
    let csr_path = temp_dir.path().join("csr.pem");

    // Generate key
    let _ = Command::new(pki_binary())
        .args(["key", "gen", "ec", "--curve", "p256", "-o"])
        .arg(&key_path)
        .output()
        .unwrap();

    // Create CSR
    let csr_output = Command::new(pki_binary())
        .args([
            "csr",
            "create",
            "--key",
            key_path.to_str().unwrap(),
            "--cn",
            "test.example.com",
            "-o",
        ])
        .arg(&csr_path)
        .output()
        .unwrap();

    // Skip if CSR creation not implemented
    if !csr_output.status.success() {
        let stderr = String::from_utf8_lossy(&csr_output.stderr);
        if stderr.contains("not yet implemented") || stderr.contains("not implemented") {
            eprintln!("Skipping: CSR creation not yet implemented");
            return;
        }
    }

    // Show CSR info
    let output = Command::new(pki_binary())
        .args(["show"])
        .arg(&csr_path)
        .output()
        .expect("Failed to execute pki");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("test.example.com") || stdout.contains("CSR"));
}

// ============================================================================
// JSON Output Tests
// ============================================================================

#[test]
fn test_json_output() {
    if !binary_exists() {
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("key.pem");

    // Generate key
    let gen_output = Command::new(pki_binary())
        .args(["key", "gen", "ec", "--curve", "p256", "-o"])
        .arg(&key_path)
        .output()
        .unwrap();

    if !gen_output.status.success() {
        eprintln!("Skipping: key generation failed");
        return;
    }

    // Show with JSON output
    let output = Command::new(pki_binary())
        .args(["key", "show", "-f", "json"])
        .arg(&key_path)
        .output()
        .expect("Failed to execute pki");

    // JSON output may not be fully implemented for all types
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Should contain JSON-like content
        assert!(
            stdout.contains("{") || stdout.contains("algorithm") || stdout.contains("key"),
            "Expected JSON output, got: {}",
            stdout
        );
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_invalid_file() {
    if !binary_exists() {
        return;
    }

    let output = Command::new(pki_binary())
        .args(["show", "/nonexistent/file.pem"])
        .output()
        .expect("Failed to execute pki");

    assert!(!output.status.success());
}

#[test]
fn test_invalid_key_algorithm() {
    if !binary_exists() {
        return;
    }

    let output = Command::new(pki_binary())
        .args(["key", "gen", "invalid-algo"])
        .output()
        .expect("Failed to execute pki");

    assert!(!output.status.success());
}

// ============================================================================
// Help Command Tests
// ============================================================================

#[test]
fn test_help_command() {
    if !binary_exists() {
        return;
    }

    let output = Command::new(pki_binary())
        .args(["--help"])
        .output()
        .expect("Failed to execute pki");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PKI") || stdout.contains("pki"));
    assert!(stdout.contains("cert"));
    assert!(stdout.contains("key"));
}

#[test]
fn test_acme_help() {
    if !binary_exists() {
        return;
    }

    let output = Command::new(pki_binary())
        .args(["acme", "--help"])
        .output()
        .expect("Failed to execute pki");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ACME") || stdout.contains("acme"));
    assert!(stdout.contains("register"));
}

#[test]
fn test_est_help() {
    if !binary_exists() {
        return;
    }

    let output = Command::new(pki_binary())
        .args(["est", "--help"])
        .output()
        .expect("Failed to execute pki");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("EST") || stdout.contains("est"));
    assert!(stdout.contains("cacerts"));
}

#[test]
fn test_scep_help() {
    if !binary_exists() {
        return;
    }

    let output = Command::new(pki_binary())
        .args(["scep", "--help"])
        .output()
        .expect("Failed to execute pki");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("SCEP") || stdout.contains("scep"));
    assert!(stdout.contains("cacaps"));
}

// ============================================================================
// Bug #32: RSA key gen size validation
// ============================================================================

/// Regression test for issue #32: `pki key gen rsa --bits 512` should fail
/// with a clear error rather than attempting to generate a dangerously small key.
#[test]
fn issue_32_rejects_rsa_512() {
    if !binary_exists() {
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("tiny.key");

    let output = Command::new(pki_binary())
        .args(["key", "gen", "rsa", "--bits", "512", "-o"])
        .arg(&key_path)
        .output()
        .expect("failed to run pki key gen");

    assert!(
        !output.status.success(),
        "pki key gen rsa --bits 512 should have failed but exited 0"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_lowercase().contains("too small")
            || stderr.to_lowercase().contains("minimum")
            || stderr.to_lowercase().contains("2048"),
        "Expected a 'too small' / 'minimum' / '2048' error message, got: {stderr}"
    );
}

/// Regression test for issue #32: `pki key gen rsa --bits 99999` should fail
/// with a clear error rather than attempting an absurdly large key generation.
#[test]
fn issue_32_rejects_rsa_99999() {
    if !binary_exists() {
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("huge.key");

    let output = Command::new(pki_binary())
        .args(["key", "gen", "rsa", "--bits", "99999", "-o"])
        .arg(&key_path)
        .output()
        .expect("failed to run pki key gen");

    assert!(
        !output.status.success(),
        "pki key gen rsa --bits 99999 should have failed but exited 0"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_lowercase().contains("too large")
            || stderr.to_lowercase().contains("maximum")
            || stderr.to_lowercase().contains("16384"),
        "Expected a 'too large' / 'maximum' / '16384' error message, got: {stderr}"
    );
}

// ============================================================================
// Bug #33: CSR create requires --cn
// ============================================================================

/// Regression test for issue #33: `pki csr create` without `--cn` must exit
/// non-zero and print a helpful error rather than silently creating a malformed
/// CSR or panicking.
#[test]
fn issue_33_csr_create_requires_cn() {
    if !binary_exists() {
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("nocn.key");
    let csr_path = temp_dir.path().join("nocn.csr");

    // Generate a key to use
    let _ = Command::new(pki_binary())
        .args(["key", "gen", "ec", "--curve", "p256", "-o"])
        .arg(&key_path)
        .output()
        .expect("failed to generate key");

    // Attempt CSR creation without --cn
    let output = Command::new(pki_binary())
        .args(["csr", "create", "--key", key_path.to_str().unwrap(), "-o"])
        .arg(&csr_path)
        .output()
        .expect("failed to run pki csr create");

    assert!(
        !output.status.success(),
        "pki csr create without --cn should exit non-zero"
    );

    // The error message should mention cn or required argument
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stderr}{stdout}").to_lowercase();
    assert!(
        combined.contains("cn")
            || combined.contains("required")
            || combined.contains("common name"),
        "Expected error mentioning '--cn' or 'required', got stderr: {stderr}\nstdout: {stdout}"
    );
}

// ============================================================================
// Version Test
// ============================================================================

#[test]
fn test_version() {
    if !binary_exists() {
        return;
    }

    let output = Command::new(pki_binary())
        .args(["--version"])
        .output()
        .expect("Failed to execute pki");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.to_lowercase().contains("pki"));
    // Must report a semver-shaped version; currently 0.8.x.
    assert!(
        stdout.contains("0.8") || stdout.contains("0.9") || stdout.contains("1."),
        "Unexpected --version output: {stdout}"
    );
}

// ============================================================================
// --format openssl (`-f os`) integration tests
//
// Regression coverage for the 0.8.0 addition: `pki cert show -f os <file>`
// should produce output that tracks `openssl x509 -text -noout` layout
// (literal "Certificate:" header, "Data:", "Serial Number:", "Issuer:",
// "Validity", "Not Before:", "Not After :", "Subject:", "X509v3 extensions:").
// ============================================================================

/// Build a self-signed EC P-256 cert on disk and return its PEM path.
///
/// Uses `spork-core` directly so the test doesn't depend on the CLI being
/// able to issue certs.
fn write_selfsigned_ec_p256_cert(dir: &std::path::Path, cn: &str) -> PathBuf {
    use spork_core::algo::{AlgorithmId, KeyPair};
    use spork_core::cert::{
        encode_certificate_pem,
        extensions::{BasicConstraints, KeyUsage, KeyUsageFlags, SubjectAltName},
        CertificateBuilder, NameBuilder, Validity,
    };

    let key = KeyPair::generate(AlgorithmId::EcdsaP256).expect("keygen");
    let dn = NameBuilder::new(cn)
        .organization("PKI Client Test")
        .country("US")
        .build();

    let cert = CertificateBuilder::new(dn, key.public_key_der().unwrap(), key.algorithm_id())
        .validity(Validity::years_from_now(1))
        .basic_constraints(BasicConstraints::end_entity())
        .key_usage(KeyUsage::new(KeyUsageFlags::new(
            KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::KEY_ENCIPHERMENT,
        )))
        .subject_alt_name(SubjectAltName::new().dns(cn))
        .include_authority_key_identifier(false)
        .build_and_sign(&key)
        .expect("build cert");

    let pem = encode_certificate_pem(&cert).expect("encode PEM");
    let path = dir.join("selfsigned.pem");
    fs::write(&path, pem).expect("write cert");
    path
}

#[test]
fn cert_show_openssl_format_full_name() {
    if !binary_exists() {
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let cert_path = write_selfsigned_ec_p256_cert(temp_dir.path(), "os-full.example.com");

    let output = Command::new(pki_binary())
        .args(["cert", "show", "-f", "openssl", "--no-chain"])
        .arg(&cert_path)
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run pki cert show -f openssl");

    assert!(
        output.status.success(),
        "cert show -f openssl failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Load-bearing openssl x509 -text landmarks.
    for needle in [
        "Certificate:",
        "Data:",
        "Version:",
        "Serial Number:",
        "Signature Algorithm:",
        "Issuer:",
        "Validity",
        "Not Before:",
        "Not After :",
        "Subject:",
        "Subject Public Key Info:",
        "X509v3 extensions:",
    ] {
        assert!(
            stdout.contains(needle),
            "expected '{}' in -f openssl output, got:\n{}",
            needle,
            stdout
        );
    }
    // And the CN should be somewhere in the Subject line.
    assert!(
        stdout.contains("os-full.example.com"),
        "expected CN in output, got:\n{}",
        stdout
    );
}

#[test]
fn cert_show_openssl_format_short_alias() {
    if !binary_exists() {
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let cert_path = write_selfsigned_ec_p256_cert(temp_dir.path(), "os-short.example.com");

    let output = Command::new(pki_binary())
        .args(["cert", "show", "-f", "os", "--no-chain"])
        .arg(&cert_path)
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run pki cert show -f os");

    assert!(
        output.status.success(),
        "cert show -f os failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("Certificate:\n"),
        "'-f os' must produce openssl-shaped output starting with 'Certificate:\\n', got:\n{}",
        stdout
    );
}

#[test]
fn cert_show_openssl_format_rejects_unknown_format() {
    if !binary_exists() {
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let cert_path = write_selfsigned_ec_p256_cert(temp_dir.path(), "os-bad.example.com");

    let output = Command::new(pki_binary())
        .args(["cert", "show", "-f", "definitely-not-a-format"])
        .arg(&cert_path)
        .output()
        .expect("failed to run pki cert show");

    assert!(
        !output.status.success(),
        "unknown format should exit non-zero"
    );
}

// ============================================================================
// Issue #12: Smoke tests for chain / crl / revoke subcommands
//
// Scope-limited: proves clap can parse --help and each subcommand dispatches.
// Full behavioral coverage (fixture-based) is tracked separately.
// ============================================================================

fn assert_help_ok(args: &[&str], expect_substr: &str) {
    if !binary_exists() {
        return;
    }
    let output = Command::new(pki_binary())
        .args(args)
        .output()
        .expect("failed to execute pki");
    assert!(
        output.status.success(),
        "`pki {}` --help should exit 0, got: {:?}",
        args.join(" "),
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout
            .to_lowercase()
            .contains(&expect_substr.to_lowercase()),
        "`pki {}` help missing `{}` — got:\n{}",
        args.join(" "),
        expect_substr,
        stdout
    );
}

#[test]
fn issue_12_chain_help_dispatches() {
    assert_help_ok(&["chain", "--help"], "build");
    assert_help_ok(&["chain", "build", "--help"], "chain");
    assert_help_ok(&["chain", "show", "--help"], "verify");
    assert_help_ok(&["chain", "verify", "--help"], "ca");
}

#[test]
fn issue_12_crl_help_dispatches() {
    assert_help_ok(&["crl", "--help"], "show");
    assert_help_ok(&["crl", "show", "--help"], "file");
    assert_help_ok(&["crl", "check", "--help"], "serial");
}

#[test]
fn issue_12_revoke_help_dispatches() {
    assert_help_ok(&["revoke", "--help"], "check");
    assert_help_ok(&["revoke", "check", "--help"], "issuer");
    assert_help_ok(&["revoke", "crl-show", "--help"], "file");
}

/// Missing-file paths must error cleanly (non-zero exit, no panic), not crash.
#[test]
fn issue_12_chain_show_missing_file_errors_cleanly() {
    if !binary_exists() {
        return;
    }
    let output = Command::new(pki_binary())
        .args(["chain", "show", "/nonexistent/definitely/not/here.pem"])
        .output()
        .expect("failed to execute pki");
    assert!(
        !output.status.success(),
        "missing chain file should exit non-zero"
    );
}

#[test]
fn issue_12_crl_show_missing_file_errors_cleanly() {
    if !binary_exists() {
        return;
    }
    let output = Command::new(pki_binary())
        .args(["crl", "show", "/nonexistent/definitely/not/here.crl"])
        .output()
        .expect("failed to execute pki");
    assert!(
        !output.status.success(),
        "missing CRL file should exit non-zero"
    );
}

#[test]
fn issue_12_revoke_crl_show_missing_file_errors_cleanly() {
    if !binary_exists() {
        return;
    }
    let output = Command::new(pki_binary())
        .args(["revoke", "crl-show", "/nonexistent/definitely/not/here.crl"])
        .output()
        .expect("failed to execute pki");
    assert!(
        !output.status.success(),
        "missing CRL file should exit non-zero"
    );
}
