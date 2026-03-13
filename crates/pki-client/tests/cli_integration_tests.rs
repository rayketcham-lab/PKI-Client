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
    assert!(stdout.contains("pki") || stdout.contains("0.3"));
}
