//! Algorithm-detection regression tests for `pki key show`.
//!
//! Guards against issue #97, where ML-DSA / SLH-DSA keys were misreported as
//! "EC P-256" because the detector fell through to size-based heuristics when
//! the PKCS#8 OID was an unrecognised PQC identifier.

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn pki_binary() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push("debug");
    path.push("pki");
    path
}

fn binary_exists() -> bool {
    pki_binary().exists()
}

fn gen_and_show(alg: &str) -> Option<(String, String)> {
    if !binary_exists() {
        return None;
    }
    let tmp = TempDir::new().ok()?;
    let key_path = tmp.path().join(format!("{alg}.key"));
    let keygen = Command::new(pki_binary())
        .args(["key", "gen", alg, "-o"])
        .arg(&key_path)
        .output()
        .ok()?;
    if !keygen.status.success() {
        let stderr = String::from_utf8_lossy(&keygen.stderr);
        if stderr.contains("Unknown algorithm")
            || stderr.contains("not supported")
            || stderr.contains("not yet supported")
        {
            return None; // pqc feature off or algo not yet wired → skip
        }
        panic!("keygen {alg} failed: {stderr}");
    }
    let show = Command::new(pki_binary())
        .args(["key", "show", "-f", "json"])
        .arg(&key_path)
        .output()
        .ok()?;
    assert!(
        show.status.success(),
        "key show failed for {alg}: {}",
        String::from_utf8_lossy(&show.stderr)
    );
    Some((
        String::from_utf8_lossy(&show.stdout).into_owned(),
        String::from_utf8_lossy(&show.stderr).into_owned(),
    ))
}

fn assert_algo(alg: &str, expected_substrings: &[&str]) {
    let Some((stdout, _)) = gen_and_show(alg) else {
        return;
    };
    for needle in expected_substrings {
        assert!(
            stdout.contains(needle),
            "`pki key show` output for {alg} missing `{needle}`:\n{stdout}"
        );
    }
    // Catch the #97 regression class: PQC keys must NOT be reported as a
    // classical algorithm. The original bug collapsed onto `EcP256`, but the
    // detector's size-heuristic fallback can just as easily misfile a PQC key
    // as RSA or Ed25519 — guard all three so a future parser bug is caught.
    if !alg.starts_with("ec-") && !alg.starts_with("rsa") && !alg.starts_with("ed") {
        for forbidden in ["\"EcP256\"", "\"Rsa\"", "\"Ed25519\""] {
            assert!(
                !stdout.contains(forbidden),
                "PQC key {alg} misidentified as {forbidden} (regression of #97 class):\n{stdout}"
            );
        }
    }
}

#[test]
fn key_show_detects_ec_p256() {
    assert_algo("ec-p256", &["\"EcP256\"", "\"P-256\""]);
}

#[test]
fn key_show_detects_rsa() {
    // Default RSA size is 4096 (2048 is refused under the secure-defaults policy).
    assert_algo("rsa", &["\"Rsa\"", "4096"]);
}

// ML-DSA assertions include the parameter-set integer so a regression that
// collapses 44/65/87 onto a single value is caught (Tester P1 finding).
#[test]
fn key_show_detects_mldsa44() {
    assert_algo("ml-dsa-44", &["\"MlDsa\": 44"]);
}

#[test]
fn key_show_detects_mldsa65() {
    assert_algo("ml-dsa-65", &["\"MlDsa\": 65"]);
}

#[test]
fn key_show_detects_mldsa87() {
    assert_algo("ml-dsa-87", &["\"MlDsa\": 87"]);
}

// SLH-DSA assertions pin the hash family + parameter set so a swap to a
// neighbouring variant (e.g., 128s misreported as 192s) is caught.
#[test]
fn key_show_detects_slhdsa_128s() {
    assert_algo("slh-dsa-128s", &["\"SlhDsa\": \"SHA2-128s\""]);
}

#[test]
fn key_show_detects_slhdsa_192s() {
    assert_algo("slh-dsa-192s", &["\"SlhDsa\": \"SHA2-192s\""]);
}

#[test]
fn key_show_detects_slhdsa_256s() {
    assert_algo("slh-dsa-256s", &["\"SlhDsa\": \"SHA2-256s\""]);
}

// Future-guard: when `pki key gen ed25519` is re-enabled, detection must
// report Ed25519 and not fall through to the size/OID heuristics. The
// skip-on-"not supported" path keeps this inert today.
#[test]
fn key_show_detects_ed25519() {
    assert_algo("ed25519", &["\"Ed25519\""]);
}
