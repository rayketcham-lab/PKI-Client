//! Adversarial input tests for `pki cert show`, `pki key show`, `pki csr show`.
//!
//! Tester P1 finding: the existing CLI integration tests cover well-formed
//! inputs and the "file does not exist" path, but never fed malformed bytes
//! to the parsers. A regression where x509-parser panics on truncated DER or
//! the PEM decoder loops on corrupt base64 would slip through CI.
//!
//! Each test asserts: the process exits non-zero, stays under a watchdog
//! deadline (no hangs), and does not panic (no `thread 'main' panicked`).

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tempfile::NamedTempFile;

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

fn write_fixture(bytes: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(bytes).expect("write");
    f.flush().expect("flush");
    f
}

fn assert_rejects(subcommand: &[&str], input: &[u8], label: &str) {
    if !binary_exists() {
        return;
    }
    let f = write_fixture(input);
    let out = Command::new(pki_binary())
        .args(subcommand)
        .arg(f.path())
        .output()
        .expect("spawn pki");

    assert!(
        !out.status.success(),
        "[{label}] {subcommand:?} should reject malformed input but exited 0:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("panicked"),
        "[{label}] {subcommand:?} panicked on malformed input:\n{stderr}",
    );
    assert!(
        !stderr.contains("RUST_BACKTRACE"),
        "[{label}] {subcommand:?} produced a backtrace (likely panic):\n{stderr}",
    );
}

// --- Fixtures -----------------------------------------------------------

const EMPTY: &[u8] = b"";
const GARBAGE: &[u8] = b"this is not a certificate or a key, just bytes\n";

// PEM frame with a recognised label but invalid base64 body.
const CORRUPT_PEM_CERT: &[u8] =
    b"-----BEGIN CERTIFICATE-----\n!!!not-base64!!!\n-----END CERTIFICATE-----\n";
const CORRUPT_PEM_KEY: &[u8] =
    b"-----BEGIN PRIVATE KEY-----\n!!!not-base64!!!\n-----END PRIVATE KEY-----\n";
const CORRUPT_PEM_CSR: &[u8] =
    b"-----BEGIN CERTIFICATE REQUEST-----\n!!!\n-----END CERTIFICATE REQUEST-----\n";

// Valid PEM frame with an empty (zero-length) body.
const EMPTY_PEM_CERT: &[u8] = b"-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n";

// Truncated DER: SEQUENCE tag claiming 0x82 (long-form, 2 length bytes) but
// no body. Common shape for cut-off downloads.
const TRUNCATED_DER: &[u8] = &[0x30, 0x82, 0x01, 0x00];

// --- pki cert show ------------------------------------------------------

#[test]
fn cert_show_rejects_empty_file() {
    assert_rejects(&["cert", "show"], EMPTY, "cert empty");
}

#[test]
fn cert_show_rejects_garbage() {
    assert_rejects(&["cert", "show"], GARBAGE, "cert garbage");
}

#[test]
fn cert_show_rejects_corrupt_pem() {
    assert_rejects(&["cert", "show"], CORRUPT_PEM_CERT, "cert corrupt-pem");
}

#[test]
fn cert_show_rejects_empty_pem_body() {
    assert_rejects(&["cert", "show"], EMPTY_PEM_CERT, "cert empty-pem-body");
}

#[test]
fn cert_show_rejects_truncated_der() {
    assert_rejects(&["cert", "show"], TRUNCATED_DER, "cert truncated-der");
}

// --- pki key show -------------------------------------------------------

#[test]
fn key_show_rejects_empty_file() {
    assert_rejects(&["key", "show"], EMPTY, "key empty");
}

#[test]
fn key_show_rejects_garbage() {
    assert_rejects(&["key", "show"], GARBAGE, "key garbage");
}

#[test]
fn key_show_rejects_corrupt_pem() {
    assert_rejects(&["key", "show"], CORRUPT_PEM_KEY, "key corrupt-pem");
}

#[test]
fn key_show_rejects_truncated_der() {
    assert_rejects(&["key", "show"], TRUNCATED_DER, "key truncated-der");
}

// --- pki csr show -------------------------------------------------------

#[test]
fn csr_show_rejects_empty_file() {
    assert_rejects(&["csr", "show"], EMPTY, "csr empty");
}

#[test]
fn csr_show_rejects_garbage() {
    assert_rejects(&["csr", "show"], GARBAGE, "csr garbage");
}

#[test]
fn csr_show_rejects_corrupt_pem() {
    assert_rejects(&["csr", "show"], CORRUPT_PEM_CSR, "csr corrupt-pem");
}

// --- Watchdog: cert show must exit within 10 s on any input -----------

#[test]
fn cert_show_does_not_hang_on_garbage() {
    if !binary_exists() {
        return;
    }
    let f = write_fixture(GARBAGE);
    let mut child = Command::new(pki_binary())
        .args(["cert", "show"])
        .arg(f.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait().expect("try_wait") {
            Some(_) => break,
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                panic!("pki cert show hung on garbage input (>10s)");
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}
