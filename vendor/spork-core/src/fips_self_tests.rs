//! FIPS 140-3 Power-Up Self-Tests (Known Answer Tests)
//!
//! Implements the power-up self-test requirements from FIPS 140-3 §4.10.1.
//! These tests validate that the cryptographic implementations are producing
//! correct output before allowing any signing operations.
//!
//! ## Test Categories
//!
//! - **KAT-SHA**: SHA-256/384/512 hash Known Answer Tests per FIPS 180-4
//! - **KAT-HMAC**: HMAC-SHA-256 Known Answer Test per FIPS 198-1
//! - **KAT-ECDSA**: ECDSA P-256/P-384 sign+verify roundtrip test
//! - **KAT-RSA**: RSA signature verification test
//!
//! ## Usage
//!
//! Call `run_self_tests()` during CA initialization. If any test fails,
//! the module is in an error state and MUST NOT be used for cryptographic
//! operations.

use chrono::{DateTime, Utc};
#[cfg(not(feature = "fips"))]
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::error::{Error, Result};

/// Result of a single Known Answer Test.
#[derive(Debug, Clone)]
pub struct KatResult {
    /// Test identifier (e.g., "KAT-SHA256-001")
    pub test_id: &'static str,
    /// Human-readable description
    pub description: &'static str,
    /// Whether the test passed
    pub passed: bool,
    /// FIPS reference
    pub reference: &'static str,
}

/// Aggregate results of all FIPS 140-3 power-up self-tests.
#[derive(Debug, Clone)]
pub struct SelfTestResults {
    /// Individual KAT results
    pub results: Vec<KatResult>,
    /// Timestamp when tests were run
    pub timestamp: DateTime<Utc>,
    /// Whether all tests passed
    pub all_passed: bool,
}

impl SelfTestResults {
    /// Return a human-readable summary of the self-test results.
    pub fn summary(&self) -> String {
        let passed = self.results.iter().filter(|r| r.passed).count();
        let total = self.results.len();
        let status = if self.all_passed { "PASS" } else { "FAIL" };
        format!(
            "FIPS 140-3 Self-Test: {} ({}/{} KATs passed) at {}",
            status,
            passed,
            total,
            self.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        )
    }

    /// Return details of any failed tests.
    pub fn failures(&self) -> Vec<&KatResult> {
        self.results.iter().filter(|r| !r.passed).collect()
    }
}

/// Run all FIPS 140-3 power-up self-tests.
///
/// This function MUST be called during CA initialization before any
/// cryptographic operations. If `all_passed` is false in the result,
/// the CA MUST NOT proceed with signing operations.
///
/// Per FIPS 140-3 §4.10.1, these tests validate:
/// - Hash algorithms (SHA-256, SHA-384, SHA-512) via Known Answer Tests
/// - HMAC (HMAC-SHA-256) via Known Answer Test
/// - Digital signatures (ECDSA P-256) via sign+verify roundtrip
pub fn run_self_tests() -> SelfTestResults {
    let results = vec![
        // SHA-256 KAT (FIPS 180-4 Appendix B.1)
        kat_sha256(),
        kat_sha256_empty(),
        kat_sha384(),
        kat_sha512(),
        // HMAC-SHA-256 KAT (FIPS 198-1)
        kat_hmac_sha256(),
        // ECDSA sign/verify roundtrip (FIPS 186-5)
        kat_ecdsa_p256(),
        kat_ecdsa_p384(),
        // Ed25519 sign/verify roundtrip (RFC 8032)
        kat_ed25519(),
        // RSA sign/verify roundtrip (FIPS 186-5)
        kat_rsa_sign_verify(),
    ];

    let all_passed = results.iter().all(|r| r.passed);

    SelfTestResults {
        results,
        timestamp: Utc::now(),
        all_passed,
    }
}

/// Validate that self-tests have passed, returning an error if not.
///
/// Call this to gate cryptographic operations on successful self-tests.
pub fn require_self_tests_passed(results: &SelfTestResults) -> Result<()> {
    if results.all_passed {
        Ok(())
    } else {
        let failures: Vec<String> = results
            .failures()
            .iter()
            .map(|f| format!("{}: {}", f.test_id, f.description))
            .collect();
        Err(Error::PolicyViolation(format!(
            "FIPS 140-3 power-up self-tests FAILED — CA must not operate. \
             Failed tests: {}",
            failures.join("; ")
        )))
    }
}

// ---- SHA Known Answer Tests (FIPS 180-4) ----

/// SHA-256 KAT: hash of "abc" (FIPS 180-4 Appendix B.1)
pub fn kat_sha256() -> KatResult {
    let expected = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    #[cfg(not(feature = "fips"))]
    let actual = Sha256::digest(b"abc");
    #[cfg(feature = "fips")]
    let actual = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"abc");
    KatResult {
        test_id: "KAT-SHA256-001",
        description: "SHA-256 hash of 'abc' (FIPS 180-4 B.1)",
        passed: actual.as_ref() == expected,
        reference: "FIPS 180-4 Appendix B.1",
    }
}

/// SHA-256 KAT: hash of empty string
pub fn kat_sha256_empty() -> KatResult {
    let expected = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];
    #[cfg(not(feature = "fips"))]
    let actual = Sha256::digest(b"");
    #[cfg(feature = "fips")]
    let actual = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"");
    KatResult {
        test_id: "KAT-SHA256-002",
        description: "SHA-256 hash of empty string",
        passed: actual.as_ref() == expected,
        reference: "FIPS 180-4",
    }
}

/// SHA-384 KAT: hash of "abc" (FIPS 180-4 Appendix D.1)
pub fn kat_sha384() -> KatResult {
    let expected = [
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50,
        0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff,
        0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34,
        0xc8, 0x25, 0xa7,
    ];
    #[cfg(not(feature = "fips"))]
    let actual = Sha384::digest(b"abc");
    #[cfg(feature = "fips")]
    let actual = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, b"abc");
    KatResult {
        test_id: "KAT-SHA384-001",
        description: "SHA-384 hash of 'abc' (FIPS 180-4 D.1)",
        passed: actual.as_ref() == expected,
        reference: "FIPS 180-4 Appendix D.1",
    }
}

/// SHA-512 KAT: hash of "abc" (FIPS 180-4 Appendix C.1)
pub fn kat_sha512() -> KatResult {
    let expected = [
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41,
        0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55,
        0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3,
        0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f,
        0xa5, 0x4c, 0xa4, 0x9f,
    ];
    #[cfg(not(feature = "fips"))]
    let actual = Sha512::digest(b"abc");
    #[cfg(feature = "fips")]
    let actual = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA512, b"abc");
    KatResult {
        test_id: "KAT-SHA512-001",
        description: "SHA-512 hash of 'abc' (FIPS 180-4 C.1)",
        passed: actual.as_ref() == expected,
        reference: "FIPS 180-4 Appendix C.1",
    }
}

// ---- HMAC Known Answer Test (FIPS 198-1) ----

/// HMAC-SHA-256 KAT using RFC 4231 Test Case 2
pub fn kat_hmac_sha256() -> KatResult {
    // RFC 4231 Test Case 2
    // Key = "Jefe" (4 bytes)
    // Data = "what do ya want for nothing?"
    // HMAC-SHA-256 = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let expected = [
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75,
        0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec,
        0x38, 0x43,
    ];

    #[cfg(not(feature = "fips"))]
    let passed = {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;
        match HmacSha256::new_from_slice(key) {
            Ok(mut mac) => {
                mac.update(data);
                let result = mac.finalize().into_bytes();
                result.as_slice() == expected
            }
            Err(_) => false,
        }
    };

    #[cfg(feature = "fips")]
    let passed = {
        let hmac_key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key);
        let tag = aws_lc_rs::hmac::sign(&hmac_key, data);
        tag.as_ref() == expected
    };

    KatResult {
        test_id: "KAT-HMAC256-001",
        description: "HMAC-SHA-256 with 'Jefe' key (RFC 4231 Test Case 2)",
        passed,
        reference: "FIPS 198-1; RFC 4231 §4.2",
    }
}

// ---- ECDSA Known Answer Tests (FIPS 186-5) ----

/// ECDSA P-256 sign+verify roundtrip KAT (conditional self-test compatible)
pub fn kat_ecdsa_p256() -> KatResult {
    use crate::algo::{AlgorithmId, KeyPair};

    let passed = match KeyPair::generate(AlgorithmId::EcdsaP256) {
        Ok(key) => {
            let test_message = b"FIPS 140-3 KAT self-test message for ECDSA P-256";
            match key.sign(test_message) {
                Ok(signature) => key.verify(test_message, &signature).is_ok(),
                Err(_) => false,
            }
        }
        Err(_) => false,
    };

    KatResult {
        test_id: "KAT-ECDSA256-001",
        description: "ECDSA P-256 sign+verify roundtrip",
        passed,
        reference: "FIPS 186-5 §6; FIPS 140-3 §4.10.1",
    }
}

/// ECDSA P-384 sign+verify roundtrip KAT (conditional self-test compatible)
pub fn kat_ecdsa_p384() -> KatResult {
    use crate::algo::{AlgorithmId, KeyPair};

    let passed = match KeyPair::generate(AlgorithmId::EcdsaP384) {
        Ok(key) => {
            let test_message = b"FIPS 140-3 KAT self-test message for ECDSA P-384";
            match key.sign(test_message) {
                Ok(signature) => key.verify(test_message, &signature).is_ok(),
                Err(_) => false,
            }
        }
        Err(_) => false,
    };

    KatResult {
        test_id: "KAT-ECDSA384-001",
        description: "ECDSA P-384 sign+verify roundtrip",
        passed,
        reference: "FIPS 186-5 §6; FIPS 140-3 §4.10.1",
    }
}

/// Ed25519 sign+verify roundtrip KAT (RFC 8032)
///
/// Ed25519 is not FIPS-approved but is used for non-FIPS signing operations
/// (e.g., installer signatures, CSR verification). This KAT validates the
/// Ed25519 implementation integrity.
///
/// When FIPS mode is active, Ed25519 key generation is blocked. In that case,
/// the KAT is skipped (Ed25519 is not used in FIPS deployments anyway).
pub fn kat_ed25519() -> KatResult {
    use crate::algo::{AlgorithmId, KeyPair};

    // Skip if FIPS mode is active — Ed25519 is not a FIPS algorithm
    if crate::fips::is_fips_mode() {
        return KatResult {
            test_id: "KAT-ED25519-001",
            description: "Ed25519 sign+verify roundtrip (skipped — FIPS mode active)",
            passed: true,
            reference: "RFC 8032; SP 800-140D §4",
        };
    }

    let passed = match KeyPair::generate(AlgorithmId::Ed25519) {
        Ok(key) => {
            let test_message = b"FIPS 140-3 KAT self-test message for Ed25519";
            match key.sign(test_message) {
                Ok(signature) => key.verify(test_message, &signature).is_ok(),
                Err(_) => false,
            }
        }
        Err(_) => false,
    };

    KatResult {
        test_id: "KAT-ED25519-001",
        description: "Ed25519 sign+verify roundtrip",
        passed,
        reference: "RFC 8032; SP 800-140D §4",
    }
}

/// RSA PKCS#1 v1.5 sign+verify roundtrip KAT (FIPS 186-5)
///
/// Validates the RSA signature implementation. Uses RSA-3072 which is
/// FIPS-approved (RSA-2048 is rejected in FIPS mode per SP 800-131A Rev 2).
pub fn kat_rsa_sign_verify() -> KatResult {
    use crate::algo::{AlgorithmId, KeyPair};

    // Use RSA-3072 (FIPS-approved) to avoid FIPS mode rejection
    let passed = match KeyPair::generate(AlgorithmId::Rsa3072) {
        Ok(key) => {
            let test_message = b"FIPS 140-3 KAT self-test message for RSA-3072";
            match key.sign(test_message) {
                Ok(signature) => key.verify(test_message, &signature).is_ok(),
                Err(_) => false,
            }
        }
        Err(_) => false,
    };

    KatResult {
        test_id: "KAT-RSA3072-001",
        description: "RSA-3072 PKCS#1 v1.5 sign+verify roundtrip",
        passed,
        reference: "FIPS 186-5 §5; FIPS 140-3 §4.10.1",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_kat_passes() {
        let result = kat_sha256();
        assert!(
            result.passed,
            "SHA-256 KAT should pass: {}",
            result.description
        );
    }

    #[test]
    fn test_sha256_empty_kat_passes() {
        let result = kat_sha256_empty();
        assert!(result.passed, "SHA-256 empty KAT should pass");
    }

    #[test]
    fn test_sha384_kat_passes() {
        let result = kat_sha384();
        assert!(
            result.passed,
            "SHA-384 KAT should pass: {}",
            result.description
        );
    }

    #[test]
    fn test_sha512_kat_passes() {
        let result = kat_sha512();
        assert!(
            result.passed,
            "SHA-512 KAT should pass: {}",
            result.description
        );
    }

    #[test]
    fn test_hmac_sha256_kat_passes() {
        let result = kat_hmac_sha256();
        assert!(
            result.passed,
            "HMAC-SHA-256 KAT should pass: {}",
            result.description
        );
    }

    #[test]
    fn test_ecdsa_p256_kat_passes() {
        let result = kat_ecdsa_p256();
        assert!(
            result.passed,
            "ECDSA P-256 KAT should pass: {}",
            result.description
        );
    }

    #[test]
    fn test_ecdsa_p384_kat_passes() {
        let result = kat_ecdsa_p384();
        assert!(
            result.passed,
            "ECDSA P-384 KAT should pass: {}",
            result.description
        );
    }

    #[test]
    fn test_ed25519_kat_passes() {
        let result = kat_ed25519();
        assert!(
            result.passed,
            "Ed25519 KAT should pass: {}",
            result.description
        );
    }

    #[test]
    fn test_rsa_sign_verify_kat_passes() {
        let result = kat_rsa_sign_verify();
        assert!(
            result.passed,
            "RSA-3072 sign+verify KAT should pass: {}",
            result.description
        );
    }

    #[test]
    fn test_run_all_self_tests_pass() {
        let results = run_self_tests();
        assert!(
            results.all_passed,
            "All self-tests should pass. Failures: {:?}",
            results
                .failures()
                .iter()
                .map(|f| f.test_id)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_self_test_count() {
        let results = run_self_tests();
        assert_eq!(
            results.results.len(),
            9,
            "Should have 9 KATs: 4 SHA + 1 HMAC + 2 ECDSA + 1 Ed25519 + 1 RSA"
        );
    }

    #[test]
    fn test_require_self_tests_passed_ok() {
        let results = run_self_tests();
        assert!(require_self_tests_passed(&results).is_ok());
    }

    #[test]
    fn test_require_self_tests_failed_blocks() {
        let results = SelfTestResults {
            results: vec![KatResult {
                test_id: "KAT-FAKE-001",
                description: "Intentionally failed test",
                passed: false,
                reference: "test",
            }],
            timestamp: Utc::now(),
            all_passed: false,
        };
        let err = require_self_tests_passed(&results);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("FIPS 140-3 power-up self-tests FAILED"));
    }

    #[test]
    fn test_self_test_summary_format() {
        let results = run_self_tests();
        let summary = results.summary();
        assert!(summary.contains("PASS"));
        assert!(summary.contains("9/9"));
        assert!(summary.contains("FIPS 140-3"));
    }

    #[test]
    fn test_self_test_timestamp() {
        let before = Utc::now();
        let results = run_self_tests();
        let after = Utc::now();
        assert!(results.timestamp >= before);
        assert!(results.timestamp <= after);
    }

    #[test]
    fn test_failures_empty_when_all_pass() {
        let results = run_self_tests();
        assert!(results.failures().is_empty());
    }

    #[test]
    fn test_each_kat_has_reference() {
        let results = run_self_tests();
        for kat in &results.results {
            assert!(
                !kat.reference.is_empty(),
                "KAT {} should have a FIPS reference",
                kat.test_id
            );
        }
    }
}
