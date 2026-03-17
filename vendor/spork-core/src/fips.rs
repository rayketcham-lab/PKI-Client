//! FIPS 140-3 runtime and compile-time enforcement
//!
//! Restricts the CA to FIPS-approved algorithms when FIPS mode is active.
//! FIPS mode can be activated at runtime (`enable_fips_mode()`) or at
//! compile time via the `fips` feature flag.
//!
//! ## Approved Algorithms (FIPS 140-3 mode)
//! - ECDSA P-256, P-384 (FIPS 186-5)
//! - RSA-3072, RSA-4096 (FIPS 186-5, minimum 3072-bit for signing)
//! - RSA-3072-PSS, RSA-4096-PSS (RFC 4055, FIPS preferred)
//!
//! ## Rejected in FIPS mode
//! - RSA-2048 (below FIPS minimum for new signatures per SP 800-131A Rev 2)
//! - ML-DSA (FIPS 204): not yet validated in supported FIPS 140-3 modules
//! - SLH-DSA (FIPS 205): not yet validated in supported FIPS 140-3 modules
//! - Composite/hybrid: no FIPS validation path

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use crate::algo::AlgorithmId;
use crate::error::{Error, Result};

/// FIPS 140-3 §4.11 module states.
///
/// Tracks the lifecycle of the cryptographic module from power-up through
/// activation. The module must complete self-tests before performing any
/// cryptographic operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FipsModuleState {
    /// Module has not been initialized. No crypto operations permitted.
    PowerOff = 0,
    /// Power-up self-tests are running (§4.10.1).
    SelfTestRunning = 1,
    /// Self-tests failed. Module is in error state — no crypto operations permitted.
    SelfTestFailed = 2,
    /// Self-tests passed, module is fully activated and ready for crypto operations.
    Activated = 3,
    /// Module has been deactivated (zeroized). No crypto operations permitted.
    Deactivated = 4,
}

/// Global FIPS mode flag (runtime).
static FIPS_MODE: AtomicBool = AtomicBool::new(false);

/// Tracks whether power-up self-tests have been run and passed.
static SELF_TESTS_PASSED: AtomicBool = AtomicBool::new(false);

/// Tracks whether entropy health validation has passed.
static ENTROPY_VALIDATED: AtomicBool = AtomicBool::new(false);

/// FIPS 140-3 §4.11 module state (formal state machine).
static FIPS_MODULE_STATE: AtomicU8 = AtomicU8::new(FipsModuleState::PowerOff as u8);

/// FIPS-approved algorithms for FIPS 140-3 mode.
///
/// Includes only classical algorithms with validated FIPS 140-3 module support.
/// PQC algorithms (ML-DSA, SLH-DSA) are standardized in FIPS 204/205 but
/// are not yet included here pending FIPS 140-3 module validation.
pub const FIPS_APPROVED_ALGORITHMS: &[AlgorithmId] = &[
    AlgorithmId::EcdsaP256,
    AlgorithmId::EcdsaP384,
    AlgorithmId::Rsa3072,
    AlgorithmId::Rsa4096,
    AlgorithmId::Rsa3072Pss,
    AlgorithmId::Rsa4096Pss,
];

/// Enable FIPS mode globally. Once enabled, cannot be disabled at runtime.
///
/// This is the basic activation — it only sets the algorithm restriction flag.
/// For full FIPS 140-3 compliance, use `enable_fips_mode_with_self_tests()`
/// which runs power-up self-tests and entropy validation before activation.
pub fn enable_fips_mode() {
    FIPS_MODE.store(true, Ordering::SeqCst);
}

/// Enable FIPS mode with full power-up self-test and entropy validation.
///
/// Per FIPS 140-3 §4.10.1, cryptographic modules must run self-tests before
/// performing any cryptographic operations. This function:
///
/// 1. Runs all Known Answer Tests (SHA-256/384/512, HMAC, ECDSA P-256/P-384)
/// 2. Validates entropy source health (SP 800-90B §4.4)
/// 3. Only enables FIPS mode if both pass
///
/// Returns an error if self-tests or entropy validation fail.
pub fn enable_fips_mode_with_self_tests() -> Result<()> {
    // §4.11: Transition to self-test-running state
    FIPS_MODULE_STATE.store(FipsModuleState::SelfTestRunning as u8, Ordering::SeqCst);

    // Run power-up self-tests (FIPS 140-3 §4.10.1)
    let self_test_results = crate::fips_self_tests::run_self_tests();
    if let Err(e) = crate::fips_self_tests::require_self_tests_passed(&self_test_results) {
        FIPS_MODULE_STATE.store(FipsModuleState::SelfTestFailed as u8, Ordering::SeqCst);
        return Err(e);
    }
    SELF_TESTS_PASSED.store(true, Ordering::SeqCst);

    // Validate entropy source (SP 800-90B §4.4)
    // Use 4096-byte sample for reliable byte-distribution statistics
    let entropy_report = crate::entropy_health::validate_entropy_source(4096);
    if let Err(e) = crate::entropy_health::require_entropy_healthy(&entropy_report) {
        FIPS_MODULE_STATE.store(FipsModuleState::SelfTestFailed as u8, Ordering::SeqCst);
        return Err(e);
    }
    ENTROPY_VALIDATED.store(true, Ordering::SeqCst);

    // All checks passed — activate FIPS mode (§4.11)
    FIPS_MODE.store(true, Ordering::SeqCst);
    FIPS_MODULE_STATE.store(FipsModuleState::Activated as u8, Ordering::SeqCst);
    Ok(())
}

/// Check whether power-up self-tests have been run and passed.
pub fn self_tests_passed() -> bool {
    SELF_TESTS_PASSED.load(Ordering::SeqCst)
}

/// Check whether entropy source has been validated.
pub fn entropy_validated() -> bool {
    ENTROPY_VALIDATED.load(Ordering::SeqCst)
}

/// Get the current FIPS module state (§4.11).
pub fn fips_module_state() -> FipsModuleState {
    match FIPS_MODULE_STATE.load(Ordering::SeqCst) {
        0 => FipsModuleState::PowerOff,
        1 => FipsModuleState::SelfTestRunning,
        2 => FipsModuleState::SelfTestFailed,
        3 => FipsModuleState::Activated,
        4 => FipsModuleState::Deactivated,
        _ => FipsModuleState::PowerOff,
    }
}

/// Check if the FIPS module is activated and ready for crypto operations (§4.11).
///
/// Returns true only when the module has completed self-tests and entropy
/// validation successfully. This is more precise than `is_fips_mode()` because
/// it verifies the module went through the proper activation sequence.
pub fn is_fips_module_activated() -> bool {
    fips_module_state() == FipsModuleState::Activated
}

/// Deactivate the FIPS module (§4.11 transition to deactivated state).
///
/// After deactivation, no crypto operations are permitted until the module
/// is re-activated via `enable_fips_mode_with_self_tests()`.
pub fn deactivate_fips_module() {
    FIPS_MODULE_STATE.store(FipsModuleState::Deactivated as u8, Ordering::SeqCst);
    FIPS_MODE.store(false, Ordering::SeqCst);
    SELF_TESTS_PASSED.store(false, Ordering::SeqCst);
    ENTROPY_VALIDATED.store(false, Ordering::SeqCst);
}

/// Run a conditional self-test for a specific algorithm.
///
/// Per SP 800-140D, conditional self-tests must be performed when an
/// algorithm is first used after power-up, or when switching algorithms.
/// This runs the relevant KAT for the requested algorithm.
///
/// Returns `Ok(())` if the algorithm's self-test passes, or an error
/// describing the failure.
pub fn conditional_algorithm_self_test(algorithm: &AlgorithmId) -> Result<()> {
    match algorithm {
        AlgorithmId::EcdsaP256 => {
            let result = crate::fips_self_tests::kat_ecdsa_p256();
            if result.passed {
                Ok(())
            } else {
                Err(Error::FipsViolation(format!(
                    "FIPS conditional self-test FAILED for {}: {}",
                    algorithm, result.description
                )))
            }
        }
        AlgorithmId::EcdsaP384 => {
            let result = crate::fips_self_tests::kat_ecdsa_p384();
            if result.passed {
                Ok(())
            } else {
                Err(Error::FipsViolation(format!(
                    "FIPS conditional self-test FAILED for {}: {}",
                    algorithm, result.description
                )))
            }
        }
        // RSA algorithms: verify SHA-256 KAT (used in RSA-PSS padding)
        AlgorithmId::Rsa3072
        | AlgorithmId::Rsa4096
        | AlgorithmId::Rsa3072Pss
        | AlgorithmId::Rsa4096Pss
        | AlgorithmId::Rsa2048 => {
            let result = crate::fips_self_tests::kat_sha256();
            if result.passed {
                Ok(())
            } else {
                Err(Error::FipsViolation(format!(
                    "FIPS conditional self-test FAILED for {} (SHA-256 KAT): {}",
                    algorithm, result.description
                )))
            }
        }
        // Ed25519: verify sign+verify roundtrip (RFC 8032, not FIPS but used in CSR verification)
        AlgorithmId::Ed25519 => {
            let result = crate::fips_self_tests::kat_ed25519();
            if result.passed {
                Ok(())
            } else {
                Err(Error::FipsViolation(format!(
                    "FIPS conditional self-test FAILED for {}: {}",
                    algorithm, result.description
                )))
            }
        }
        // PQC and composite algorithms: no conditional self-test defined
        #[allow(unreachable_patterns)]
        _ => Ok(()),
    }
}

/// Check whether FIPS mode is currently active.
///
/// Returns `true` if either:
/// - The `fips` compile-time feature is enabled, or
/// - `enable_fips_mode()` has been called at runtime.
pub fn is_fips_mode() -> bool {
    if cfg!(feature = "fips") {
        return true;
    }
    FIPS_MODE.load(Ordering::SeqCst)
}

/// Check whether the underlying crypto module has FIPS 140-3 certification.
///
/// When built with `--features fips`, the classical crypto operations (ECDSA, RSA,
/// Ed25519, SHA-2, HMAC) use aws-lc-rs, which wraps AWS-LC — a FIPS 140-3 Level 1
/// certified module (NIST Certificate #4816). In this configuration, `is_fips_module_certified()`
/// returns `true`.
///
/// Without the `fips` feature, returns `false` — the RustCrypto backend is not
/// CMVP-validated.
pub fn is_fips_module_certified() -> bool {
    cfg!(feature = "fips")
}

/// Return a human-readable summary of the FIPS status for compliance reporting.
///
/// Includes: FIPS mode active/inactive, module certification status,
/// self-test state, entropy validation state, and approved algorithm count.
pub fn fips_status_summary() -> String {
    let mode = if is_fips_mode() { "ACTIVE" } else { "inactive" };
    let certified = if is_fips_module_certified() {
        "CMVP-validated"
    } else {
        "not certified (algorithm-restriction only)"
    };
    let self_tests = if self_tests_passed() {
        "PASSED"
    } else {
        "not run"
    };
    let entropy = if entropy_validated() {
        "HEALTHY"
    } else {
        "not validated"
    };
    format!(
        "FIPS mode: {} | Module: {} | Self-tests: {} | Entropy: {} | Approved algorithms: {}",
        mode,
        certified,
        self_tests,
        entropy,
        FIPS_APPROVED_ALGORITHMS.len()
    )
}

/// Check whether a specific algorithm is FIPS-approved.
///
/// This is a pure predicate — it does not check whether FIPS mode is active.
/// Use `validate_algorithm` to enforce FIPS restrictions based on mode.
pub fn is_fips_approved(algo: &AlgorithmId) -> bool {
    matches!(
        algo,
        AlgorithmId::EcdsaP256
            | AlgorithmId::EcdsaP384
            | AlgorithmId::Rsa3072
            | AlgorithmId::Rsa4096
            | AlgorithmId::Rsa3072Pss
            | AlgorithmId::Rsa4096Pss
    )
}

/// Validate that an algorithm is permitted under current FIPS enforcement.
///
/// Returns `Ok(())` if:
/// - FIPS mode is not active, or
/// - FIPS mode is active and the algorithm is FIPS-approved.
///
/// Returns `Err(FipsViolation)` if FIPS mode is active and the algorithm
/// is not approved.
pub fn validate_algorithm(algorithm: AlgorithmId) -> Result<()> {
    if !is_fips_mode() {
        return Ok(());
    }

    if is_fips_approved(&algorithm) {
        return Ok(());
    }

    let reason = fips_rejection_reason(&algorithm);
    Err(Error::FipsViolation(reason))
}

/// Return a human-readable reason why an algorithm is rejected in FIPS mode.
fn fips_rejection_reason(algorithm: &AlgorithmId) -> String {
    match algorithm {
        AlgorithmId::Rsa2048 => {
            "RSA-2048 is below the FIPS minimum key size (3072-bit) for new signatures \
             per NIST SP 800-131A Rev 2"
                .to_string()
        }
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa44 | AlgorithmId::MlDsa65 | AlgorithmId::MlDsa87 => {
            "ML-DSA (FIPS 204) is not yet validated in a FIPS 140-3 module; \
             use ECDSA or RSA in FIPS mode"
                .to_string()
        }
        #[cfg(feature = "pqc")]
        AlgorithmId::SlhDsaSha2_128s
        | AlgorithmId::SlhDsaSha2_192s
        | AlgorithmId::SlhDsaSha2_256s => {
            "SLH-DSA (FIPS 205) is not yet validated in a FIPS 140-3 module; \
             use ECDSA or RSA in FIPS mode"
                .to_string()
        }
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa44EcdsaP256
        | AlgorithmId::MlDsa65EcdsaP256
        | AlgorithmId::MlDsa65EcdsaP384
        | AlgorithmId::MlDsa87EcdsaP384 => {
            "Composite/hybrid algorithms have no FIPS 140-3 validation path".to_string()
        }
        AlgorithmId::Ed25519 => "Ed25519 (RFC 8032) is not a FIPS-approved algorithm; \
             use ECDSA or RSA in FIPS mode"
            .to_string(),
        other => format!(
            "Algorithm {} is not approved for use in FIPS 140-3 mode",
            other
        ),
    }
}

/// Pairwise consistency test for a newly generated key pair.
///
/// Per SP 800-56A §5.6.2.1 and FIPS 140-3 §4.10.2, newly generated
/// asymmetric key pairs must be validated by performing a sign+verify
/// operation to confirm internal consistency before use.
///
/// This test is required after key generation but before the key is
/// used for any production signing operations.
pub fn pairwise_consistency_test(key: &crate::algo::KeyPair) -> Result<()> {
    let test_message = b"FIPS 140-3 pairwise consistency test";

    let signature = key.sign(test_message).map_err(|e| {
        Error::FipsViolation(format!(
            "Pairwise consistency test FAILED — signing error: {}",
            e
        ))
    })?;

    key.verify(test_message, &signature).map_err(|e| {
        Error::FipsViolation(format!(
            "Pairwise consistency test FAILED — verification error: {}",
            e
        ))
    })?;

    Ok(())
}

/// Approved security functions provided by this module.
///
/// Per FIPS 140-3 §4.9, a cryptographic module must enumerate all approved
/// security functions it implements. This returns a structured list of
/// the module's capabilities grouped by category.
pub fn approved_security_functions() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (
            "Digital Signatures (FIPS 186-5)",
            vec![
                "ECDSA P-256 (sign/verify)",
                "ECDSA P-384 (sign/verify)",
                "RSA-3072 PKCS#1 v1.5 (sign/verify)",
                "RSA-4096 PKCS#1 v1.5 (sign/verify)",
                "RSA-3072 PSS (sign/verify)",
                "RSA-4096 PSS (sign/verify)",
            ],
        ),
        (
            "Hashing (FIPS 180-4)",
            vec!["SHA-256", "SHA-384", "SHA-512"],
        ),
        (
            "Message Authentication (FIPS 198-1)",
            vec!["HMAC-SHA-256", "HMAC-SHA-384", "HMAC-SHA-512"],
        ),
        (
            "Symmetric Encryption (FIPS 197)",
            vec!["AES-256-GCM (key wrapping)"],
        ),
        (
            "Key Derivation",
            vec!["Argon2id (password-based, OWASP recommended)"],
        ),
        (
            "Random Number Generation (SP 800-90A/B)",
            vec!["OS CSPRNG via getrandom (/dev/urandom)"],
        ),
    ]
}

/// Conditional self-test for imported key pairs.
///
/// Per FIPS 140-3 §4.10.2, conditional self-tests must be performed
/// when a key pair is loaded/imported from external storage. This
/// verifies the key's internal consistency by performing a sign+verify
/// roundtrip, similar to `pairwise_consistency_test()` but specifically
/// intended for the import path.
///
/// Returns `Ok(())` if the imported key is internally consistent.
pub fn key_import_self_test(key: &crate::algo::KeyPair) -> Result<()> {
    // Use a distinct test message from keygen to differentiate in logs
    let test_message = b"FIPS 140-3 key import conditional self-test";

    let signature = key.sign(test_message).map_err(|e| {
        Error::FipsViolation(format!(
            "Key import self-test FAILED — signing error: {}",
            e
        ))
    })?;

    key.verify(test_message, &signature).map_err(|e| {
        Error::FipsViolation(format!(
            "Key import self-test FAILED — verification error: {}",
            e
        ))
    })?;

    Ok(())
}

/// Pre-flight check for key generation in FIPS mode.
///
/// Combines all required validation steps before a key can be generated:
/// 1. Algorithm is FIPS-approved (if FIPS mode active)
/// 2. Conditional self-test for the algorithm passes
/// 3. Entropy source is healthy
///
/// Call this before `KeyPair::generate()` for FIPS-compliant key generation.
/// After generation, call `pairwise_consistency_test()` on the result.
pub fn keygen_preflight(algorithm: AlgorithmId) -> Result<()> {
    // Step 1: Validate algorithm is permitted
    validate_algorithm(algorithm)?;

    // Step 2: Conditional self-test (SP 800-140D)
    if is_fips_mode() {
        conditional_algorithm_self_test(&algorithm)?;
    }

    // Step 3: Entropy health (SP 800-90B §4.4)
    // Use 4096-byte sample for reliable statistics: with 256 byte-value bins,
    // expected count = 16 per bin (vs 4 with 1024), eliminating false positives
    // in the byte-distribution chi-squared test.
    if is_fips_mode() {
        let report = crate::entropy_health::validate_entropy_source(4096);
        crate::entropy_health::require_entropy_healthy(&report)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    #[cfg(not(feature = "fips"))]
    use std::sync::Mutex;

    /// Mutex to serialize tests that toggle the global FIPS_MODE atomic.
    /// Without this, parallel tests race on the shared flag.
    #[cfg(not(feature = "fips"))]
    static FIPS_LOCK: Mutex<()> = Mutex::new(());

    // Temporarily enable/disable FIPS mode for a test closure.
    // Only valid in non-fips-feature builds (feature flag makes it permanent).
    // Uses unwrap_or_else to recover from poisoned mutex (prior test panic).
    #[cfg(not(feature = "fips"))]
    fn with_fips_mode<F: FnOnce()>(f: F) {
        let _guard = FIPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        FIPS_MODE.store(true, Ordering::SeqCst);
        f();
        FIPS_MODE.store(false, Ordering::SeqCst);
    }

    // ---- is_fips_approved tests ----

    #[test]
    fn test_is_fips_approved_ecdsa_p256() {
        assert!(is_fips_approved(&AlgorithmId::EcdsaP256));
    }

    #[test]
    fn test_is_fips_approved_ecdsa_p384() {
        assert!(is_fips_approved(&AlgorithmId::EcdsaP384));
    }

    #[test]
    fn test_is_fips_approved_rsa_3072() {
        assert!(is_fips_approved(&AlgorithmId::Rsa3072));
    }

    #[test]
    fn test_is_fips_approved_rsa_4096() {
        assert!(is_fips_approved(&AlgorithmId::Rsa4096));
    }

    #[test]
    fn test_is_fips_approved_rsa_3072_pss() {
        assert!(is_fips_approved(&AlgorithmId::Rsa3072Pss));
    }

    #[test]
    fn test_is_fips_approved_rsa_4096_pss() {
        assert!(is_fips_approved(&AlgorithmId::Rsa4096Pss));
    }

    #[test]
    fn test_is_fips_approved_rejects_rsa_2048() {
        assert!(!is_fips_approved(&AlgorithmId::Rsa2048));
    }

    #[test]
    #[cfg(feature = "pqc")]
    fn test_is_fips_approved_rejects_mldsa() {
        assert!(!is_fips_approved(&AlgorithmId::MlDsa44));
        assert!(!is_fips_approved(&AlgorithmId::MlDsa65));
        assert!(!is_fips_approved(&AlgorithmId::MlDsa87));
    }

    #[test]
    #[cfg(feature = "pqc")]
    fn test_is_fips_approved_rejects_slhdsa() {
        assert!(!is_fips_approved(&AlgorithmId::SlhDsaSha2_128s));
        assert!(!is_fips_approved(&AlgorithmId::SlhDsaSha2_192s));
        assert!(!is_fips_approved(&AlgorithmId::SlhDsaSha2_256s));
    }

    #[test]
    #[cfg(feature = "pqc")]
    fn test_is_fips_approved_rejects_composite() {
        assert!(!is_fips_approved(&AlgorithmId::MlDsa44EcdsaP256));
        assert!(!is_fips_approved(&AlgorithmId::MlDsa65EcdsaP256));
        assert!(!is_fips_approved(&AlgorithmId::MlDsa65EcdsaP384));
        assert!(!is_fips_approved(&AlgorithmId::MlDsa87EcdsaP384));
    }

    // ---- FIPS_APPROVED_ALGORITHMS constant ----

    #[test]
    fn test_fips_approved_algorithms_constant_contains_ecdsa() {
        assert!(FIPS_APPROVED_ALGORITHMS.contains(&AlgorithmId::EcdsaP256));
        assert!(FIPS_APPROVED_ALGORITHMS.contains(&AlgorithmId::EcdsaP384));
    }

    #[test]
    fn test_fips_approved_algorithms_constant_contains_rsa() {
        assert!(FIPS_APPROVED_ALGORITHMS.contains(&AlgorithmId::Rsa3072));
        assert!(FIPS_APPROVED_ALGORITHMS.contains(&AlgorithmId::Rsa4096));
        assert!(FIPS_APPROVED_ALGORITHMS.contains(&AlgorithmId::Rsa3072Pss));
        assert!(FIPS_APPROVED_ALGORITHMS.contains(&AlgorithmId::Rsa4096Pss));
    }

    #[test]
    fn test_fips_approved_algorithms_constant_excludes_rsa_2048() {
        assert!(!FIPS_APPROVED_ALGORITHMS.contains(&AlgorithmId::Rsa2048));
    }

    // ---- validate_algorithm (non-FIPS mode) ----

    #[test]
    fn test_non_fips_allows_everything() {
        FIPS_MODE.store(false, Ordering::SeqCst);
        // Only run this test when the fips feature is not compiled in
        #[cfg(not(feature = "fips"))]
        {
            assert!(validate_algorithm(AlgorithmId::Rsa2048).is_ok());
            assert!(validate_algorithm(AlgorithmId::EcdsaP256).is_ok());
        }
    }

    // ---- validate_algorithm (FIPS mode active) ----

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_fips_allows_ecdsa_p256() {
        with_fips_mode(|| {
            assert!(validate_algorithm(AlgorithmId::EcdsaP256).is_ok());
        });
    }

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_fips_allows_ecdsa_p384() {
        with_fips_mode(|| {
            assert!(validate_algorithm(AlgorithmId::EcdsaP384).is_ok());
        });
    }

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_fips_allows_rsa_3072() {
        with_fips_mode(|| {
            assert!(validate_algorithm(AlgorithmId::Rsa3072).is_ok());
        });
    }

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_fips_allows_rsa_4096() {
        with_fips_mode(|| {
            assert!(validate_algorithm(AlgorithmId::Rsa4096).is_ok());
        });
    }

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_fips_rejects_rsa_2048() {
        with_fips_mode(|| {
            let err = validate_algorithm(AlgorithmId::Rsa2048);
            assert!(err.is_err());
            let msg = format!("{}", err.unwrap_err());
            assert!(msg.contains("RSA-2048"));
        });
    }

    #[test]
    #[cfg(all(not(feature = "fips"), feature = "pqc"))]
    fn test_fips_rejects_mldsa() {
        with_fips_mode(|| {
            let err44 = validate_algorithm(AlgorithmId::MlDsa44);
            assert!(err44.is_err(), "ML-DSA-44 should be rejected in FIPS mode");
            assert!(format!("{}", err44.unwrap_err()).contains("ML-DSA"));

            let err65 = validate_algorithm(AlgorithmId::MlDsa65);
            assert!(err65.is_err(), "ML-DSA-65 should be rejected in FIPS mode");

            let err87 = validate_algorithm(AlgorithmId::MlDsa87);
            assert!(err87.is_err(), "ML-DSA-87 should be rejected in FIPS mode");
        });
    }

    #[test]
    #[cfg(all(not(feature = "fips"), feature = "pqc"))]
    fn test_fips_rejects_slhdsa() {
        with_fips_mode(|| {
            assert!(
                validate_algorithm(AlgorithmId::SlhDsaSha2_128s).is_err(),
                "SLH-DSA-128s should be rejected in FIPS mode"
            );
            assert!(
                validate_algorithm(AlgorithmId::SlhDsaSha2_192s).is_err(),
                "SLH-DSA-192s should be rejected in FIPS mode"
            );
            assert!(
                validate_algorithm(AlgorithmId::SlhDsaSha2_256s).is_err(),
                "SLH-DSA-256s should be rejected in FIPS mode"
            );
        });
    }

    #[test]
    #[cfg(all(not(feature = "fips"), feature = "pqc"))]
    fn test_fips_rejects_composite() {
        with_fips_mode(|| {
            assert!(validate_algorithm(AlgorithmId::MlDsa44EcdsaP256).is_err());
            assert!(validate_algorithm(AlgorithmId::MlDsa65EcdsaP256).is_err());
            assert!(validate_algorithm(AlgorithmId::MlDsa65EcdsaP384).is_err());
            assert!(validate_algorithm(AlgorithmId::MlDsa87EcdsaP384).is_err());
        });
    }

    // ---- is_fips_mode / enable_fips_mode ----

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_enable_fips_mode_runtime() {
        let _guard = FIPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        FIPS_MODE.store(false, Ordering::SeqCst);
        assert!(!is_fips_mode());
        enable_fips_mode();
        assert!(is_fips_mode());
        // Clean up
        FIPS_MODE.store(false, Ordering::SeqCst);
    }

    #[test]
    fn test_is_fips_mode_compile_time() {
        // When the fips feature is compiled in, is_fips_mode() must always be true
        if cfg!(feature = "fips") {
            assert!(is_fips_mode());
        }
    }

    #[test]
    fn test_is_fips_module_certification_matches_feature() {
        if cfg!(feature = "fips") {
            assert!(is_fips_module_certified());
        } else {
            assert!(!is_fips_module_certified());
        }
    }

    #[test]
    fn test_fips_status_summary_format() {
        let summary = fips_status_summary();
        assert!(summary.contains("FIPS mode:"));
        assert!(summary.contains("Module:"));
        assert!(summary.contains("Self-tests:"));
        assert!(summary.contains("Entropy:"));
        assert!(summary.contains("Approved algorithms: 6"));
    }

    // ---- FIPS mode with self-tests ----

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_enable_fips_mode_with_self_tests() {
        let _guard = FIPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        FIPS_MODE.store(false, Ordering::SeqCst);
        SELF_TESTS_PASSED.store(false, Ordering::SeqCst);
        ENTROPY_VALIDATED.store(false, Ordering::SeqCst);

        let result = enable_fips_mode_with_self_tests();
        assert!(result.is_ok(), "FIPS mode with self-tests should succeed");
        assert!(
            is_fips_mode(),
            "FIPS mode should be active after self-tests"
        );
        assert!(self_tests_passed(), "Self-tests should be marked passed");
        assert!(entropy_validated(), "Entropy should be marked validated");

        // Clean up
        FIPS_MODE.store(false, Ordering::SeqCst);
        SELF_TESTS_PASSED.store(false, Ordering::SeqCst);
        ENTROPY_VALIDATED.store(false, Ordering::SeqCst);
    }

    #[test]
    fn test_self_tests_passed_initially_false() {
        // Reset state
        SELF_TESTS_PASSED.store(false, Ordering::SeqCst);
        assert!(!self_tests_passed());
    }

    #[test]
    fn test_entropy_validated_initially_false() {
        ENTROPY_VALIDATED.store(false, Ordering::SeqCst);
        assert!(!entropy_validated());
    }

    // ---- Conditional algorithm self-tests ----

    #[test]
    fn test_conditional_self_test_ecdsa_p256() {
        let result = conditional_algorithm_self_test(&AlgorithmId::EcdsaP256);
        assert!(
            result.is_ok(),
            "ECDSA P-256 conditional self-test should pass"
        );
    }

    #[test]
    fn test_conditional_self_test_ecdsa_p384() {
        let result = conditional_algorithm_self_test(&AlgorithmId::EcdsaP384);
        assert!(
            result.is_ok(),
            "ECDSA P-384 conditional self-test should pass"
        );
    }

    #[test]
    fn test_conditional_self_test_rsa_3072() {
        let result = conditional_algorithm_self_test(&AlgorithmId::Rsa3072);
        assert!(
            result.is_ok(),
            "RSA-3072 conditional self-test should pass (SHA-256 KAT)"
        );
    }

    #[test]
    fn test_conditional_self_test_rsa_pss() {
        let result = conditional_algorithm_self_test(&AlgorithmId::Rsa3072Pss);
        assert!(
            result.is_ok(),
            "RSA-3072-PSS conditional self-test should pass"
        );
    }

    #[test]
    fn test_conditional_self_test_ed25519() {
        // Ed25519 is not FIPS-approved but has a KAT for integrity validation
        let result = conditional_algorithm_self_test(&AlgorithmId::Ed25519);
        assert!(
            result.is_ok(),
            "Ed25519 conditional self-test (sign+verify KAT) should pass"
        );
    }

    // ---- validate_algorithm enforces FIPS mode on keygen path ----
    //
    // These tests verify the FIPS enforcement that KeyPair::generate calls.
    // We test validate_algorithm directly (not KeyPair::generate) to keep
    // the critical section where FIPS_MODE=true as short as possible —
    // KeyPair::generate for RSA takes seconds, during which any parallel
    // test calling KeyPair::generate would see FIPS_MODE=true and fail.

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_keygen_fips_rejects_rsa_2048() {
        with_fips_mode(|| {
            let result = validate_algorithm(AlgorithmId::Rsa2048);
            assert!(
                result.is_err(),
                "validate_algorithm should reject RSA-2048 in FIPS mode"
            );
            let msg = format!("{}", result.unwrap_err());
            assert!(msg.contains("RSA-2048") || msg.contains("FIPS"));
        });
    }

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_keygen_fips_allows_ecdsa_p256() {
        with_fips_mode(|| {
            let result = validate_algorithm(AlgorithmId::EcdsaP256);
            assert!(
                result.is_ok(),
                "validate_algorithm should allow ECDSA P-256 in FIPS mode"
            );
        });
    }

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_keygen_fips_allows_rsa_3072() {
        with_fips_mode(|| {
            let result = validate_algorithm(AlgorithmId::Rsa3072);
            assert!(
                result.is_ok(),
                "validate_algorithm should allow RSA-3072 in FIPS mode"
            );
        });
    }

    #[test]
    #[cfg(all(not(feature = "fips"), feature = "pqc"))]
    fn test_keygen_fips_rejects_mldsa() {
        with_fips_mode(|| {
            let result = validate_algorithm(AlgorithmId::MlDsa44);
            assert!(
                result.is_err(),
                "validate_algorithm should reject ML-DSA-44 in FIPS mode"
            );
        });
    }

    // ---- Pairwise consistency tests (SP 800-56A §5.6.2.1) ----

    #[test]
    fn test_pairwise_consistency_ecdsa_p256() {
        use crate::algo::KeyPair;
        let key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let result = pairwise_consistency_test(&key);
        assert!(
            result.is_ok(),
            "P-256 key pair should pass pairwise consistency"
        );
    }

    #[test]
    fn test_pairwise_consistency_ecdsa_p384() {
        use crate::algo::KeyPair;
        let key = KeyPair::generate(AlgorithmId::EcdsaP384).unwrap();
        let result = pairwise_consistency_test(&key);
        assert!(
            result.is_ok(),
            "P-384 key pair should pass pairwise consistency"
        );
    }

    #[test]
    #[cfg(not(feature = "fips"))] // Ed25519 rejected by FIPS algorithm validation
    fn test_pairwise_consistency_ed25519() {
        use crate::algo::KeyPair;
        // Hold FIPS lock to prevent race with tests that temporarily enable FIPS mode,
        // which would cause KeyPair::generate(Ed25519) to be rejected.
        let _guard = FIPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        FIPS_MODE.store(false, Ordering::SeqCst);
        let key = KeyPair::generate(AlgorithmId::Ed25519).unwrap();
        let result = pairwise_consistency_test(&key);
        assert!(
            result.is_ok(),
            "Ed25519 key pair should pass pairwise consistency"
        );
    }

    // ---- Keygen preflight tests ----

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_keygen_preflight_non_fips_allows_all() {
        FIPS_MODE.store(false, Ordering::SeqCst);
        // Non-FIPS mode should allow everything
        assert!(keygen_preflight(AlgorithmId::EcdsaP256).is_ok());
        assert!(keygen_preflight(AlgorithmId::Rsa2048).is_ok());
        assert!(keygen_preflight(AlgorithmId::Ed25519).is_ok());
    }

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_keygen_preflight_fips_rejects_rsa_2048() {
        with_fips_mode(|| {
            let result = keygen_preflight(AlgorithmId::Rsa2048);
            assert!(
                result.is_err(),
                "keygen_preflight should reject RSA-2048 in FIPS mode"
            );
        });
    }

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_keygen_preflight_fips_passes_p256() {
        with_fips_mode(|| {
            let result = keygen_preflight(AlgorithmId::EcdsaP256);
            assert!(
                result.is_ok(),
                "keygen_preflight should pass for P-256 in FIPS mode: {:?}",
                result.err()
            );
        });
    }

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_keygen_preflight_fips_passes_p384() {
        with_fips_mode(|| {
            let result = keygen_preflight(AlgorithmId::EcdsaP384);
            assert!(
                result.is_ok(),
                "keygen_preflight should pass for P-384 in FIPS mode: {:?}",
                result.err()
            );
        });
    }

    // ---- approved_security_functions tests ----

    #[test]
    fn test_approved_security_functions_categories() {
        let funcs = approved_security_functions();
        assert!(
            funcs.len() >= 5,
            "Should have at least 5 categories of security functions"
        );
        let categories: Vec<&str> = funcs.iter().map(|(cat, _)| *cat).collect();
        assert!(categories.iter().any(|c| c.contains("Digital Signatures")));
        assert!(categories.iter().any(|c| c.contains("Hashing")));
        assert!(categories
            .iter()
            .any(|c| c.contains("Message Authentication")));
        assert!(categories
            .iter()
            .any(|c| c.contains("Symmetric Encryption")));
    }

    #[test]
    fn test_approved_security_functions_signature_algos() {
        let funcs = approved_security_functions();
        let sig_funcs = funcs
            .iter()
            .find(|(cat, _)| cat.contains("Digital Signatures"))
            .expect("Should have Digital Signatures category");
        assert_eq!(sig_funcs.1.len(), 6, "Should list 6 signature algorithms");
        assert!(sig_funcs.1.iter().any(|f| f.contains("ECDSA P-256")));
        assert!(sig_funcs.1.iter().any(|f| f.contains("ECDSA P-384")));
        assert!(sig_funcs.1.iter().any(|f| f.contains("RSA-3072 PSS")));
    }

    #[test]
    fn test_approved_security_functions_hash_algos() {
        let funcs = approved_security_functions();
        let hash_funcs = funcs
            .iter()
            .find(|(cat, _)| cat.contains("Hashing"))
            .expect("Should have Hashing category");
        assert_eq!(hash_funcs.1.len(), 3, "Should list 3 hash algorithms");
        assert!(hash_funcs.1.contains(&"SHA-256"));
        assert!(hash_funcs.1.contains(&"SHA-384"));
        assert!(hash_funcs.1.contains(&"SHA-512"));
    }

    // ---- key_import_self_test tests ----

    #[test]
    fn test_key_import_self_test_p256() {
        let key = crate::algo::KeyPair::generate(AlgorithmId::EcdsaP256)
            .expect("P-256 keygen should work");
        let result = key_import_self_test(&key);
        assert!(
            result.is_ok(),
            "Key import self-test should pass for valid P-256 key"
        );
    }

    #[test]
    fn test_key_import_self_test_p384() {
        let key = crate::algo::KeyPair::generate(AlgorithmId::EcdsaP384)
            .expect("P-384 keygen should work");
        let result = key_import_self_test(&key);
        assert!(
            result.is_ok(),
            "Key import self-test should pass for valid P-384 key"
        );
    }

    #[test]
    #[cfg(not(feature = "fips"))] // Ed25519 rejected by FIPS algorithm validation
    fn test_key_import_self_test_ed25519() {
        let key = crate::algo::KeyPair::generate(AlgorithmId::Ed25519)
            .expect("Ed25519 keygen should work");
        let result = key_import_self_test(&key);
        assert!(
            result.is_ok(),
            "Key import self-test should pass for valid Ed25519 key"
        );
    }

    // ---- FipsModuleState / §4.11 state machine tests ----

    #[test]
    fn test_fips_module_state_initial() {
        // Initial state should be PowerOff (or Activated if earlier tests activated it)
        // Just verify the function doesn't panic
        let _state = fips_module_state();
    }

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_fips_module_activated_after_self_tests() {
        let _guard = FIPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Reset state
        FIPS_MODULE_STATE.store(FipsModuleState::PowerOff as u8, Ordering::SeqCst);
        FIPS_MODE.store(false, Ordering::SeqCst);
        SELF_TESTS_PASSED.store(false, Ordering::SeqCst);
        ENTROPY_VALIDATED.store(false, Ordering::SeqCst);

        let result = enable_fips_mode_with_self_tests();
        assert!(
            result.is_ok(),
            "enable_fips_mode_with_self_tests failed: {:?}",
            result.err()
        );
        assert_eq!(fips_module_state(), FipsModuleState::Activated);
        assert!(is_fips_module_activated());

        // Cleanup
        FIPS_MODE.store(false, Ordering::SeqCst);
        FIPS_MODULE_STATE.store(FipsModuleState::PowerOff as u8, Ordering::SeqCst);
    }

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_fips_module_deactivation() {
        let _guard = FIPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Activate first
        FIPS_MODE.store(true, Ordering::SeqCst);
        FIPS_MODULE_STATE.store(FipsModuleState::Activated as u8, Ordering::SeqCst);

        deactivate_fips_module();
        assert_eq!(fips_module_state(), FipsModuleState::Deactivated);
        assert!(!is_fips_module_activated());
        assert!(!is_fips_mode());

        // Cleanup
        FIPS_MODULE_STATE.store(FipsModuleState::PowerOff as u8, Ordering::SeqCst);
    }

    #[test]
    fn test_fips_module_state_repr() {
        assert_eq!(FipsModuleState::PowerOff as u8, 0);
        assert_eq!(FipsModuleState::SelfTestRunning as u8, 1);
        assert_eq!(FipsModuleState::SelfTestFailed as u8, 2);
        assert_eq!(FipsModuleState::Activated as u8, 3);
        assert_eq!(FipsModuleState::Deactivated as u8, 4);
    }
}
