//! SPORK Core - Certificate Authority Operations
#![forbid(unsafe_code)]
//!
//! Pure Rust implementation of X.509 PKI operations with native
//! support for post-quantum cryptography (ML-DSA, SLH-DSA) and
//! legacy algorithms (ECDSA, RSA).
//!
//! # Features
//!
//! - **Algorithm Abstraction**: Unified interface across PQC and legacy algorithms
//! - **CA Operations**: Root/Intermediate CA initialization and certificate issuance
//! - **CSR Handling**: PKCS#10 parsing and generation
//! - **X.509 Extensions**: Full RFC 5280 extension support
//!
//! # Example (requires `ceremony` feature)
//!
//! ```rust,ignore
//! use spork_core::algo::{AlgorithmId, KeyPair};
//! use spork_core::ca::{CaCeremony, CaConfig, CertificateProfile, IssuanceRequest};
//! use spork_core::cert::{CsrBuilder, NameBuilder, SubjectAltName, Validity};
//!
//! // Initialize a Root CA with ECDSA P-256 (ceremony feature required)
//! let config = CaConfig::root("SPORK Root CA", AlgorithmId::EcdsaP256)
//!     .with_subject(
//!         NameBuilder::new("SPORK Root CA")
//!             .organization("SPORK Project")
//!             .country("US")
//!             .build()
//!     );
//!
//! let mut root = CaCeremony::init_root(config).unwrap();
//! ```
//!
//! # Supported Algorithms
//!
//! ## Post-Quantum (FIPS 204/205)
//! - ML-DSA-44 (NIST Level 1)
//! - ML-DSA-65 (NIST Level 3)
//! - ML-DSA-87 (NIST Level 5)
//! - SLH-DSA-SHA2-128s (NIST Level 1)
//! - SLH-DSA-SHA2-192s (NIST Level 3)
//! - SLH-DSA-SHA2-256s (NIST Level 5)
//!
//! ## Legacy
//! - ECDSA P-256
//! - ECDSA P-384
//! - RSA-2048
//! - RSA-4096

#![allow(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod algo;
pub mod audit;
pub mod ca;
pub mod cert;
pub mod crl;
pub mod digest;
pub mod dual_control;
pub mod entropy_health;
pub mod error;
pub mod fips;
pub mod fips_self_tests;
pub mod hsm;
pub mod key_lifecycle;
pub mod policy;
#[cfg(feature = "recovery")]
pub mod recovery;
pub mod storage;
pub mod templates;

// Re-exports for convenience
pub use algo::{AlgorithmId, KeyPair};
pub use audit::{
    AuditAction, AuditEntry, AuditError, AuditLogger, AuditResult, AuditResult_ as AuditOutcome,
    ExportFormat, VerificationResult,
};
#[cfg(feature = "ceremony")]
pub use ca::{CaCeremony, CaConfig, InitializedCa, SubordinateCsr};
pub use ca::{CaType, CertificateAuthority, CertificateProfile, Signer};
pub use cert::verify::{
    validate_chain, validate_chain_der, verify_raw_signature_with_spki, verify_signature,
    ChainValidationOptions, ChainValidationResult,
};
pub use cert::{
    CertificateBuilder, CertificateRequest, CsrBuilder, DistinguishedName, NameBuilder,
    SerialNumber, SubjectAltName, Validity,
};
pub use crl::{
    Crl, CrlBuilder, CrlShard, CrlShardManager, DeltaCrl, DeltaCrlBuilder, RevocationReason,
    RevokedCertificate,
};
pub use dual_control::{
    Approval, ApprovalError, ApprovalRequest, ApprovalStatus, ApproveResult,
    ConfigError as DualControlConfigError, ControlLevel, DualControlConfig, DualControlManager,
    InitiateResult, Operation, OperationCategory, APPROVAL_ALPHABET,
};
pub use error::{Error, Result};
pub use fips::{
    enable_fips_mode, is_fips_approved, is_fips_mode,
    validate_algorithm as validate_fips_algorithm, FIPS_APPROVED_ALGORITHMS,
};
pub use policy::{
    CaPolicy, PolicyEngine, PolicyRequest, PolicyResult, PolicyViolation, PolicyWarning,
    ViolationType,
};
#[cfg(feature = "recovery")]
pub use recovery::{
    ConfigError as RecoveryConfigError, RecoveryAction, RecoveryConfig, RecoveryLevel,
    RecoverySession, RecoverySessionManager, RecoveryShare, RecoveryShares, SessionError,
    ShareError, SHARE_ALPHABET,
};
pub use templates::{
    AllowedAlgorithm, BuiltinProfiles, SanType, Template, TemplateBuilder, TemplateConfig,
    TemplateRegistry, ValidatedRequest,
};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod integration_tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    #[cfg(feature = "ceremony")]
    fn test_full_pki_workflow() {
        // 1. Create Root CA
        let root_config = CaConfig::root("Integration Test Root CA", AlgorithmId::EcdsaP256)
            .with_subject(
                NameBuilder::new("Integration Test Root CA")
                    .organization("SPORK Test")
                    .country("US")
                    .build(),
            );

        let root_result = CaCeremony::init_root(root_config).unwrap();
        let mut root_ca = root_result.ca;

        assert!(root_result.certificate_pem.contains("BEGIN CERTIFICATE"));

        // 2. Create Intermediate CA
        let int_config =
            CaConfig::intermediate("Integration Test Intermediate", AlgorithmId::EcdsaP256)
                .with_subject(
                    NameBuilder::new("Integration Test Intermediate CA")
                        .organization("SPORK Test")
                        .country("US")
                        .build(),
                );

        let int_result = CaCeremony::init_intermediate(int_config, &mut root_ca).unwrap();
        let mut int_ca = int_result.ca;

        // 3. Issue end-entity certificate from Intermediate
        let ee_subject = NameBuilder::new("test.example.com")
            .organization("Example Inc")
            .build();

        let (ee_cert, ee_key) = int_ca
            .issue_direct(
                ee_subject,
                AlgorithmId::EcdsaP256,
                CertificateProfile::TlsServer,
                Validity::days_from_now(365),
                Some(
                    SubjectAltName::new()
                        .dns("test.example.com")
                        .dns("www.example.com")
                        .ip("127.0.0.1".parse().unwrap()),
                ),
            )
            .unwrap();

        assert!(ee_cert.pem.contains("BEGIN CERTIFICATE"));
        assert!(ee_key.contains("BEGIN PRIVATE KEY"));
        assert_eq!(ee_cert.subject_cn, "test.example.com");

        // 4. Verify serial numbers are incrementing
        let (ee_cert2, _) = int_ca
            .issue_direct(
                NameBuilder::new("test2.example.com").build(),
                AlgorithmId::EcdsaP256,
                CertificateProfile::TlsClient,
                Validity::ee_default(),
                None,
            )
            .unwrap();

        assert_ne!(ee_cert.serial_hex, ee_cert2.serial_hex);
    }

    #[test]
    #[cfg(all(feature = "ceremony", feature = "pqc"))]
    fn test_pqc_full_workflow() {
        // PQC Root CA
        let root_config = CaConfig::root("PQC Root CA", AlgorithmId::MlDsa65);
        let root_result = CaCeremony::init_root(root_config).unwrap();
        let mut root_ca = root_result.ca;

        // PQC Intermediate
        let int_config = CaConfig::intermediate("PQC Intermediate", AlgorithmId::MlDsa65);
        let int_result = CaCeremony::init_intermediate(int_config, &mut root_ca).unwrap();
        let mut int_ca = int_result.ca;

        // PQC End Entity
        let (ee_cert, _) = int_ca
            .issue_direct(
                NameBuilder::new("pqc.example.com").build(),
                AlgorithmId::MlDsa65,
                CertificateProfile::TlsServer,
                Validity::ee_default(),
                None,
            )
            .unwrap();

        assert!(ee_cert.pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    #[cfg(feature = "ceremony")]
    fn test_csr_workflow() {
        use crate::cert::CsrBuilder;

        // CA setup
        let config = CaConfig::root("CSR Test CA", AlgorithmId::EcdsaP256);
        let mut ca = CaCeremony::init_root(config).unwrap().ca;

        // Generate CSR externally
        let ee_key = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let csr = CsrBuilder::new(NameBuilder::new("csr.example.com").build())
            .build_and_sign(&ee_key)
            .unwrap();

        // Verify CSR PEM format
        let pem = csr.to_pem();
        assert!(pem.contains("BEGIN CERTIFICATE REQUEST"));

        // Parse back and issue
        let parsed = CertificateRequest::from_pem(&pem).unwrap();
        let request = ca::IssuanceRequest::new(parsed, CertificateProfile::TlsServer);
        let issued = ca.issue_certificate(request).unwrap();

        assert_eq!(issued.subject_cn, "csr.example.com");
    }

    #[test]
    #[cfg(feature = "ceremony")]
    fn test_algorithm_parity() {
        // Test that all classic algorithms work for CA creation
        let algorithms = [
            AlgorithmId::EcdsaP256,
            AlgorithmId::EcdsaP384,
            // RSA is slower, test separately
        ];

        for algo in algorithms {
            let config = CaConfig::root(format!("{} Test CA", algo), algo);
            let result = CaCeremony::init_root(config);
            assert!(result.is_ok(), "Failed for algorithm: {}", algo);
        }
    }

    #[test]
    #[cfg(all(feature = "ceremony", feature = "pqc"))]
    fn test_pqc_algorithm_parity() {
        // Test that all PQC algorithms work for CA creation
        let algorithms = [
            AlgorithmId::MlDsa44,
            AlgorithmId::MlDsa65,
            AlgorithmId::MlDsa87,
        ];

        for algo in algorithms {
            let config = CaConfig::root(format!("{} Test CA", algo), algo);
            let result = CaCeremony::init_root(config);
            assert!(result.is_ok(), "Failed for algorithm: {}", algo);
        }
    }
}
